// Kubernix client plugin.
//
// Registers two store schemes that connect to the Kubernix frontend and speak the
// Lix daemon protocol as Cap'n Proto RPC:
//
//   kubernix://[user@]host        over SSH (kubernix-sshd)
//   kubernix-tls://host[:port]    over mutual TLS (kubernix-mtlsd), the client
//                                 authenticating with a certificate chain
//
// This exists because `ssh-ng://` does *not* speak Cap'n Proto: SSHStore::init
// calls RemoteStore::initConnection, which performs the legacy worker-protocol
// handshake. The RPC implementation (RpcRemoteStore) is welded to unix sockets
// and its connection setup is private, so it cannot be reused for another
// transport. See NOTES.md item 5 and DESIGN.md.
//
// SPIKE STATUS: the bootstrap path is implemented and the store operations are
// not. Connecting proves the handshake; any actual store operation will fail.

#include "config.h"

#include <lix/libstore/derivations.hh>
#include <lix/libstore/nar-accessor.hh>
#include <lix/libstore/daemon-rpc.hh>

#include <lix/libstore/daemon.hh>
#include <lix/libstore/remote-store.hh>
#include <lix/libstore/remote-store-connection.hh>
#include <lix/libstore/ssh.hh>
#include <lix/libstore/ssh-store.hh>
#include <lix/libstore/store-api.hh>
#include <lix/libutil/async.hh>
#include <lix/libutil/file-descriptor.hh>
#include <lix/libutil/file-system.hh>
#include <lix/libutil/logging.hh>
#include <lix/libutil/logging-rpc.hh>
#include <lix/libutil/result.hh>
#include <lix/libutil/strings.hh>

#include <capnp/rpc-twoparty.h>
#include <kj/compat/tls.h>

namespace nix {

struct KubernixStoreConfig : virtual RemoteStoreConfig, virtual CommonSSHStoreConfig
{
    using RemoteStoreConfig::RemoteStoreConfig;
    using CommonSSHStoreConfig::CommonSSHStoreConfig;

    const Setting<Path> remoteProgram{
        this, "nix-daemon", "remote-program",
        "Path to the program to run on the remote machine. The Kubernix frontend "
        "serves the protocol itself and ignores the name, but it is configurable "
        "so the connection can be pointed at a test harness."
    };

    /* Only meaningful for `kubernix-tls://`. */
    const Setting<Path> tlsCert{
        this, "", "tls-cert",
        "PEM file holding the client certificate chain, leaf first. The frontend "
        "attributes the connection to a tenant from the LAST certificate sent, so the "
        "chain must end with the CA registered for the tenant (or a certificate that CA "
        "issued directly)."
    };

    const Setting<Path> tlsKey{
        this, "", "tls-key", "PEM file holding the private key for `tls-cert`."
    };

    const Setting<Path> tlsCa{
        this, "", "tls-ca",
        "PEM bundle of CAs trusted to have issued the frontend's server certificate. "
        "Empty means the system trust store."
    };

    const Setting<std::string> tlsServerName{
        this, "", "tls-server-name",
        "Name to verify the server certificate against. Defaults to the host in the URI."
    };

    const std::string name() override { return "Kubernix Store"; }

    std::string doc() override
    {
        return "Kubernix distributed remote builder. Connects over SSH "
               "(kubernix://) or mutual TLS (kubernix-tls://) and speaks the daemon "
               "protocol as Cap'n Proto RPC.";
    }
};

class KubernixStore final : public RemoteStore
{
    friend MustCallInit;

    KubernixStoreConfig config_;

public:
    KubernixStore(
        MustCallInit & w,
        kj::Badge<KubernixStore>,
        const std::string & scheme,
        const std::string & host,
        KubernixStoreConfig config
    )
        : Store(config)
        , RemoteStore(w, config)
        , config_(std::move(config))
        , scheme_(scheme)
        , host(host)
    {
        if (useTls()) {
            if (host.find('@') != std::string::npos) {
                throw Error("kubernix-tls:// takes no user: the tenant comes from the client certificate");
            }
            if (config_.tlsCert.get().empty() || config_.tlsKey.get().empty()) {
                throw UsageError("kubernix-tls:// requires the tls-cert and tls-key settings");
            }
        } else {
            ssh.emplace(host, config_.port, config_.sshKey, config_.sshPublicHostKey, config_.compress);
        }
    }

    static kj::Promise<Result<std::optional<ref<Store>>>>
    open(const std::string & scheme, const Path & host, KubernixStoreConfig config)
    try {
        MustCallInit init;
        auto store =
            make_ref<KubernixStore>(init, kj::Badge<KubernixStore>{}, scheme, host, std::move(config));
        TRY_AWAIT(init(store));
        co_return store;
    } catch (...) {
        co_return result::current_exception();
    }

    KubernixStoreConfig & config() override { return config_; }
    const KubernixStoreConfig & config() const override { return config_; }

    static inline const std::string sshScheme = "kubernix";
    static inline const std::string tlsScheme = "kubernix-tls";

    bool useTls() const { return scheme_ == tlsScheme; }

    std::string getUri() override { return scheme_ + "://" + host; }

    kj::Promise<Result<std::optional<std::string>>> getBuildLogExact(const StorePath & path) override
    try {
        // Logs live in the frontend's object store and are served over its HTTP
        // endpoint, not over this connection.
        unsupported("getBuildLogExact");
    } catch (...) {
        return {result::current_exception()};
    }

    /* Store operations, delegated to the RPC capability.

       These must be overridden: RemoteStore's inherited implementations drive the
       *legacy* wire protocol over the connection fd, and ours is -1, so falling
       through to them fails with "makeNonBlocking: Bad file descriptor".
       RpcRemoteStore overrides the same set (uds-remote-store.cc:316-560); we
       mirror it because that class cannot be reused (NOTES.md item 5). */

    kj::Promise<Result<bool>>
    isValidPathUncached(const StorePath & path, const Activity * context) override
    try {
        auto req = rpc->legacyProtocol.isValidPathRequest();
        RPC_FILL(req, initPath, path, *this);
        co_return TRY_AWAIT_RPC(req.send()).getResult();
    } catch (...) {
        co_return result::current_exception();
    }

    kj::Promise<Result<StorePathSet>>
    queryValidPaths(const StorePathSet & paths, SubstituteFlag maybeSubstitute) override
    try {
        auto req = rpc->legacyProtocol.queryValidPathsRequest();
        RPC_FILL(req, initPaths, paths, *this);
        req.setSubstitute(maybeSubstitute);

        auto res = TRY_AWAIT_RPC(req.send());
        co_return rpc::to<StorePathSet>(res.getResult(), *this);
    } catch (...) {
        co_return result::current_exception();
    }

    kj::Promise<Result<StorePathSet>> queryAllValidPaths() override
    try {
        auto req = rpc->legacyProtocol.queryAllValidPathsRequest();
        auto res = TRY_AWAIT_RPC(req.send());
        co_return rpc::to<StorePathSet>(res.getResult(), *this);
    } catch (...) {
        co_return result::current_exception();
    }

    kj::Promise<Result<std::shared_ptr<const ValidPathInfo>>>
    queryPathInfoUncached(const StorePath & path, const Activity * context) override
    try {
        auto req = rpc->legacyProtocol.queryPathInfoRequest();
        RPC_FILL(req, initPath, path, *this);

        auto resp = TRY_AWAIT_RPC(req.send());
        if (auto res = from(resp.getResult(), *this)) {
            co_return std::make_shared<ValidPathInfo>(std::move(*res));
        }
        co_return result::success(nullptr);
    } catch (...) {
        co_return result::current_exception();
    }

    /* Upload a path: the client already has the ValidPathInfo, so this maps onto
       addToStoreNar and streams the NAR through the returned Stream capability. */
    kj::Promise<Result<void>> addToStore(
        const ValidPathInfo & info,
        AsyncInputStream & nar,
        RepairFlag repair,
        CheckSigsFlag checkSigs,
        const Activity * context
    ) override
    try {
        auto req = rpc->legacyProtocol.addToStoreNarRequest();
        RPC_FILL(req, initInfo, info, *this);
        RPC_FILL(req, setRepair, repair);
        RPC_FILL(req, setDontCheckSigs, !checkSigs);

        auto stream = TRY_AWAIT_RPC(req.send()).getResult();

        auto copier = copyNAR(nar);
        constexpr size_t BUF_SIZE = 65536;
        auto buf = std::make_unique<char[]>(BUF_SIZE);
        while (auto r = TRY_AWAIT(copier->read(buf.get(), BUF_SIZE))) {
            auto feedReq = stream.feedRequest();
            RPC_FILL(feedReq, setRaw, std::string_view(buf.get(), *r));
            TRY_AWAIT_RPC(feedReq.send());
        }

        TRY_AWAIT_RPC(stream.finalizeRequest().send());
        co_return result::success();
    } catch (...) {
        co_return result::current_exception();
    }

    kj::Promise<Result<StorePathSet>> querySubstitutablePaths(const StorePathSet & paths) override
    try {
        auto req = rpc->legacyProtocol.querySubstitutablePathsRequest();
        RPC_FILL(req, initPaths, paths, *this);
        auto res = TRY_AWAIT_RPC(req.send());
        co_return rpc::to<StorePathSet>(res.getResult(), *this);
    } catch (...) {
        co_return result::current_exception();
    }

    kj::Promise<Result<void>>
    queryReferrers(const StorePath & path, StorePathSet & referrers) override
    try {
        auto req = rpc->legacyProtocol.queryReferrersRequest();
        RPC_FILL(req, initPath, path, *this);
        auto res = TRY_AWAIT_RPC(req.send());
        referrers.merge(rpc::to<StorePathSet>(res.getResult(), *this));
        co_return result::success();
    } catch (...) {
        co_return result::current_exception();
    }

    kj::Promise<Result<StorePathSet>> queryValidDerivers(const StorePath & path) override
    try {
        auto req = rpc->legacyProtocol.queryValidDeriversRequest();
        RPC_FILL(req, initPath, path, *this);
        auto res = TRY_AWAIT_RPC(req.send());
        co_return rpc::to<StorePathSet>(res.getResult(), *this);
    } catch (...) {
        co_return result::current_exception();
    }

    kj::Promise<Result<std::map<std::string, StorePath>>>
    queryDerivationOutputMap(const StorePath & path) override
    try {
        auto req = rpc->legacyProtocol.queryDerivationOutputMapRequest();
        RPC_FILL(req, initPath, path, *this);
        auto res = TRY_AWAIT_RPC(req.send());
        co_return rpc::to<std::map<std::string, StorePath>>(res.getResult(), *this);
    } catch (...) {
        co_return result::current_exception();
    }

    kj::Promise<Result<std::optional<StorePath>>>
    queryPathFromHashPart(const std::string & hashPart) override
    try {
        auto req = rpc->legacyProtocol.queryPathFromHashPartRequest();
        RPC_FILL(req, setHashPart, hashPart);
        auto res = TRY_AWAIT_RPC(req.send());
        co_return rpc::from(res.getResult(), *this);
    } catch (...) {
        co_return result::current_exception();
    }

    kj::Promise<Result<void>> queryMissing(
        const std::vector<DerivedPath> & targets,
        StorePathSet & willBuild,
        StorePathSet & willSubstitute,
        StorePathSet & unknown,
        uint64_t & downloadSize,
        uint64_t & narSize
    ) override
    try {
        auto req = rpc->legacyProtocol.queryMissingRequest();
        RPC_FILL(req, initTargets, targets, static_cast<Store &>(*this));

        auto res = TRY_AWAIT_RPC(req.send());
        willBuild = rpc::to<StorePathSet>(res.getResult().getWillBuild(), static_cast<Store &>(*this));
        willSubstitute =
            rpc::to<StorePathSet>(res.getResult().getWillSubstitute(), static_cast<Store &>(*this));
        unknown = rpc::to<StorePathSet>(res.getResult().getUnknown(), static_cast<Store &>(*this));
        downloadSize = res.getResult().getDownloadSize();
        narSize = res.getResult().getNarSize();
        co_return result::success();
    } catch (...) {
        co_return result::current_exception();
    }

    /* Substituter info is not something the frontend can answer: it does not
       consult substituters on the client's behalf. Upstream refuses this too. */
    kj::Promise<Result<void>> querySubstitutablePathInfos(
        const StorePathCAMap & paths, SubstitutablePathInfos & infos
    ) override
    try {
        throw UnimplementedError("querySubstitutablePathInfos is not supported on kubernix stores");
    } catch (...) {
        co_return result::current_exception();
    }

    /* GC roots. `nix copy` takes a temp root on the source store, so this must be
       delegated even though the frontend treats it as a no-op. */
    kj::Promise<Result<void>> addTempRoot(const StorePath & path) override
    try {
        auto req = rpc->legacyProtocol.addTempRootRequest();
        RPC_FILL(req, initPath, path, *this);
        TRY_AWAIT_RPC(req.send());
        co_return result::success();
    } catch (...) {
        co_return result::current_exception();
    }

    /* No addIndirectRoot: that is IndirectRootStore's, and RemoteStore does not
       inherit it. UDSRemoteStore can override it only because it is a local-fs
       store as well. */

    kj::Promise<Result<Roots>> findRoots(bool censor) override
    try {
        auto res = TRY_AWAIT_RPC(rpc->legacyProtocol.findRootsRequest().send());
        co_return rpc::to<Roots>(res.getResult(), *this);
    } catch (...) {
        co_return result::current_exception();
    }

    kj::Promise<Result<void>> collectGarbageImpl(
        ConnectionHandle & conn, const GCOptions & options, GCResults & results
    ) override
    try {
        auto req = rpc->legacyProtocol.collectGarbageRequest();
        req.setAction(rpc::from(options.action));
        RPC_FILL(req, initPathsToDelete, options.pathsToDelete, *this);
        RPC_FILL(req, setIgnoreLiveness, options.ignoreLiveness);
        RPC_FILL(req, setMaxFreed, options.maxFreed);

        auto res = TRY_AWAIT_RPC(req.send());
        results.paths = rpc::to<PathSet>(res.getPaths());
        results.bytesFreed = res.getBytesFreed();
        co_return result::success();
    } catch (...) {
        co_return result::current_exception();
    }

    kj::Promise<Result<void>> ensurePath(const StorePath & path) override
    try {
        auto req = rpc->legacyProtocol.ensurePathRequest();
        RPC_FILL(req, initPath, path, *this);
        TRY_AWAIT_RPC(req.send());
        co_return result::success();
    } catch (...) {
        co_return result::current_exception();
    }

    kj::Promise<Result<void>> optimiseStore() override
    try {
        TRY_AWAIT_RPC(rpc->legacyProtocol.optimiseStoreRequest().send());
        co_return result::success();
    } catch (...) {
        co_return result::current_exception();
    }

    kj::Promise<Result<bool>> verifyStore(bool checkContents, RepairFlag repair) override
    try {
        auto req = rpc->legacyProtocol.verifyStoreRequest();
        RPC_FILL(req, setCheckContents, checkContents);
        RPC_FILL(req, setRepair, repair);
        co_return TRY_AWAIT_RPC(req.send()).getResult();
    } catch (...) {
        co_return result::current_exception();
    }

    kj::Promise<Result<void>>
    addSignatures(const StorePath & storePath, const StringSet & sigs) override
    try {
        auto req = rpc->legacyProtocol.addSignaturesRequest();
        RPC_FILL(req, initPath, storePath, *this);
        RPC_FILL(req, initSignatures, sigs);
        TRY_AWAIT_RPC(req.send());
        co_return result::success();
    } catch (...) {
        co_return result::current_exception();
    }

    kj::Promise<Result<void>> addBuildLog(const StorePath & drvPath, std::string_view log) override
    try {
        auto req = rpc->legacyProtocol.addBuildLogRequest();
        RPC_FILL(req, initPath, drvPath, *this);
        auto stream = TRY_AWAIT_RPC(req.send()).getStream();

        while (!log.empty()) {
            auto feedReq = stream.feedRequest();
            RPC_FILL(feedReq, setRaw, log.substr(0, 65536));
            log.remove_prefix(feedReq.getRaw().size());
            TRY_AWAIT_RPC(feedReq.send());
        }

        TRY_AWAIT_RPC(stream.finalizeRequest().send());
        co_return result::success();
    } catch (...) {
        co_return result::current_exception();
    }

    /* Content-addressed add: the frontend computes the store path, so the result
       comes back as a ValidPathInfo rather than being known up front. */
    kj::Promise<Result<ref<const ValidPathInfo>>> addCAToStore(
        AsyncInputStream & dump,
        std::string_view name,
        ContentAddressMethod caMethod,
        HashType hashType,
        const StorePathSet & references,
        RepairFlag repair
    ) override
    try {
        auto req = rpc->legacyProtocol.addToStoreRequest();
        RPC_FILL(req, setName, name);
        req.setContentAddressMethod(rpc::daemon::to(caMethod));
        req.setHashType(rpc::daemon::to(hashType));
        RPC_FILL(req, initReferences, references, *this);
        RPC_FILL(req, setRepair, repair);

        auto stream = TRY_AWAIT_RPC(req.send()).getResult();

        constexpr size_t BUF_SIZE = 65536;
        auto buf = std::make_unique<char[]>(BUF_SIZE);
        while (auto r = TRY_AWAIT(dump.read(buf.get(), BUF_SIZE))) {
            auto feedReq = stream.feedRequest();
            RPC_FILL(feedReq, setRaw, std::string_view(buf.get(), *r));
            TRY_AWAIT_RPC(feedReq.send());
        }

        auto res = TRY_AWAIT_RPC(stream.finalizeRequest().send());
        co_return make_ref<ValidPathInfo>(from(res.getResult(), *this));
    } catch (...) {
        co_return result::current_exception();
    }

    kj::Promise<Result<void>> buildPathsImpl(
        ConnectionHandle conn, const std::vector<DerivedPath> & paths, BuildMode buildMode
    ) override
    try {
        (void) auto(std::move(conn));

        auto req = rpc->legacyProtocol.buildPathsRequest();
        req.setMode(rpc::from(buildMode));
        RPC_FILL(req, initPaths, paths, *this);
        TRY_AWAIT_RPC(req.send());
        co_return result::success();
    } catch (...) {
        co_return result::current_exception();
    }

    kj::Promise<Result<std::vector<KeyedBuildResult>>> buildPathsWithResultsImpl(
        ConnectionHandle conn, const std::vector<DerivedPath> & paths, BuildMode buildMode
    ) override
    try {
        (void) auto(std::move(conn));

        auto req = rpc->legacyProtocol.buildPathsWithResultRequest();
        req.setMode(rpc::from(buildMode));
        RPC_FILL(req, initPaths, paths, *this);

        auto res = TRY_AWAIT_RPC(req.send());
        co_return rpc::to<std::vector<KeyedBuildResult>>(res.getResult(), *this);
    } catch (...) {
        co_return result::current_exception();
    }

    /* Download a path. The frontend does not return NAR bytes in the reply; it
       feeds them into a Stream capability we supply. So we hand it one end of a
       pipe and return the other as the store's input stream. */
    kj::Promise<Result<box_ptr<AsyncInputStream>>>
    narFromPath(const StorePath & path, const Activity * context) override
    try {
        struct FeedStream final : rpc::daemon::LegacyProtocol::Stream::Server
        {
            std::unique_ptr<AsyncOutputStream> out;

            FeedStream(std::unique_ptr<AsyncOutputStream> out) : out(std::move(out)) {}

            kj::Promise<void> feed(FeedContext context) override
            {
                return RPC_IMPL({
                    auto bytes = context.getParams().getRaw().asChars();
                    TRY_AWAIT(out->writeFull(bytes.begin(), bytes.size()));
                });
            }

            kj::Promise<void> finalize(FinalizeContext context) override
            {
                return RPC_IMPL({ out = nullptr; });
            }
        };

        /* The RPC call's own completion is only observed at EOF; otherwise a
           failure mid-transfer would surface as a short read rather than an
           error. */
        struct ReturnStream : AsyncInputStream
        {
            std::unique_ptr<AsyncInputStream> in;
            capnp::RemotePromise<rpc::daemon::LegacyProtocol::NarFromPathResults> source;

            ReturnStream(
                std::unique_ptr<AsyncInputStream> in,
                capnp::RemotePromise<rpc::daemon::LegacyProtocol::NarFromPathResults> source
            )
                : in(std::move(in))
                , source(std::move(source))
            {
            }

            kj::Promise<Result<std::optional<size_t>>> read(void * buffer, size_t size) override
            try {
                auto got = TRY_AWAIT(in->read(buffer, size));
                if (!got) {
                    TRY_AWAIT_RPC(std::move(source));
                }
                co_return got;
            } catch (...) {
                co_return result::current_exception();
            }
        };

        auto pipe = newZeroCopyPipe();

        auto req = rpc->legacyProtocol.narFromPathRequest();
        RPC_FILL(req, initPath, path, *this);
        req.setInto(kj::heap<FeedStream>(std::move(pipe.writer)));

        co_return make_box_ptr<ReturnStream>(std::move(pipe.reader), req.send());
    } catch (...) {
        co_return result::current_exception();
    }

    /* `nix copy` funnels through here rather than calling addToStore directly.

       Upstream's version toposorts the batch and uploads with concurrency; this
       one is deliberately sequential. Ordering by references does not matter to
       the frontend (it does not validate closures on upload), and sequential
       upload is far easier to keep correct. Revisit if upload throughput matters. */
    kj::Promise<Result<void>> addMultipleToStore(
        PathsSource & pathsToCopy, Activity & act, RepairFlag repair, CheckSigsFlag checkSigs
    ) override
    try {
        for (auto & [info, fn] : pathsToCopy) {
            auto data = TRY_AWAIT(fn());
            TRY_AWAIT(addToStore(info, *data, repair, checkSigs, &act));
        }
        co_return result::success();
    } catch (...) {
        co_return result::current_exception();
    }

    kj::Promise<Result<BuildResult>> buildDerivation(
        const StorePath & drvPath, const BasicDerivation & drv, BuildMode buildMode
    ) override
    try {
        auto req = rpc->legacyProtocol.buildDerivationRequest();
        RPC_FILL(req, initPath, drvPath, *this);
        // `drv` is Data on the wire: a serialized derivation, not a struct.
        RPC_FILL(req, setDrv, GeneratorSource{serializeDerivation(*this, drv)}.drain());
        req.setMode(rpc::from(buildMode));

        auto res = TRY_AWAIT_RPC(req.send());
        co_return rpc::to<nix::BuildResult>(res.getResult(), *this);
    } catch (...) {
        co_return result::current_exception();
    }

protected:
    struct Connection : RemoteStore::Connection
    {
        // Declared first so it is destroyed *last*: the sshConn feeding the pipe
        // must die before the coroutine reading it. Same ordering as SSHStore.
        kj::Promise<void> logHandlerPromise{nullptr};
        std::unique_ptr<SSH::Connection> sshConn;

        // kj::Promise makes the implicit destructor potentially-throwing, which is
        // laxer than the base's. SSHStore declares the same override.
        ~Connection() noexcept = default;

        // The legacy connection machinery inherited from RemoteStore is unused:
        // everything goes through the RPC capability instead. RpcRemoteStore does
        // the same thing.
        int getFD() const override { return -1; }

        // Only valid before logHandler() takes ownership of the pipe, which is
        // exactly the window in which connection setup can fail.
        std::string connectErrorInfo() override
        {
            if (!sshConn || !sshConn->stderrPipe) {
                return "";
            }
            return chomp(drainFD(sshConn->stderrPipe.get(), false));
        }

        /* Drain the remote's stderr for the life of the connection.
           Two reasons this is not optional: without it the frontend's diagnostics
           are invisible, and a frontend that writes steadily to stderr will fill
           the pipe and block. */
        kj::Promise<void> logHandler(std::string storeUri)
        try {
            auto stderrPipe = std::move(sshConn->stderrPipe);
            auto reader = AIO().lowLevelProvider.wrapInputFd(stderrPipe.get());

            LogLineSplitter splitter;
            auto flushLine = [&](const std::string & line) {
                debug("kubernix(%s): %s", storeUri, line);
            };

            auto buf = kj::heapArray<char>(4096);
            while (true) {
                const auto got = co_await reader->tryRead(buf.begin(), 1, buf.size());
                if (got == 0) {
                    break;
                }

                std::string_view data{buf.begin(), got};
                while (!data.empty()) {
                    if (auto line = splitter.feed(data)) {
                        flushLine(*line);
                    }
                }
            }

            if (auto line = splitter.finish(); !line.empty()) {
                flushLine(line);
            }
        } catch (std::exception & e) { // NOLINT(lix-foreign-exceptions)
            logException("kubernix remote store error", e);
        } catch (...) {
            std::terminate();
        }
    };

    struct RpcState
    {
        // Declared before rpcStream so it is destroyed after it: a wrapped TLS
        // stream refers to its context.
        std::unique_ptr<kj::TlsContext> tls;
        kj::Own<kj::AsyncIoStream> rpcStream;
        std::unique_ptr<capnp::TwoPartyClient> client;
        Activity loggerActivity;
        rpc::daemon::LegacyProtocol::Client legacyProtocol;
    };

    /* Dial the frontend and run the TLS handshake, presenting the client chain. */
    kj::Promise<std::tuple<kj::Own<kj::AsyncIoStream>, std::unique_ptr<kj::TlsContext>>> connectTls();

    kj::Promise<Result<std::shared_ptr<RemoteStore::Connection>>> openConnection();

    kj::Promise<Result<std::shared_ptr<RemoteStore::Connection>>> reconnect() override { return openConnection(); }

    kj::Promise<Result<void>> setOptions(RemoteStore::Connection & conn) override
    {
        // Options are forwarded via the RPC setOptions call once store operations
        // are implemented; nothing to do over the legacy connection.
        return {result::success()};
    }

    std::string scheme_;
    std::string host;
    std::optional<SSH> ssh;
    std::shared_ptr<RpcState> rpc;
};

kj::Promise<Result<std::shared_ptr<RemoteStore::Connection>>> KubernixStore::openConnection()
try {
    auto conn = std::make_shared<Connection>();
    kj::Own<kj::AsyncIoStream> rpcStream;
    std::unique_ptr<kj::TlsContext> tlsContext;

    if (useTls()) {
        std::tie(rpcStream, tlsContext) = co_await connectTls();
    } else {
        /* Start the remote end. The client half of the socketpair is dup'd onto both
           stdin and stdout of the remote command, so from here it is a single
           bidirectional stream. */
        std::string command = config_.remoteProgram.get() + " --stdio";

        conn->sshConn = ssh->startCommand(command);

        auto fd = conn->sshConn->socket.get();
        rpcStream = AIO().lowLevelProvider.wrapSocketFd(fd, kj::LowLevelAsyncIoProvider::TAKE_OWNERSHIP);
        conn->sshConn->socket.release();
    }

    auto client = std::make_unique<capnp::TwoPartyClient>(*rpcStream);

    /* The RpcState is built *now*, before the handshake, because
       RpcLoggerServer holds `const Activity &` to the activity we pass it
       (logging-rpc.hh:127) and calls `parent.addChild(...)` on every event
       (logging-rpc.cc). Constructing the activity as a local and moving it into
       the state afterwards leaves that reference dangling, which segfaults the
       client the first time the frontend pushes a log event. Own it first, then
       hand out a reference to the stable location. */
    rpc = std::make_shared<RpcState>(RpcState{
        .tls = std::move(tlsContext),
        .rpcStream = std::move(rpcStream),
        .client = std::move(client),
        .loggerActivity = logger->startActivity(lvlDebug, actUnknown, "kubernix connection"),
        .legacyProtocol = nullptr,
    });

    auto bootstrap = rpc->client->bootstrap().castAs<rpc::daemon::Bootstrap>();

    /* Step 1: what does the far side speak? */
    {
        auto supported = co_await bootstrap.supportedRequest().send();
        auto protocols = supported.getProtocols();
        debug("kubernix: remote advertised %s", supported.toString().flatten().cStr());
        if (protocols.size() == 0) {
            throw Error("kubernix: remote advertised no protocols");
        }
    }

    /* Step 2: request the tunneled legacy protocol. We send Lix's own identifier,
       which embeds PACKAGE_VERSION, so the frontend learns the client's exact
       version. The frontend is lenient about this value. */
    auto bootstrapReq = bootstrap.requestRequest();
    bootstrapReq.setClientInfo("kubernix-plugin");
    RPC_FILL(bootstrapReq, setProtocol, rpc::daemon::UNSTABLE_LEGACY_TUNNELED);
    auto legacyBoot =
        TRY_AWAIT_RPC_NOEXCEPT(bootstrapReq.send()).getResult().castAs<rpc::daemon::LegacyBoot>();

    /* Step 3: hand the frontend a logger capability. Everything the remote build
       prints comes back through this, which is why no side channel is needed. */
    auto initReq = legacyBoot.initRequest();
    initReq.setLogger(kj::heap<rpc::log::RpcLoggerServer>(rpc->loggerActivity));

    auto initResult = TRY_AWAIT_RPC(initReq.send());

    conn->daemonVersion = PROTOCOL_VERSION;
    conn->daemonNixVersion = rpc::to<std::string>(initResult.getVersion());
    conn->remoteTrustsUs =
        initResult.getTrust() == rpc::daemon::LegacyBoot::Trust::TRUSTED   ? std::optional{Trusted}
        : initResult.getTrust() == rpc::daemon::LegacyBoot::Trust::UNTRUSTED ? std::optional{NotTrusted}
                                                                            : std::nullopt;
    conn->store = this;

    rpc->legacyProtocol = initResult.getProtocol();

    notice(
        "kubernix: connected to %s (remote version %s)",
        getUri(),
        conn->daemonNixVersion.value_or("unknown")
    );

    /* Start draining stderr only now: until this point connectErrorInfo() needs
       the pipe to report why setup failed. */
    if (conn->sshConn) {
        conn->logHandlerPromise = conn->logHandler(getUri());
    }

    co_return conn;
} catch (...) {
    co_return result::current_exception();
}

/* Split `host[:port]`, including `[v6]:port`. */
static std::pair<std::string, std::optional<std::string>> splitHostPort(const std::string & authority)
{
    if (authority.starts_with('[')) {
        auto end = authority.find(']');
        if (end == std::string::npos) {
            throw Error("malformed host '%s'", authority);
        }
        auto name = authority.substr(1, end - 1);
        if (authority.size() > end + 1 && authority[end + 1] == ':') {
            return {name, authority.substr(end + 2)};
        }
        return {name, std::nullopt};
    }
    if (auto colon = authority.rfind(':'); colon != std::string::npos) {
        return {authority.substr(0, colon), authority.substr(colon + 1)};
    }
    return {authority, std::nullopt};
}

kj::Promise<std::tuple<kj::Own<kj::AsyncIoStream>, std::unique_ptr<kj::TlsContext>>>
KubernixStore::connectTls()
{
    constexpr uint16_t DEFAULT_TLS_PORT = 2224;

    auto [hostname, port] = splitHostPort(host);
    auto serverName = config_.tlsServerName.get().empty() ? hostname : config_.tlsServerName.get();

    /* The key and the chain are read here rather than at store construction so a
       rotated file is picked up on reconnect. */
    kj::TlsPrivateKey key(readFile(config_.tlsKey.get()).c_str());
    kj::TlsCertificate chain(readFile(config_.tlsCert.get()).c_str());
    kj::TlsKeypair keypair{kj::mv(key), kj::mv(chain)};

    std::vector<kj::TlsCertificate> trusted;
    kj::TlsContext::Options options;
    if (config_.tlsCa.get().empty()) {
        options.useSystemTrustStore = true;
    } else {
        options.useSystemTrustStore = false;
        trusted.emplace_back(readFile(config_.tlsCa.get()).c_str());
    }
    options.trustedCertificates = kj::ArrayPtr<const kj::TlsCertificate>(trusted.data(), trusted.size());
    options.defaultKeypair = keypair;
    options.minVersion = kj::TlsVersion::TLS_1_2;

    auto context = std::make_unique<kj::TlsContext>(kj::mv(options));

    auto authority = port ? hostname + ":" + *port : hostname;
    auto address = co_await AIO().provider.getNetwork().parseAddress(authority, DEFAULT_TLS_PORT);
    auto raw = co_await address->connect();
    auto stream = co_await context->wrapClient(kj::mv(raw), serverName);

    co_return std::make_tuple(kj::mv(stream), kj::mv(context));
}

static void kubernixInit()
{
    StoreImplementations::add<KubernixStore, KubernixStoreConfig>(
        {KubernixStore::sshScheme, KubernixStore::tlsScheme}
    );
}

static struct RegisterKubernix
{
    RegisterKubernix() { kubernixInit(); }
} registerKubernix_;

}

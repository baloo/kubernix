#include "config.h"

#include <lix/libstore/build-result.hh>
#include <lix/libstore/derivations.hh>
#include <lix/libstore/worker-protocol.hh>
#include <lix/libutil/async.hh>
#include <lix/libutil/result.hh>
#include <lix/libutil/types.hh>
#include <lix/libstore/store-api.hh>
#include <lix/libstore/remote-store.hh>
#include <lix/libstore/remote-store-connection.hh>
#include <lix/libstore/filetransfer.hh>

#include <nlohmann/json.hpp>
#include <curl/curl.h>
#include <capnp/message.h>
#include <capnp/serialize.h>
#include "kubernix.capnp.h"

#include <iostream>
#include <string>
#include <unistd.h>

using namespace nix;

//struct CurlResponse {
//    int status_code;
//    std::string body;
//};
//
//static size_t WriteCallback(void* contents, size_t size, size_t nmemb, void* userp) {
//    ((std::string*)userp)->append((char*)contents, size * nmemb);
//    return size * nmemb;
//}
//
//static CurlResponse postCapnp(const std::string& url, kj::ArrayPtr<const capnp::word> data) {
//    CurlResponse response;
//    CURL* curl = curl_easy_init();
//    if(curl) {
//        struct curl_slist* headers = NULL;
//        headers = curl_slist_append(headers, "Content-Type: application/capnp");
//
//        curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
//        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
//        curl_easy_setopt(curl, CURLOPT_POST, 1L);
//        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, data.begin());
//        curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, data.size() * sizeof(capnp::word));
//        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
//        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response.body);
//
//        CURLcode res = curl_easy_perform(curl);
//        if(res == CURLE_OK) {
//            long http_code = 0;
//            curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
//            response.status_code = http_code;
//        } else {
//            response.status_code = 0;
//            response.body = curl_easy_strerror(res);
//        }
//
//        curl_slist_free_all(headers);
//        curl_easy_cleanup(curl);
//    }
//    return response;
//}
//
//static CurlResponse getCapnp(const std::string& url) {
//    CurlResponse response;
//    CURL* curl = curl_easy_init();
//    if(curl) {
//        curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
//        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
//        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response.body);
//
//        CURLcode res = curl_easy_perform(curl);
//        if(res == CURLE_OK) {
//            long http_code = 0;
//            curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
//            response.status_code = http_code;
//        } else {
//            response.status_code = 0;
//            response.body = curl_easy_strerror(res);
//        }
//
//        curl_easy_cleanup(curl);
//    }
//    return response;
//}

struct KubernixStoreConfig : virtual RemoteStoreConfig {
    using RemoteStoreConfig::RemoteStoreConfig;

    const std::string name() override { return "KubernixStore"; }
    std::string doc() override { return "Kubernix remote builder plugin"; }
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
        , host(host)
    {
        std::cout << "KubernixStore constructed for host: " << host << std::endl;
    }

    static kj::Promise<Result<std::optional<ref<Store>>>>
    open(const std::string & scheme, const Path & host, KubernixStoreConfig config)
    try {
        MustCallInit init;
        auto store = make_ref<KubernixStore>(init, kj::Badge<KubernixStore>{}, scheme, host, std::move(config));
        TRY_AWAIT(init(store));
        co_return store;
    } catch (...) {
        co_return result::current_exception();
    }

    KubernixStoreConfig & config() override {
        return config_;
    }
    const KubernixStoreConfig & config() const override {
        return config_;
    }

    static inline const std::string scheme = "kubernix";

    std::string getUri() override {
        return scheme + "://" + host;
    }

    kj::Promise<Result<std::optional<std::string>>> getBuildLogExact(const StorePath & path) override
    {
    }

    //kj::Promise<Result<std::vector<KeyedBuildResult>>> buildPathsWithResults(
    //    const std::vector<DerivedPath> & paths,
    //    BuildMode buildMode,
    //    std::shared_ptr<Store> evalStore) override {

    //    std::vector<KeyedBuildResult> results;

    //    for (const auto& derived_path : paths) {
    //        if (std::holds_alternative<DerivedPathBuilt>(derived_path.raw())) {
    //            const auto& built = std::get<DerivedPathBuilt>(derived_path.raw());
    //
    //            auto drvResult = co_await evalStore->readDerivation(built.drvPath.path);
    //            if (drvResult.has_error()) {
    //                co_return drvResult.error();
    //            }
    //            const auto& drv = drvResult.value();

    //            capnp::MallocMessageBuilder message;
    //            auto req = message.initRoot<BuildRequest>();
    //            auto job_id_builder = req.initJobId(0); // We leave job ID blank on client side, server assigns it.
    //            req.setDerivationPath(evalStore->printStorePath(built.drvPath.path));
    //            req.setSystem(drv.platform);

    //            auto req_inputs = req.initRequiredInputs(drv.inputSrcs.size() + drv.inputDrvs.size());
    //            size_t i = 0;
    //            for (auto & p : drv.inputSrcs) {
    //                req_inputs.set(i++, evalStore->printStorePath(p));
    //            }
    //            for (auto & p : drv.inputDrvs) {
    //                req_inputs.set(i++, evalStore->printStorePath(p.first));
    //            }

    //            auto payload = capnp::messageToFlatArray(message);
    //            std::cout << "Kubernix: Submitting build for " << evalStore->printStorePath(built.drvPath.path) << std::endl;

    //            std::string url = "http://" + host + "/api/v1/build";
    //            CurlResponse resp = postCapnp(url, payload.asPtr());

    //            if (resp.status_code == 200) {
    //                try {
    //                    auto data_array = kj::ArrayPtr<const capnp::word>(
    //                        reinterpret_cast<const capnp::word*>(resp.body.data()),
    //                        resp.body.size() / sizeof(capnp::word)
    //                    );
    //                    capnp::FlatArrayMessageReader reader(data_array);
    //                    auto build_resp = reader.getRoot<BuildResponse>();
    //                    std::string job_id = build_resp.getJobId().cStr();
    //                    std::cout << "Kubernix: Build submitted successfully. Job ID: " << job_id << std::endl;

    //                    // Polling for build completion
    //                    std::string status_url = "http://" + host + "/api/v1/build/" + job_id;
    //                    bool done = false;
    //                    while (!done) {
    //                        sleep(1); // poll every 1 second
    //                        CurlResponse status_resp = getCapnp(status_url);
    //                        if (status_resp.status_code == 200) {
    //                            auto s_data_array = kj::ArrayPtr<const capnp::word>(
    //                                reinterpret_cast<const capnp::word*>(status_resp.body.data()),
    //                                status_resp.body.size() / sizeof(capnp::word)
    //                            );
    //                            capnp::FlatArrayMessageReader s_reader(s_data_array);
    //                            auto job_result = s_reader.getRoot<JobResult>();
    //                            auto status = job_result.getStatus();

    //                            if (status == JobStatus::COMPLETED) {
    //                                std::cout << "Kubernix: Job " << job_id << " completed successfully." << std::endl;
    //                                KeyedBuildResult kbr { {}, derived_path };
    //                                kbr.status = BuildResult::Built;
    //                                results.push_back(kbr);
    //                                done = true;
    //                            } else if (status == JobStatus::FAILED) {
    //                                std::cout << "Kubernix: Job " << job_id << " failed." << std::endl;
    //                                KeyedBuildResult kbr { {}, derived_path };
    //                                kbr.status = BuildResult::MiscFailure;
    //                                kbr.errorMsg = "Kubernix build failed";
    //                                results.push_back(kbr);
    //                                done = true;
    //                            } else {
    //                                // Pending or Running, continue polling
    //                            }
    //                        } else {
    //                            std::cerr << "Kubernix: Error polling status: " << status_resp.status_code << std::endl;
    //                            // Wait a bit more before retrying
    //                        }
    //                    }
    //                } catch (const std::exception& e) {
    //                    std::cerr << "Kubernix: Failed to parse build response: " << e.what() << std::endl;
    //                    co_return result::failure(std::make_exception_ptr(nix::Error("Kubernix: capnp parse error")));
    //                }
    //            } else {
    //                std::cerr << "Kubernix: Failed to submit build. HTTP Status: " << resp.status_code << ", Body: " << resp.body << std::endl;
    //                co_return result::failure(std::make_exception_ptr(nix::Error("Kubernix: Build submission failed for %s", evalStore->printStorePath(built.drvPath.path))));
    //            }
    //        } else {
    //            std::cout << "Kubernix: Skipping opaque derived path" << std::endl;
    //        }
    //
    //    }

    //    co_return results;
    //}

    kj ::Promise<Result<BuildResult>> buildDerivation(
        const StorePath & drvPath, const BasicDerivation & drv, BuildMode buildMode
    ) override{
        std::cout << "KubernixStore::buildDerivation" << std::endl;
    }

    kj::Promise<Result<ref<const ValidPathInfo>>> addCAToStore(
        AsyncInputStream & dump,
        std::string_view name,
        ContentAddressMethod caMethod,
        HashType hashType,
        const StorePathSet & references,
        RepairFlag repair)
    {
        std::cout << "KubernixStore::addCAToStore" << std::endl;
    }

    kj::Promise<Result<StorePath>> addTextToStore(
        std::string_view name,
        std::string_view s,
        const StorePathSet & references,
        RepairFlag repair)
    try {
        AsyncStringInputStream source(s);
        std::cout << "KubernixStore::addTextToStore" << std::endl;
        co_return TRY_AWAIT(addCAToStore(source, name, TextIngestionMethod {}, HashType::SHA256, references, repair))->path;
    } catch (...) {
        co_return result::current_exception();
    }
protected:
    struct Connection : RemoteStore::Connection {
        int fd[2];
        Connection() {
            if (pipe(fd) < 0) {
                throw SysError("pipe failed");
            }
        }
        ~Connection() {
            close(fd[0]);
            close(fd[1]);
        }
        int getFD() const override { return fd[0]; }
    };

    kj::Promise<Result<void>> init();

    std::string host;

    kj::Promise<Result<void>> setOptions(RemoteStore::Connection & conn) override
    {
        /* TODO Add a way to explicitly ask for some options to be
           forwarded. One option: A way to query the daemon for its
           settings, and then a series of params to SSHStore like
           forward-cores or forward-overridden-cores that only
           override the requested settings.
        */
        return {result::success()};
    };
};

kj::Promise<Result<void>> KubernixStore::init()
try {
    co_return result::success();
} catch (...) {
    co_return result::current_exception();
}

static void kubernix_init() {
    std::cout << "Kubernix remote builder plugin loaded!" << std::endl;
    StoreImplementations::add<KubernixStore, KubernixStoreConfig>({KubernixStore::scheme});
}

static struct RegisterKubernix {
    RegisterKubernix() {
        kubernix_init();
    }
} _registerKubernix;

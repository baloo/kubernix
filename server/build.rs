fn main() {
    // Internal frontend<->worker messages.
    capnpc::CompilerCommand::new()
        .src_prefix("../protocol")
        .file("../protocol/kubernix.capnp")
        .run()
        .expect("schema compiler command");

    // The Lix daemon protocol. Schemas are vendored verbatim (see
    // ../protocol/vendor/README.md); the import root must be the vendor directory
    // because they use absolute imports like /lix/libutil/types.capnp.
    capnpc::CompilerCommand::new()
        .src_prefix("../protocol/vendor")
        .import_path("../protocol/vendor")
        .file("../protocol/vendor/lix/libstore/daemon.capnp")
        .file("../protocol/vendor/lix/libstore/types.capnp")
        .file("../protocol/vendor/lix/libutil/types.capnp")
        .file("../protocol/vendor/lix/libutil/logging.capnp")
        .run()
        .expect("lix schema compiler command");

    println!("cargo:rerun-if-changed=../protocol");
}

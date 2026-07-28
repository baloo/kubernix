fn main() {
    capnpc::CompilerCommand::new()
        .src_prefix("../protocol")
        .file("../protocol/kubernix.capnp")
        .run()
        .expect("schema compiler command");
}

fn main() {
    // Generate the tonic server bindings for the shared enforcement contract.
    // Server-only: the engine is the gRPC server; the Go control plane is the client.
    tonic_build::configure()
        .build_server(true)
        .build_client(false)
        .compile_protos(
            &["../../proto/enforcement.proto"],
            &["../../proto"],
        )
        .expect("failed to compile proto/enforcement.proto");

    println!("cargo:rerun-if-changed=../../proto/enforcement.proto");
}

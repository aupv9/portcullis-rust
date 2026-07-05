fn main() {
    // Make `protoc` available without a system dependency. tonic-build needs a
    // protoc to compile the proto; rather than require every environment (CI,
    // `cross` Docker containers, contributors) to apt-install protobuf-compiler,
    // we fall back to a vendored protoc binary when none is on PATH. A system
    // protoc (e.g. set via $PROTOC or present on PATH) still takes precedence.
    if std::env::var_os("PROTOC").is_none() && !system_protoc_on_path() {
        match protoc_bin_vendored::protoc_bin_path() {
            Ok(path) => std::env::set_var("PROTOC", path),
            Err(e) => println!("cargo:warning=no system protoc and vendored protoc unavailable: {e}"),
        }
    }

    // Generate both tonic client and server bindings for the shared contract.
    // Client: the engine dials the control plane over the `Connect` bidi stream
    // (production path behind CGNAT). Server: retained for the on-net/dev unary
    // RPCs and the service unit tests.
    tonic_build::configure()
        .build_server(true)
        .build_client(true)
        .compile_protos(&["../../proto/enforcement.proto"], &["../../proto"])
        .expect("failed to compile proto/enforcement.proto");

    println!("cargo:rerun-if-changed=../../proto/enforcement.proto");
}

/// True if a `protoc` (or `protoc.exe`) executable is found on `PATH`.
fn system_protoc_on_path() -> bool {
    let Some(path) = std::env::var_os("PATH") else {
        return false;
    };
    std::env::split_paths(&path).any(|dir| {
        dir.join("protoc").is_file() || dir.join("protoc.exe").is_file()
    })
}

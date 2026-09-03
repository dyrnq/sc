fn main() {
    // The shim references glibc's `_res` via `<resolv.h>`, so only
    // build it on Linux. Other targets leave `switch_ns` as a stub
    // (see `src/switch_ns.rs`).
    if std::env::var("CARGO_CFG_TARGET_OS").ok().as_deref() == Some("linux") {
        cc::Build::new()
            .file("csrc/switch_ns_shim.c")
            .compile("sc_shim");
        println!("cargo:rerun-if-changed=csrc/switch_ns_shim.c");
    }
}
fn main() {
    cc::Build::new()
        .file("csrc/switch_ns_shim.c")
        .compile("sc_shim");
    println!("cargo:rerun-if-changed=csrc/switch_ns_shim.c");
}
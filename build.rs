#[cfg(all(target_family = "unix", target_pointer_width = "64"))]
fn main() {
    println!("cargo:rerun-if-changed=src/wrap.c");
    cc::Build::new()
        .define("UNIX", Some("1"))
        .define("HAVE_LIMITS_H", Some("1"))
        .define("HAVE_STDINT_H", Some("1"))
        .define("SIZEOF_VOID_P", Some("8"))
        // .include("/opt/cprocsp/include")
        .include("/opt/cprocsp/include/cpcsp")
        .include("/opt/cprocsp/include/pki")
        .file("src/wrap.c")
        .compile("wrap");
}

#[cfg(not(all(target_family = "unix", target_pointer_width = "64")))]
fn main() {
    compile_error!("building supported only on unix 64 bit");
}

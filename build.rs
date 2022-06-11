#[cfg(all(target_family = "unix", target_pointer_width = "64"))]
fn main() {
    // println!("cargo:include=/opt/cprocsp/include/cpcsp");
    println!("cargo:rustc-link-search=/opt/cprocsp/lib/amd64/");
    println!("cargo:rustc-link-lib=cades");
    println!("cargo:rerun-if-changed=src/arch/unix64.h");

    bindgen::Builder::default()
        .clang_args(&[
            "-I/opt/cprocsp/include",
            "-I/opt/cprocsp/include/cpcsp",
            "-I/opt/cprocsp/include/pki",
        ])
        .header("src/arch/unix64.h")
        .generate()
        .expect("Unable to generate bindings")
        .write_to_file("src/cprocsp.rs")
        .expect("Couldn't write bindings!");
}

#[cfg(not(all(target_family = "unix", target_pointer_width = "64")))]
fn main() {
    compile_error!("building supported only on unix 64 bit");
}

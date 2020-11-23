
fn main() {
  println!("cargo:rustc-link-search=native={}/lib", "/usr/local/Cellar/qpid-proton/0.33.0");
  println!("cargo:rustc-link-lib=dylib=qpid-proton");
  println!("cargo:rustc-link-lib=dylib=qpid-proton-core");
  println!("cargo:rustc-link-lib=dylib=qpid-proton-proactor");
}
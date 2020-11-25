extern crate cmake;
use cmake::Config;

fn main()
{
  println!("cargo:rustc-link-lib=dylib=qpid-proton");
  println!("cargo:rustc-link-lib=dylib=qpid-proton-core");
  println!("cargo:rustc-link-lib=dylib=qpid-proton-proactor");
}
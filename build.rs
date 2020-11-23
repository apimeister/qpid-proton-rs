extern crate cmake;
use cmake::Config;

fn main()
{
  let dst = Config::new("lib/qpid-proton-0.33.0")
    .define("BUILD_CPP","OFF")
    .define("BUILD_GO","OFF")
    .define("ENABLE_FUZZ_TESTING","OFF")
    .build();       

  println!("cargo:rustc-link-search=native={}", dst.display());
  println!("cargo:rustc-link-lib=dylib=qpid-proton");
  println!("cargo:rustc-link-lib=dylib=qpid-proton-core");
  println!("cargo:rustc-link-lib=dylib=qpid-proton-proactor");
}
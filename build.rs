extern crate cmake;
use cmake::Config;

fn main()
{
  println!("cargo:rustc-env=PYTHONDONTWRITEBYTECODE=1");
  let dst = Config::new("lib/qpid-proton-0.33.0")
    .define("BUILD_CPP","OFF")
    .define("BUILD_GO","OFF")
    .define("BUILD_PYTHON","OFF")
    .define("BUILD_RUBY","OFF")
    .define("ENABLE_FUZZ_TESTING","OFF")
    .build();       

  println!("cargo:rustc-link-search=native={}/lib64", dst.display());
  println!("cargo:rustc-link-lib=dylib=qpid-proton");
  println!("cargo:rustc-link-lib=dylib=qpid-proton-core");
  println!("cargo:rustc-link-lib=dylib=qpid-proton-proactor");
}
# qpid_proton
[![Latest Version](https://img.shields.io/crates/v/qpid_proton.svg)](https://crates.io/crates/qpid_proton)

Rust bindings for the Apache Qpid Proton EMS C library.


# License
qpid_proton is licensed under Apache License, Version 2.0 (LICENSE-APACHE or http://www.apache.org/licenses/LICENSE-2.0).

# Build

This is still exprimental and only partially working.


### run qpid a server

docker run -it --rm -p 8080:8080 -p 5672:5672 -e AUTH=admin:admin itherz/qpid-server
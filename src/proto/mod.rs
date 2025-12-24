#![allow(rustdoc::invalid_rust_codeblocks)]

pub mod google {
    pub mod api {
        include!("google.api.rs");
    }
}

pub mod opentelemetry {
    pub mod proto {
        pub mod common {
            pub mod v1 {
                include!("opentelemetry.proto.common.v1.rs");
            }
        }
    }
}

pub mod tero {
    pub mod policy {
        pub mod v1 {
            include!("tero.policy.v1.rs");
        }
    }
}

#![allow(rustdoc::invalid_rust_codeblocks)]
#![allow(clippy::doc_overindented_list_items)]
#![allow(clippy::doc_lazy_continuation)]

/// Serde helper for proto3 JSON 64-bit integer encoding (as strings).
pub mod serde_helpers {
    use serde::{self, Deserialize, Deserializer, Serializer};

    /// Serialize u64 as a string (proto3 JSON format).
    pub fn serialize_u64_as_string<S>(value: &u64, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&value.to_string())
    }

    /// Deserialize u64 from either a string or number.
    pub fn deserialize_u64_from_string<'de, D>(deserializer: D) -> Result<u64, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum StringOrNumber {
            String(String),
            Number(u64),
        }

        match StringOrNumber::deserialize(deserializer)? {
            StringOrNumber::String(s) => s.parse().map_err(serde::de::Error::custom),
            StringOrNumber::Number(n) => Ok(n),
        }
    }

    /// Serialize i64 as a string (proto3 JSON format).
    pub fn serialize_i64_as_string<S>(value: &i64, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&value.to_string())
    }

    /// Deserialize i64 from either a string or number.
    pub fn deserialize_i64_from_string<'de, D>(deserializer: D) -> Result<i64, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum StringOrNumber {
            String(String),
            Number(i64),
        }

        match StringOrNumber::deserialize(deserializer)? {
            StringOrNumber::String(s) => s.parse().map_err(serde::de::Error::custom),
            StringOrNumber::Number(n) => Ok(n),
        }
    }

    /// Module for SyncType enum serialization (proto3 JSON uses string names).
    pub mod sync_type {
        use super::super::tero::policy::v1::SyncType;
        use serde::{self, Deserialize, Deserializer, Serializer};

        pub fn serialize<S>(value: &i32, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            let enum_value = SyncType::try_from(*value).unwrap_or(SyncType::Unspecified);
            serializer.serialize_str(enum_value.as_str_name())
        }

        pub fn deserialize<'de, D>(deserializer: D) -> Result<i32, D::Error>
        where
            D: Deserializer<'de>,
        {
            #[derive(Deserialize)]
            #[serde(untagged)]
            enum StringOrInt {
                String(String),
                Int(i32),
            }

            match StringOrInt::deserialize(deserializer)? {
                StringOrInt::String(s) => SyncType::from_str_name(&s)
                    .map(|v| v as i32)
                    .ok_or_else(|| serde::de::Error::custom(format!("unknown SyncType: {}", s))),
                StringOrInt::Int(n) => Ok(n),
            }
        }
    }
}

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

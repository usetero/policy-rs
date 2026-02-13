#![allow(rustdoc::invalid_rust_codeblocks)]
#![allow(clippy::doc_overindented_list_items)]
#![allow(clippy::doc_lazy_continuation)]

/// Serde helper for proto3 JSON 64-bit integer encoding (as strings).
pub mod serde_helpers {
    use serde::{self, Deserialize, Deserializer, Serializer};

    /// Returns true, used as serde default for Policy.enabled.
    pub fn default_true() -> bool {
        true
    }

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

    /// Generates a serde module for a prost enum type that serializes as string
    /// names and deserializes from both string names and integers.
    macro_rules! proto_enum_serde {
        ($mod_name:ident, $enum_type:ty) => {
            pub mod $mod_name {
                use serde::{self, Deserialize, Deserializer, Serializer};

                pub fn serialize<S>(value: &i32, serializer: S) -> Result<S::Ok, S::Error>
                where
                    S: Serializer,
                {
                    let enum_value =
                        <$enum_type>::try_from(*value).unwrap_or(<$enum_type>::Unspecified);
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
                        StringOrInt::String(s) => <$enum_type>::from_str_name(&s)
                            .map(|v| v as i32)
                            .ok_or_else(|| {
                                serde::de::Error::custom(format!(
                                    "unknown {}: {}",
                                    stringify!($enum_type),
                                    s
                                ))
                            }),
                        StringOrInt::Int(n) => Ok(n),
                    }
                }
            }
        };
    }

    // Only SyncType is currently used as a standalone enum field with serde.
    // Enum fields inside oneofs (LogField, MetricField, etc.) use i32 encoding
    // because tonic-build cannot add per-variant serde attributes on oneof enums.
    proto_enum_serde!(sync_type, crate::proto::tero::policy::v1::SyncType);

    /// Module for AttributePath deserialization supporting three forms:
    /// 1. Canonical: `{ "path": ["http", "method"] }`
    /// 2. Shorthand array: `["http", "method"]`
    /// 3. Shorthand string: `"user_id"`
    pub mod attribute_path {
        use super::super::tero::policy::v1::AttributePath;
        use serde::{self, Deserialize, Serialize};

        /// Wrapper type for flexible AttributePath serialization/deserialization.
        /// Used with `#[serde(from = "...", into = "...")]` on AttributePath.
        #[derive(Serialize, Deserialize, Clone)]
        #[serde(untagged)]
        pub enum AttributePathInput {
            /// Canonical: { "path": ["a", "b"] }
            Canonical { path: Vec<String> },
            /// Shorthand array: ["a", "b"]
            Array(Vec<String>),
            /// Shorthand string: "user_id"
            String(String),
        }

        impl From<AttributePathInput> for AttributePath {
            fn from(input: AttributePathInput) -> Self {
                let path = match input {
                    AttributePathInput::Canonical { path } => path,
                    AttributePathInput::Array(arr) => arr,
                    AttributePathInput::String(s) => vec![s],
                };
                AttributePath { path }
            }
        }

        impl From<AttributePath> for AttributePathInput {
            fn from(attr: AttributePath) -> Self {
                // Serialize as shorthand array (cleaner output)
                AttributePathInput::Array(attr.path)
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

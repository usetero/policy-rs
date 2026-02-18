impl serde::Serialize for AggregationTemporality {
    #[allow(deprecated)]
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let variant = match self {
            Self::Unspecified => "AGGREGATION_TEMPORALITY_UNSPECIFIED",
            Self::Delta => "AGGREGATION_TEMPORALITY_DELTA",
            Self::Cumulative => "AGGREGATION_TEMPORALITY_CUMULATIVE",
        };
        serializer.serialize_str(variant)
    }
}
impl<'de> serde::Deserialize<'de> for AggregationTemporality {
    #[allow(deprecated)]
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        const FIELDS: &[&str] = &[
            "AGGREGATION_TEMPORALITY_UNSPECIFIED",
            "AGGREGATION_TEMPORALITY_DELTA",
            "AGGREGATION_TEMPORALITY_CUMULATIVE",
        ];

        struct GeneratedVisitor;

        impl<'de> serde::de::Visitor<'de> for GeneratedVisitor {
            type Value = AggregationTemporality;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(formatter, "expected one of: {:?}", &FIELDS)
            }

            fn visit_i64<E>(self, v: i64) -> std::result::Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                i32::try_from(v)
                    .ok()
                    .and_then(|x| x.try_into().ok())
                    .ok_or_else(|| {
                        serde::de::Error::invalid_value(serde::de::Unexpected::Signed(v), &self)
                    })
            }

            fn visit_u64<E>(self, v: u64) -> std::result::Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                i32::try_from(v)
                    .ok()
                    .and_then(|x| x.try_into().ok())
                    .ok_or_else(|| {
                        serde::de::Error::invalid_value(serde::de::Unexpected::Unsigned(v), &self)
                    })
            }

            fn visit_str<E>(self, value: &str) -> std::result::Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                match value {
                    "AGGREGATION_TEMPORALITY_UNSPECIFIED" => Ok(AggregationTemporality::Unspecified),
                    "AGGREGATION_TEMPORALITY_DELTA" => Ok(AggregationTemporality::Delta),
                    "AGGREGATION_TEMPORALITY_CUMULATIVE" => Ok(AggregationTemporality::Cumulative),
                    _ => Err(serde::de::Error::unknown_variant(value, FIELDS)),
                }
            }
        }
        deserializer.deserialize_any(GeneratedVisitor)
    }
}
impl serde::Serialize for AttributePath {
    #[allow(deprecated)]
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut len = 0;
        if !self.path.is_empty() {
            len += 1;
        }
        let mut struct_ser = serializer.serialize_struct("tero.policy.v1.AttributePath", len)?;
        if !self.path.is_empty() {
            struct_ser.serialize_field("path", &self.path)?;
        }
        struct_ser.end()
    }
}
impl<'de> serde::Deserialize<'de> for AttributePath {
    #[allow(deprecated)]
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        const FIELDS: &[&str] = &[
            "path",
        ];

        #[allow(clippy::enum_variant_names)]
        enum GeneratedField {
            Path,
        }
        impl<'de> serde::Deserialize<'de> for GeneratedField {
            fn deserialize<D>(deserializer: D) -> std::result::Result<GeneratedField, D::Error>
            where
                D: serde::Deserializer<'de>,
            {
                struct GeneratedVisitor;

                impl<'de> serde::de::Visitor<'de> for GeneratedVisitor {
                    type Value = GeneratedField;

                    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                        write!(formatter, "expected one of: {:?}", &FIELDS)
                    }

                    #[allow(unused_variables)]
                    fn visit_str<E>(self, value: &str) -> std::result::Result<GeneratedField, E>
                    where
                        E: serde::de::Error,
                    {
                        match value {
                            "path" => Ok(GeneratedField::Path),
                            _ => Err(serde::de::Error::unknown_field(value, FIELDS)),
                        }
                    }
                }
                deserializer.deserialize_identifier(GeneratedVisitor)
            }
        }
        struct GeneratedVisitor;
        impl<'de> serde::de::Visitor<'de> for GeneratedVisitor {
            type Value = AttributePath;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("struct tero.policy.v1.AttributePath")
            }

            fn visit_map<V>(self, mut map_: V) -> std::result::Result<AttributePath, V::Error>
                where
                    V: serde::de::MapAccess<'de>,
            {
                let mut path__ = None;
                while let Some(k) = map_.next_key()? {
                    match k {
                        GeneratedField::Path => {
                            if path__.is_some() {
                                return Err(serde::de::Error::duplicate_field("path"));
                            }
                            path__ = Some(map_.next_value()?);
                        }
                    }
                }
                Ok(AttributePath {
                    path: path__.unwrap_or_default(),
                })
            }
        }
        deserializer.deserialize_struct("tero.policy.v1.AttributePath", FIELDS, GeneratedVisitor)
    }
}
impl serde::Serialize for ClientMetadata {
    #[allow(deprecated)]
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut len = 0;
        if !self.supported_policy_stages.is_empty() {
            len += 1;
        }
        if !self.labels.is_empty() {
            len += 1;
        }
        if !self.resource_attributes.is_empty() {
            len += 1;
        }
        let mut struct_ser = serializer.serialize_struct("tero.policy.v1.ClientMetadata", len)?;
        if !self.supported_policy_stages.is_empty() {
            let v = self.supported_policy_stages.iter().cloned().map(|v| {
                PolicyStage::try_from(v)
                    .map_err(|_| serde::ser::Error::custom(format!("Invalid variant {}", v)))
                }).collect::<std::result::Result<Vec<_>, _>>()?;
            struct_ser.serialize_field("supportedPolicyStages", &v)?;
        }
        if !self.labels.is_empty() {
            struct_ser.serialize_field("labels", &self.labels)?;
        }
        if !self.resource_attributes.is_empty() {
            struct_ser.serialize_field("resourceAttributes", &self.resource_attributes)?;
        }
        struct_ser.end()
    }
}
impl<'de> serde::Deserialize<'de> for ClientMetadata {
    #[allow(deprecated)]
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        const FIELDS: &[&str] = &[
            "supported_policy_stages",
            "supportedPolicyStages",
            "labels",
            "resource_attributes",
            "resourceAttributes",
        ];

        #[allow(clippy::enum_variant_names)]
        enum GeneratedField {
            SupportedPolicyStages,
            Labels,
            ResourceAttributes,
        }
        impl<'de> serde::Deserialize<'de> for GeneratedField {
            fn deserialize<D>(deserializer: D) -> std::result::Result<GeneratedField, D::Error>
            where
                D: serde::Deserializer<'de>,
            {
                struct GeneratedVisitor;

                impl<'de> serde::de::Visitor<'de> for GeneratedVisitor {
                    type Value = GeneratedField;

                    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                        write!(formatter, "expected one of: {:?}", &FIELDS)
                    }

                    #[allow(unused_variables)]
                    fn visit_str<E>(self, value: &str) -> std::result::Result<GeneratedField, E>
                    where
                        E: serde::de::Error,
                    {
                        match value {
                            "supportedPolicyStages" | "supported_policy_stages" => Ok(GeneratedField::SupportedPolicyStages),
                            "labels" => Ok(GeneratedField::Labels),
                            "resourceAttributes" | "resource_attributes" => Ok(GeneratedField::ResourceAttributes),
                            _ => Err(serde::de::Error::unknown_field(value, FIELDS)),
                        }
                    }
                }
                deserializer.deserialize_identifier(GeneratedVisitor)
            }
        }
        struct GeneratedVisitor;
        impl<'de> serde::de::Visitor<'de> for GeneratedVisitor {
            type Value = ClientMetadata;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("struct tero.policy.v1.ClientMetadata")
            }

            fn visit_map<V>(self, mut map_: V) -> std::result::Result<ClientMetadata, V::Error>
                where
                    V: serde::de::MapAccess<'de>,
            {
                let mut supported_policy_stages__ = None;
                let mut labels__ = None;
                let mut resource_attributes__ = None;
                while let Some(k) = map_.next_key()? {
                    match k {
                        GeneratedField::SupportedPolicyStages => {
                            if supported_policy_stages__.is_some() {
                                return Err(serde::de::Error::duplicate_field("supportedPolicyStages"));
                            }
                            supported_policy_stages__ = Some(map_.next_value::<Vec<PolicyStage>>()?.into_iter().map(|x| x as i32).collect());
                        }
                        GeneratedField::Labels => {
                            if labels__.is_some() {
                                return Err(serde::de::Error::duplicate_field("labels"));
                            }
                            labels__ = Some(map_.next_value()?);
                        }
                        GeneratedField::ResourceAttributes => {
                            if resource_attributes__.is_some() {
                                return Err(serde::de::Error::duplicate_field("resourceAttributes"));
                            }
                            resource_attributes__ = Some(map_.next_value()?);
                        }
                    }
                }
                Ok(ClientMetadata {
                    supported_policy_stages: supported_policy_stages__.unwrap_or_default(),
                    labels: labels__.unwrap_or_default(),
                    resource_attributes: resource_attributes__.unwrap_or_default(),
                })
            }
        }
        deserializer.deserialize_struct("tero.policy.v1.ClientMetadata", FIELDS, GeneratedVisitor)
    }
}
impl serde::Serialize for LogAdd {
    #[allow(deprecated)]
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut len = 0;
        if !self.value.is_empty() {
            len += 1;
        }
        if self.upsert {
            len += 1;
        }
        if self.field.is_some() {
            len += 1;
        }
        let mut struct_ser = serializer.serialize_struct("tero.policy.v1.LogAdd", len)?;
        if !self.value.is_empty() {
            struct_ser.serialize_field("value", &self.value)?;
        }
        if self.upsert {
            struct_ser.serialize_field("upsert", &self.upsert)?;
        }
        if let Some(v) = self.field.as_ref() {
            match v {
                log_add::Field::LogField(v) => {
                    let v = LogField::try_from(*v)
                        .map_err(|_| serde::ser::Error::custom(format!("Invalid variant {}", *v)))?;
                    struct_ser.serialize_field("logField", &v)?;
                }
                log_add::Field::LogAttribute(v) => {
                    struct_ser.serialize_field("logAttribute", v)?;
                }
                log_add::Field::ResourceAttribute(v) => {
                    struct_ser.serialize_field("resourceAttribute", v)?;
                }
                log_add::Field::ScopeAttribute(v) => {
                    struct_ser.serialize_field("scopeAttribute", v)?;
                }
            }
        }
        struct_ser.end()
    }
}
impl<'de> serde::Deserialize<'de> for LogAdd {
    #[allow(deprecated)]
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        const FIELDS: &[&str] = &[
            "value",
            "upsert",
            "log_field",
            "logField",
            "log_attribute",
            "logAttribute",
            "resource_attribute",
            "resourceAttribute",
            "scope_attribute",
            "scopeAttribute",
        ];

        #[allow(clippy::enum_variant_names)]
        enum GeneratedField {
            Value,
            Upsert,
            LogField,
            LogAttribute,
            ResourceAttribute,
            ScopeAttribute,
        }
        impl<'de> serde::Deserialize<'de> for GeneratedField {
            fn deserialize<D>(deserializer: D) -> std::result::Result<GeneratedField, D::Error>
            where
                D: serde::Deserializer<'de>,
            {
                struct GeneratedVisitor;

                impl<'de> serde::de::Visitor<'de> for GeneratedVisitor {
                    type Value = GeneratedField;

                    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                        write!(formatter, "expected one of: {:?}", &FIELDS)
                    }

                    #[allow(unused_variables)]
                    fn visit_str<E>(self, value: &str) -> std::result::Result<GeneratedField, E>
                    where
                        E: serde::de::Error,
                    {
                        match value {
                            "value" => Ok(GeneratedField::Value),
                            "upsert" => Ok(GeneratedField::Upsert),
                            "logField" | "log_field" => Ok(GeneratedField::LogField),
                            "logAttribute" | "log_attribute" => Ok(GeneratedField::LogAttribute),
                            "resourceAttribute" | "resource_attribute" => Ok(GeneratedField::ResourceAttribute),
                            "scopeAttribute" | "scope_attribute" => Ok(GeneratedField::ScopeAttribute),
                            _ => Err(serde::de::Error::unknown_field(value, FIELDS)),
                        }
                    }
                }
                deserializer.deserialize_identifier(GeneratedVisitor)
            }
        }
        struct GeneratedVisitor;
        impl<'de> serde::de::Visitor<'de> for GeneratedVisitor {
            type Value = LogAdd;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("struct tero.policy.v1.LogAdd")
            }

            fn visit_map<V>(self, mut map_: V) -> std::result::Result<LogAdd, V::Error>
                where
                    V: serde::de::MapAccess<'de>,
            {
                let mut value__ = None;
                let mut upsert__ = None;
                let mut field__ = None;
                while let Some(k) = map_.next_key()? {
                    match k {
                        GeneratedField::Value => {
                            if value__.is_some() {
                                return Err(serde::de::Error::duplicate_field("value"));
                            }
                            value__ = Some(map_.next_value()?);
                        }
                        GeneratedField::Upsert => {
                            if upsert__.is_some() {
                                return Err(serde::de::Error::duplicate_field("upsert"));
                            }
                            upsert__ = Some(map_.next_value()?);
                        }
                        GeneratedField::LogField => {
                            if field__.is_some() {
                                return Err(serde::de::Error::duplicate_field("logField"));
                            }
                            field__ = map_.next_value::<::std::option::Option<LogField>>()?.map(|x| log_add::Field::LogField(x as i32));
                        }
                        GeneratedField::LogAttribute => {
                            if field__.is_some() {
                                return Err(serde::de::Error::duplicate_field("logAttribute"));
                            }
                            field__ = map_.next_value::<::std::option::Option<_>>()?.map(log_add::Field::LogAttribute)
;
                        }
                        GeneratedField::ResourceAttribute => {
                            if field__.is_some() {
                                return Err(serde::de::Error::duplicate_field("resourceAttribute"));
                            }
                            field__ = map_.next_value::<::std::option::Option<_>>()?.map(log_add::Field::ResourceAttribute)
;
                        }
                        GeneratedField::ScopeAttribute => {
                            if field__.is_some() {
                                return Err(serde::de::Error::duplicate_field("scopeAttribute"));
                            }
                            field__ = map_.next_value::<::std::option::Option<_>>()?.map(log_add::Field::ScopeAttribute)
;
                        }
                    }
                }
                Ok(LogAdd {
                    value: value__.unwrap_or_default(),
                    upsert: upsert__.unwrap_or_default(),
                    field: field__,
                })
            }
        }
        deserializer.deserialize_struct("tero.policy.v1.LogAdd", FIELDS, GeneratedVisitor)
    }
}
impl serde::Serialize for LogField {
    #[allow(deprecated)]
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let variant = match self {
            Self::Unspecified => "LOG_FIELD_UNSPECIFIED",
            Self::Body => "LOG_FIELD_BODY",
            Self::SeverityText => "LOG_FIELD_SEVERITY_TEXT",
            Self::TraceId => "LOG_FIELD_TRACE_ID",
            Self::SpanId => "LOG_FIELD_SPAN_ID",
            Self::EventName => "LOG_FIELD_EVENT_NAME",
            Self::ResourceSchemaUrl => "LOG_FIELD_RESOURCE_SCHEMA_URL",
            Self::ScopeSchemaUrl => "LOG_FIELD_SCOPE_SCHEMA_URL",
        };
        serializer.serialize_str(variant)
    }
}
impl<'de> serde::Deserialize<'de> for LogField {
    #[allow(deprecated)]
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        const FIELDS: &[&str] = &[
            "LOG_FIELD_UNSPECIFIED",
            "LOG_FIELD_BODY",
            "LOG_FIELD_SEVERITY_TEXT",
            "LOG_FIELD_TRACE_ID",
            "LOG_FIELD_SPAN_ID",
            "LOG_FIELD_EVENT_NAME",
            "LOG_FIELD_RESOURCE_SCHEMA_URL",
            "LOG_FIELD_SCOPE_SCHEMA_URL",
        ];

        struct GeneratedVisitor;

        impl<'de> serde::de::Visitor<'de> for GeneratedVisitor {
            type Value = LogField;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(formatter, "expected one of: {:?}", &FIELDS)
            }

            fn visit_i64<E>(self, v: i64) -> std::result::Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                i32::try_from(v)
                    .ok()
                    .and_then(|x| x.try_into().ok())
                    .ok_or_else(|| {
                        serde::de::Error::invalid_value(serde::de::Unexpected::Signed(v), &self)
                    })
            }

            fn visit_u64<E>(self, v: u64) -> std::result::Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                i32::try_from(v)
                    .ok()
                    .and_then(|x| x.try_into().ok())
                    .ok_or_else(|| {
                        serde::de::Error::invalid_value(serde::de::Unexpected::Unsigned(v), &self)
                    })
            }

            fn visit_str<E>(self, value: &str) -> std::result::Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                match value {
                    "LOG_FIELD_UNSPECIFIED" => Ok(LogField::Unspecified),
                    "LOG_FIELD_BODY" => Ok(LogField::Body),
                    "LOG_FIELD_SEVERITY_TEXT" => Ok(LogField::SeverityText),
                    "LOG_FIELD_TRACE_ID" => Ok(LogField::TraceId),
                    "LOG_FIELD_SPAN_ID" => Ok(LogField::SpanId),
                    "LOG_FIELD_EVENT_NAME" => Ok(LogField::EventName),
                    "LOG_FIELD_RESOURCE_SCHEMA_URL" => Ok(LogField::ResourceSchemaUrl),
                    "LOG_FIELD_SCOPE_SCHEMA_URL" => Ok(LogField::ScopeSchemaUrl),
                    _ => Err(serde::de::Error::unknown_variant(value, FIELDS)),
                }
            }
        }
        deserializer.deserialize_any(GeneratedVisitor)
    }
}
impl serde::Serialize for LogMatcher {
    #[allow(deprecated)]
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut len = 0;
        if self.negate {
            len += 1;
        }
        if self.case_insensitive {
            len += 1;
        }
        if self.field.is_some() {
            len += 1;
        }
        if self.r#match.is_some() {
            len += 1;
        }
        let mut struct_ser = serializer.serialize_struct("tero.policy.v1.LogMatcher", len)?;
        if self.negate {
            struct_ser.serialize_field("negate", &self.negate)?;
        }
        if self.case_insensitive {
            struct_ser.serialize_field("caseInsensitive", &self.case_insensitive)?;
        }
        if let Some(v) = self.field.as_ref() {
            match v {
                log_matcher::Field::LogField(v) => {
                    let v = LogField::try_from(*v)
                        .map_err(|_| serde::ser::Error::custom(format!("Invalid variant {}", *v)))?;
                    struct_ser.serialize_field("logField", &v)?;
                }
                log_matcher::Field::LogAttribute(v) => {
                    struct_ser.serialize_field("logAttribute", v)?;
                }
                log_matcher::Field::ResourceAttribute(v) => {
                    struct_ser.serialize_field("resourceAttribute", v)?;
                }
                log_matcher::Field::ScopeAttribute(v) => {
                    struct_ser.serialize_field("scopeAttribute", v)?;
                }
            }
        }
        if let Some(v) = self.r#match.as_ref() {
            match v {
                log_matcher::Match::Exact(v) => {
                    struct_ser.serialize_field("exact", v)?;
                }
                log_matcher::Match::Regex(v) => {
                    struct_ser.serialize_field("regex", v)?;
                }
                log_matcher::Match::Exists(v) => {
                    struct_ser.serialize_field("exists", v)?;
                }
                log_matcher::Match::StartsWith(v) => {
                    struct_ser.serialize_field("startsWith", v)?;
                }
                log_matcher::Match::EndsWith(v) => {
                    struct_ser.serialize_field("endsWith", v)?;
                }
                log_matcher::Match::Contains(v) => {
                    struct_ser.serialize_field("contains", v)?;
                }
            }
        }
        struct_ser.end()
    }
}
impl<'de> serde::Deserialize<'de> for LogMatcher {
    #[allow(deprecated)]
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        const FIELDS: &[&str] = &[
            "negate",
            "case_insensitive",
            "caseInsensitive",
            "log_field",
            "logField",
            "log_attribute",
            "logAttribute",
            "resource_attribute",
            "resourceAttribute",
            "scope_attribute",
            "scopeAttribute",
            "exact",
            "regex",
            "exists",
            "starts_with",
            "startsWith",
            "ends_with",
            "endsWith",
            "contains",
        ];

        #[allow(clippy::enum_variant_names)]
        enum GeneratedField {
            Negate,
            CaseInsensitive,
            LogField,
            LogAttribute,
            ResourceAttribute,
            ScopeAttribute,
            Exact,
            Regex,
            Exists,
            StartsWith,
            EndsWith,
            Contains,
        }
        impl<'de> serde::Deserialize<'de> for GeneratedField {
            fn deserialize<D>(deserializer: D) -> std::result::Result<GeneratedField, D::Error>
            where
                D: serde::Deserializer<'de>,
            {
                struct GeneratedVisitor;

                impl<'de> serde::de::Visitor<'de> for GeneratedVisitor {
                    type Value = GeneratedField;

                    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                        write!(formatter, "expected one of: {:?}", &FIELDS)
                    }

                    #[allow(unused_variables)]
                    fn visit_str<E>(self, value: &str) -> std::result::Result<GeneratedField, E>
                    where
                        E: serde::de::Error,
                    {
                        match value {
                            "negate" => Ok(GeneratedField::Negate),
                            "caseInsensitive" | "case_insensitive" => Ok(GeneratedField::CaseInsensitive),
                            "logField" | "log_field" => Ok(GeneratedField::LogField),
                            "logAttribute" | "log_attribute" => Ok(GeneratedField::LogAttribute),
                            "resourceAttribute" | "resource_attribute" => Ok(GeneratedField::ResourceAttribute),
                            "scopeAttribute" | "scope_attribute" => Ok(GeneratedField::ScopeAttribute),
                            "exact" => Ok(GeneratedField::Exact),
                            "regex" => Ok(GeneratedField::Regex),
                            "exists" => Ok(GeneratedField::Exists),
                            "startsWith" | "starts_with" => Ok(GeneratedField::StartsWith),
                            "endsWith" | "ends_with" => Ok(GeneratedField::EndsWith),
                            "contains" => Ok(GeneratedField::Contains),
                            _ => Err(serde::de::Error::unknown_field(value, FIELDS)),
                        }
                    }
                }
                deserializer.deserialize_identifier(GeneratedVisitor)
            }
        }
        struct GeneratedVisitor;
        impl<'de> serde::de::Visitor<'de> for GeneratedVisitor {
            type Value = LogMatcher;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("struct tero.policy.v1.LogMatcher")
            }

            fn visit_map<V>(self, mut map_: V) -> std::result::Result<LogMatcher, V::Error>
                where
                    V: serde::de::MapAccess<'de>,
            {
                let mut negate__ = None;
                let mut case_insensitive__ = None;
                let mut field__ = None;
                let mut r#match__ = None;
                while let Some(k) = map_.next_key()? {
                    match k {
                        GeneratedField::Negate => {
                            if negate__.is_some() {
                                return Err(serde::de::Error::duplicate_field("negate"));
                            }
                            negate__ = Some(map_.next_value()?);
                        }
                        GeneratedField::CaseInsensitive => {
                            if case_insensitive__.is_some() {
                                return Err(serde::de::Error::duplicate_field("caseInsensitive"));
                            }
                            case_insensitive__ = Some(map_.next_value()?);
                        }
                        GeneratedField::LogField => {
                            if field__.is_some() {
                                return Err(serde::de::Error::duplicate_field("logField"));
                            }
                            field__ = map_.next_value::<::std::option::Option<LogField>>()?.map(|x| log_matcher::Field::LogField(x as i32));
                        }
                        GeneratedField::LogAttribute => {
                            if field__.is_some() {
                                return Err(serde::de::Error::duplicate_field("logAttribute"));
                            }
                            field__ = map_.next_value::<::std::option::Option<_>>()?.map(log_matcher::Field::LogAttribute)
;
                        }
                        GeneratedField::ResourceAttribute => {
                            if field__.is_some() {
                                return Err(serde::de::Error::duplicate_field("resourceAttribute"));
                            }
                            field__ = map_.next_value::<::std::option::Option<_>>()?.map(log_matcher::Field::ResourceAttribute)
;
                        }
                        GeneratedField::ScopeAttribute => {
                            if field__.is_some() {
                                return Err(serde::de::Error::duplicate_field("scopeAttribute"));
                            }
                            field__ = map_.next_value::<::std::option::Option<_>>()?.map(log_matcher::Field::ScopeAttribute)
;
                        }
                        GeneratedField::Exact => {
                            if r#match__.is_some() {
                                return Err(serde::de::Error::duplicate_field("exact"));
                            }
                            r#match__ = map_.next_value::<::std::option::Option<_>>()?.map(log_matcher::Match::Exact);
                        }
                        GeneratedField::Regex => {
                            if r#match__.is_some() {
                                return Err(serde::de::Error::duplicate_field("regex"));
                            }
                            r#match__ = map_.next_value::<::std::option::Option<_>>()?.map(log_matcher::Match::Regex);
                        }
                        GeneratedField::Exists => {
                            if r#match__.is_some() {
                                return Err(serde::de::Error::duplicate_field("exists"));
                            }
                            r#match__ = map_.next_value::<::std::option::Option<_>>()?.map(log_matcher::Match::Exists);
                        }
                        GeneratedField::StartsWith => {
                            if r#match__.is_some() {
                                return Err(serde::de::Error::duplicate_field("startsWith"));
                            }
                            r#match__ = map_.next_value::<::std::option::Option<_>>()?.map(log_matcher::Match::StartsWith);
                        }
                        GeneratedField::EndsWith => {
                            if r#match__.is_some() {
                                return Err(serde::de::Error::duplicate_field("endsWith"));
                            }
                            r#match__ = map_.next_value::<::std::option::Option<_>>()?.map(log_matcher::Match::EndsWith);
                        }
                        GeneratedField::Contains => {
                            if r#match__.is_some() {
                                return Err(serde::de::Error::duplicate_field("contains"));
                            }
                            r#match__ = map_.next_value::<::std::option::Option<_>>()?.map(log_matcher::Match::Contains);
                        }
                    }
                }
                Ok(LogMatcher {
                    negate: negate__.unwrap_or_default(),
                    case_insensitive: case_insensitive__.unwrap_or_default(),
                    field: field__,
                    r#match: r#match__,
                })
            }
        }
        deserializer.deserialize_struct("tero.policy.v1.LogMatcher", FIELDS, GeneratedVisitor)
    }
}
impl serde::Serialize for LogRedact {
    #[allow(deprecated)]
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut len = 0;
        if !self.replacement.is_empty() {
            len += 1;
        }
        if self.field.is_some() {
            len += 1;
        }
        let mut struct_ser = serializer.serialize_struct("tero.policy.v1.LogRedact", len)?;
        if !self.replacement.is_empty() {
            struct_ser.serialize_field("replacement", &self.replacement)?;
        }
        if let Some(v) = self.field.as_ref() {
            match v {
                log_redact::Field::LogField(v) => {
                    let v = LogField::try_from(*v)
                        .map_err(|_| serde::ser::Error::custom(format!("Invalid variant {}", *v)))?;
                    struct_ser.serialize_field("logField", &v)?;
                }
                log_redact::Field::LogAttribute(v) => {
                    struct_ser.serialize_field("logAttribute", v)?;
                }
                log_redact::Field::ResourceAttribute(v) => {
                    struct_ser.serialize_field("resourceAttribute", v)?;
                }
                log_redact::Field::ScopeAttribute(v) => {
                    struct_ser.serialize_field("scopeAttribute", v)?;
                }
            }
        }
        struct_ser.end()
    }
}
impl<'de> serde::Deserialize<'de> for LogRedact {
    #[allow(deprecated)]
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        const FIELDS: &[&str] = &[
            "replacement",
            "log_field",
            "logField",
            "log_attribute",
            "logAttribute",
            "resource_attribute",
            "resourceAttribute",
            "scope_attribute",
            "scopeAttribute",
        ];

        #[allow(clippy::enum_variant_names)]
        enum GeneratedField {
            Replacement,
            LogField,
            LogAttribute,
            ResourceAttribute,
            ScopeAttribute,
        }
        impl<'de> serde::Deserialize<'de> for GeneratedField {
            fn deserialize<D>(deserializer: D) -> std::result::Result<GeneratedField, D::Error>
            where
                D: serde::Deserializer<'de>,
            {
                struct GeneratedVisitor;

                impl<'de> serde::de::Visitor<'de> for GeneratedVisitor {
                    type Value = GeneratedField;

                    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                        write!(formatter, "expected one of: {:?}", &FIELDS)
                    }

                    #[allow(unused_variables)]
                    fn visit_str<E>(self, value: &str) -> std::result::Result<GeneratedField, E>
                    where
                        E: serde::de::Error,
                    {
                        match value {
                            "replacement" => Ok(GeneratedField::Replacement),
                            "logField" | "log_field" => Ok(GeneratedField::LogField),
                            "logAttribute" | "log_attribute" => Ok(GeneratedField::LogAttribute),
                            "resourceAttribute" | "resource_attribute" => Ok(GeneratedField::ResourceAttribute),
                            "scopeAttribute" | "scope_attribute" => Ok(GeneratedField::ScopeAttribute),
                            _ => Err(serde::de::Error::unknown_field(value, FIELDS)),
                        }
                    }
                }
                deserializer.deserialize_identifier(GeneratedVisitor)
            }
        }
        struct GeneratedVisitor;
        impl<'de> serde::de::Visitor<'de> for GeneratedVisitor {
            type Value = LogRedact;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("struct tero.policy.v1.LogRedact")
            }

            fn visit_map<V>(self, mut map_: V) -> std::result::Result<LogRedact, V::Error>
                where
                    V: serde::de::MapAccess<'de>,
            {
                let mut replacement__ = None;
                let mut field__ = None;
                while let Some(k) = map_.next_key()? {
                    match k {
                        GeneratedField::Replacement => {
                            if replacement__.is_some() {
                                return Err(serde::de::Error::duplicate_field("replacement"));
                            }
                            replacement__ = Some(map_.next_value()?);
                        }
                        GeneratedField::LogField => {
                            if field__.is_some() {
                                return Err(serde::de::Error::duplicate_field("logField"));
                            }
                            field__ = map_.next_value::<::std::option::Option<LogField>>()?.map(|x| log_redact::Field::LogField(x as i32));
                        }
                        GeneratedField::LogAttribute => {
                            if field__.is_some() {
                                return Err(serde::de::Error::duplicate_field("logAttribute"));
                            }
                            field__ = map_.next_value::<::std::option::Option<_>>()?.map(log_redact::Field::LogAttribute)
;
                        }
                        GeneratedField::ResourceAttribute => {
                            if field__.is_some() {
                                return Err(serde::de::Error::duplicate_field("resourceAttribute"));
                            }
                            field__ = map_.next_value::<::std::option::Option<_>>()?.map(log_redact::Field::ResourceAttribute)
;
                        }
                        GeneratedField::ScopeAttribute => {
                            if field__.is_some() {
                                return Err(serde::de::Error::duplicate_field("scopeAttribute"));
                            }
                            field__ = map_.next_value::<::std::option::Option<_>>()?.map(log_redact::Field::ScopeAttribute)
;
                        }
                    }
                }
                Ok(LogRedact {
                    replacement: replacement__.unwrap_or_default(),
                    field: field__,
                })
            }
        }
        deserializer.deserialize_struct("tero.policy.v1.LogRedact", FIELDS, GeneratedVisitor)
    }
}
impl serde::Serialize for LogRemove {
    #[allow(deprecated)]
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut len = 0;
        if self.field.is_some() {
            len += 1;
        }
        let mut struct_ser = serializer.serialize_struct("tero.policy.v1.LogRemove", len)?;
        if let Some(v) = self.field.as_ref() {
            match v {
                log_remove::Field::LogField(v) => {
                    let v = LogField::try_from(*v)
                        .map_err(|_| serde::ser::Error::custom(format!("Invalid variant {}", *v)))?;
                    struct_ser.serialize_field("logField", &v)?;
                }
                log_remove::Field::LogAttribute(v) => {
                    struct_ser.serialize_field("logAttribute", v)?;
                }
                log_remove::Field::ResourceAttribute(v) => {
                    struct_ser.serialize_field("resourceAttribute", v)?;
                }
                log_remove::Field::ScopeAttribute(v) => {
                    struct_ser.serialize_field("scopeAttribute", v)?;
                }
            }
        }
        struct_ser.end()
    }
}
impl<'de> serde::Deserialize<'de> for LogRemove {
    #[allow(deprecated)]
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        const FIELDS: &[&str] = &[
            "log_field",
            "logField",
            "log_attribute",
            "logAttribute",
            "resource_attribute",
            "resourceAttribute",
            "scope_attribute",
            "scopeAttribute",
        ];

        #[allow(clippy::enum_variant_names)]
        enum GeneratedField {
            LogField,
            LogAttribute,
            ResourceAttribute,
            ScopeAttribute,
        }
        impl<'de> serde::Deserialize<'de> for GeneratedField {
            fn deserialize<D>(deserializer: D) -> std::result::Result<GeneratedField, D::Error>
            where
                D: serde::Deserializer<'de>,
            {
                struct GeneratedVisitor;

                impl<'de> serde::de::Visitor<'de> for GeneratedVisitor {
                    type Value = GeneratedField;

                    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                        write!(formatter, "expected one of: {:?}", &FIELDS)
                    }

                    #[allow(unused_variables)]
                    fn visit_str<E>(self, value: &str) -> std::result::Result<GeneratedField, E>
                    where
                        E: serde::de::Error,
                    {
                        match value {
                            "logField" | "log_field" => Ok(GeneratedField::LogField),
                            "logAttribute" | "log_attribute" => Ok(GeneratedField::LogAttribute),
                            "resourceAttribute" | "resource_attribute" => Ok(GeneratedField::ResourceAttribute),
                            "scopeAttribute" | "scope_attribute" => Ok(GeneratedField::ScopeAttribute),
                            _ => Err(serde::de::Error::unknown_field(value, FIELDS)),
                        }
                    }
                }
                deserializer.deserialize_identifier(GeneratedVisitor)
            }
        }
        struct GeneratedVisitor;
        impl<'de> serde::de::Visitor<'de> for GeneratedVisitor {
            type Value = LogRemove;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("struct tero.policy.v1.LogRemove")
            }

            fn visit_map<V>(self, mut map_: V) -> std::result::Result<LogRemove, V::Error>
                where
                    V: serde::de::MapAccess<'de>,
            {
                let mut field__ = None;
                while let Some(k) = map_.next_key()? {
                    match k {
                        GeneratedField::LogField => {
                            if field__.is_some() {
                                return Err(serde::de::Error::duplicate_field("logField"));
                            }
                            field__ = map_.next_value::<::std::option::Option<LogField>>()?.map(|x| log_remove::Field::LogField(x as i32));
                        }
                        GeneratedField::LogAttribute => {
                            if field__.is_some() {
                                return Err(serde::de::Error::duplicate_field("logAttribute"));
                            }
                            field__ = map_.next_value::<::std::option::Option<_>>()?.map(log_remove::Field::LogAttribute)
;
                        }
                        GeneratedField::ResourceAttribute => {
                            if field__.is_some() {
                                return Err(serde::de::Error::duplicate_field("resourceAttribute"));
                            }
                            field__ = map_.next_value::<::std::option::Option<_>>()?.map(log_remove::Field::ResourceAttribute)
;
                        }
                        GeneratedField::ScopeAttribute => {
                            if field__.is_some() {
                                return Err(serde::de::Error::duplicate_field("scopeAttribute"));
                            }
                            field__ = map_.next_value::<::std::option::Option<_>>()?.map(log_remove::Field::ScopeAttribute)
;
                        }
                    }
                }
                Ok(LogRemove {
                    field: field__,
                })
            }
        }
        deserializer.deserialize_struct("tero.policy.v1.LogRemove", FIELDS, GeneratedVisitor)
    }
}
impl serde::Serialize for LogRename {
    #[allow(deprecated)]
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut len = 0;
        if !self.to.is_empty() {
            len += 1;
        }
        if self.upsert {
            len += 1;
        }
        if self.from.is_some() {
            len += 1;
        }
        let mut struct_ser = serializer.serialize_struct("tero.policy.v1.LogRename", len)?;
        if !self.to.is_empty() {
            struct_ser.serialize_field("to", &self.to)?;
        }
        if self.upsert {
            struct_ser.serialize_field("upsert", &self.upsert)?;
        }
        if let Some(v) = self.from.as_ref() {
            match v {
                log_rename::From::FromLogField(v) => {
                    let v = LogField::try_from(*v)
                        .map_err(|_| serde::ser::Error::custom(format!("Invalid variant {}", *v)))?;
                    struct_ser.serialize_field("fromLogField", &v)?;
                }
                log_rename::From::FromLogAttribute(v) => {
                    struct_ser.serialize_field("fromLogAttribute", v)?;
                }
                log_rename::From::FromResourceAttribute(v) => {
                    struct_ser.serialize_field("fromResourceAttribute", v)?;
                }
                log_rename::From::FromScopeAttribute(v) => {
                    struct_ser.serialize_field("fromScopeAttribute", v)?;
                }
            }
        }
        struct_ser.end()
    }
}
impl<'de> serde::Deserialize<'de> for LogRename {
    #[allow(deprecated)]
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        const FIELDS: &[&str] = &[
            "to",
            "upsert",
            "from_log_field",
            "fromLogField",
            "from_log_attribute",
            "fromLogAttribute",
            "from_resource_attribute",
            "fromResourceAttribute",
            "from_scope_attribute",
            "fromScopeAttribute",
        ];

        #[allow(clippy::enum_variant_names)]
        enum GeneratedField {
            To,
            Upsert,
            FromLogField,
            FromLogAttribute,
            FromResourceAttribute,
            FromScopeAttribute,
        }
        impl<'de> serde::Deserialize<'de> for GeneratedField {
            fn deserialize<D>(deserializer: D) -> std::result::Result<GeneratedField, D::Error>
            where
                D: serde::Deserializer<'de>,
            {
                struct GeneratedVisitor;

                impl<'de> serde::de::Visitor<'de> for GeneratedVisitor {
                    type Value = GeneratedField;

                    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                        write!(formatter, "expected one of: {:?}", &FIELDS)
                    }

                    #[allow(unused_variables)]
                    fn visit_str<E>(self, value: &str) -> std::result::Result<GeneratedField, E>
                    where
                        E: serde::de::Error,
                    {
                        match value {
                            "to" => Ok(GeneratedField::To),
                            "upsert" => Ok(GeneratedField::Upsert),
                            "fromLogField" | "from_log_field" => Ok(GeneratedField::FromLogField),
                            "fromLogAttribute" | "from_log_attribute" => Ok(GeneratedField::FromLogAttribute),
                            "fromResourceAttribute" | "from_resource_attribute" => Ok(GeneratedField::FromResourceAttribute),
                            "fromScopeAttribute" | "from_scope_attribute" => Ok(GeneratedField::FromScopeAttribute),
                            _ => Err(serde::de::Error::unknown_field(value, FIELDS)),
                        }
                    }
                }
                deserializer.deserialize_identifier(GeneratedVisitor)
            }
        }
        struct GeneratedVisitor;
        impl<'de> serde::de::Visitor<'de> for GeneratedVisitor {
            type Value = LogRename;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("struct tero.policy.v1.LogRename")
            }

            fn visit_map<V>(self, mut map_: V) -> std::result::Result<LogRename, V::Error>
                where
                    V: serde::de::MapAccess<'de>,
            {
                let mut to__ = None;
                let mut upsert__ = None;
                let mut from__ = None;
                while let Some(k) = map_.next_key()? {
                    match k {
                        GeneratedField::To => {
                            if to__.is_some() {
                                return Err(serde::de::Error::duplicate_field("to"));
                            }
                            to__ = Some(map_.next_value()?);
                        }
                        GeneratedField::Upsert => {
                            if upsert__.is_some() {
                                return Err(serde::de::Error::duplicate_field("upsert"));
                            }
                            upsert__ = Some(map_.next_value()?);
                        }
                        GeneratedField::FromLogField => {
                            if from__.is_some() {
                                return Err(serde::de::Error::duplicate_field("fromLogField"));
                            }
                            from__ = map_.next_value::<::std::option::Option<LogField>>()?.map(|x| log_rename::From::FromLogField(x as i32));
                        }
                        GeneratedField::FromLogAttribute => {
                            if from__.is_some() {
                                return Err(serde::de::Error::duplicate_field("fromLogAttribute"));
                            }
                            from__ = map_.next_value::<::std::option::Option<_>>()?.map(log_rename::From::FromLogAttribute)
;
                        }
                        GeneratedField::FromResourceAttribute => {
                            if from__.is_some() {
                                return Err(serde::de::Error::duplicate_field("fromResourceAttribute"));
                            }
                            from__ = map_.next_value::<::std::option::Option<_>>()?.map(log_rename::From::FromResourceAttribute)
;
                        }
                        GeneratedField::FromScopeAttribute => {
                            if from__.is_some() {
                                return Err(serde::de::Error::duplicate_field("fromScopeAttribute"));
                            }
                            from__ = map_.next_value::<::std::option::Option<_>>()?.map(log_rename::From::FromScopeAttribute)
;
                        }
                    }
                }
                Ok(LogRename {
                    to: to__.unwrap_or_default(),
                    upsert: upsert__.unwrap_or_default(),
                    from: from__,
                })
            }
        }
        deserializer.deserialize_struct("tero.policy.v1.LogRename", FIELDS, GeneratedVisitor)
    }
}
impl serde::Serialize for LogSampleKey {
    #[allow(deprecated)]
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut len = 0;
        if self.field.is_some() {
            len += 1;
        }
        let mut struct_ser = serializer.serialize_struct("tero.policy.v1.LogSampleKey", len)?;
        if let Some(v) = self.field.as_ref() {
            match v {
                log_sample_key::Field::LogField(v) => {
                    let v = LogField::try_from(*v)
                        .map_err(|_| serde::ser::Error::custom(format!("Invalid variant {}", *v)))?;
                    struct_ser.serialize_field("logField", &v)?;
                }
                log_sample_key::Field::LogAttribute(v) => {
                    struct_ser.serialize_field("logAttribute", v)?;
                }
                log_sample_key::Field::ResourceAttribute(v) => {
                    struct_ser.serialize_field("resourceAttribute", v)?;
                }
                log_sample_key::Field::ScopeAttribute(v) => {
                    struct_ser.serialize_field("scopeAttribute", v)?;
                }
            }
        }
        struct_ser.end()
    }
}
impl<'de> serde::Deserialize<'de> for LogSampleKey {
    #[allow(deprecated)]
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        const FIELDS: &[&str] = &[
            "log_field",
            "logField",
            "log_attribute",
            "logAttribute",
            "resource_attribute",
            "resourceAttribute",
            "scope_attribute",
            "scopeAttribute",
        ];

        #[allow(clippy::enum_variant_names)]
        enum GeneratedField {
            LogField,
            LogAttribute,
            ResourceAttribute,
            ScopeAttribute,
        }
        impl<'de> serde::Deserialize<'de> for GeneratedField {
            fn deserialize<D>(deserializer: D) -> std::result::Result<GeneratedField, D::Error>
            where
                D: serde::Deserializer<'de>,
            {
                struct GeneratedVisitor;

                impl<'de> serde::de::Visitor<'de> for GeneratedVisitor {
                    type Value = GeneratedField;

                    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                        write!(formatter, "expected one of: {:?}", &FIELDS)
                    }

                    #[allow(unused_variables)]
                    fn visit_str<E>(self, value: &str) -> std::result::Result<GeneratedField, E>
                    where
                        E: serde::de::Error,
                    {
                        match value {
                            "logField" | "log_field" => Ok(GeneratedField::LogField),
                            "logAttribute" | "log_attribute" => Ok(GeneratedField::LogAttribute),
                            "resourceAttribute" | "resource_attribute" => Ok(GeneratedField::ResourceAttribute),
                            "scopeAttribute" | "scope_attribute" => Ok(GeneratedField::ScopeAttribute),
                            _ => Err(serde::de::Error::unknown_field(value, FIELDS)),
                        }
                    }
                }
                deserializer.deserialize_identifier(GeneratedVisitor)
            }
        }
        struct GeneratedVisitor;
        impl<'de> serde::de::Visitor<'de> for GeneratedVisitor {
            type Value = LogSampleKey;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("struct tero.policy.v1.LogSampleKey")
            }

            fn visit_map<V>(self, mut map_: V) -> std::result::Result<LogSampleKey, V::Error>
                where
                    V: serde::de::MapAccess<'de>,
            {
                let mut field__ = None;
                while let Some(k) = map_.next_key()? {
                    match k {
                        GeneratedField::LogField => {
                            if field__.is_some() {
                                return Err(serde::de::Error::duplicate_field("logField"));
                            }
                            field__ = map_.next_value::<::std::option::Option<LogField>>()?.map(|x| log_sample_key::Field::LogField(x as i32));
                        }
                        GeneratedField::LogAttribute => {
                            if field__.is_some() {
                                return Err(serde::de::Error::duplicate_field("logAttribute"));
                            }
                            field__ = map_.next_value::<::std::option::Option<_>>()?.map(log_sample_key::Field::LogAttribute)
;
                        }
                        GeneratedField::ResourceAttribute => {
                            if field__.is_some() {
                                return Err(serde::de::Error::duplicate_field("resourceAttribute"));
                            }
                            field__ = map_.next_value::<::std::option::Option<_>>()?.map(log_sample_key::Field::ResourceAttribute)
;
                        }
                        GeneratedField::ScopeAttribute => {
                            if field__.is_some() {
                                return Err(serde::de::Error::duplicate_field("scopeAttribute"));
                            }
                            field__ = map_.next_value::<::std::option::Option<_>>()?.map(log_sample_key::Field::ScopeAttribute)
;
                        }
                    }
                }
                Ok(LogSampleKey {
                    field: field__,
                })
            }
        }
        deserializer.deserialize_struct("tero.policy.v1.LogSampleKey", FIELDS, GeneratedVisitor)
    }
}
impl serde::Serialize for LogTarget {
    #[allow(deprecated)]
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut len = 0;
        if !self.r#match.is_empty() {
            len += 1;
        }
        if !self.keep.is_empty() {
            len += 1;
        }
        if self.transform.is_some() {
            len += 1;
        }
        if self.sample_key.is_some() {
            len += 1;
        }
        let mut struct_ser = serializer.serialize_struct("tero.policy.v1.LogTarget", len)?;
        if !self.r#match.is_empty() {
            struct_ser.serialize_field("match", &self.r#match)?;
        }
        if !self.keep.is_empty() {
            struct_ser.serialize_field("keep", &self.keep)?;
        }
        if let Some(v) = self.transform.as_ref() {
            struct_ser.serialize_field("transform", v)?;
        }
        if let Some(v) = self.sample_key.as_ref() {
            struct_ser.serialize_field("sampleKey", v)?;
        }
        struct_ser.end()
    }
}
impl<'de> serde::Deserialize<'de> for LogTarget {
    #[allow(deprecated)]
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        const FIELDS: &[&str] = &[
            "match",
            "keep",
            "transform",
            "sample_key",
            "sampleKey",
        ];

        #[allow(clippy::enum_variant_names)]
        enum GeneratedField {
            Match,
            Keep,
            Transform,
            SampleKey,
        }
        impl<'de> serde::Deserialize<'de> for GeneratedField {
            fn deserialize<D>(deserializer: D) -> std::result::Result<GeneratedField, D::Error>
            where
                D: serde::Deserializer<'de>,
            {
                struct GeneratedVisitor;

                impl<'de> serde::de::Visitor<'de> for GeneratedVisitor {
                    type Value = GeneratedField;

                    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                        write!(formatter, "expected one of: {:?}", &FIELDS)
                    }

                    #[allow(unused_variables)]
                    fn visit_str<E>(self, value: &str) -> std::result::Result<GeneratedField, E>
                    where
                        E: serde::de::Error,
                    {
                        match value {
                            "match" => Ok(GeneratedField::Match),
                            "keep" => Ok(GeneratedField::Keep),
                            "transform" => Ok(GeneratedField::Transform),
                            "sampleKey" | "sample_key" => Ok(GeneratedField::SampleKey),
                            _ => Err(serde::de::Error::unknown_field(value, FIELDS)),
                        }
                    }
                }
                deserializer.deserialize_identifier(GeneratedVisitor)
            }
        }
        struct GeneratedVisitor;
        impl<'de> serde::de::Visitor<'de> for GeneratedVisitor {
            type Value = LogTarget;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("struct tero.policy.v1.LogTarget")
            }

            fn visit_map<V>(self, mut map_: V) -> std::result::Result<LogTarget, V::Error>
                where
                    V: serde::de::MapAccess<'de>,
            {
                let mut r#match__ = None;
                let mut keep__ = None;
                let mut transform__ = None;
                let mut sample_key__ = None;
                while let Some(k) = map_.next_key()? {
                    match k {
                        GeneratedField::Match => {
                            if r#match__.is_some() {
                                return Err(serde::de::Error::duplicate_field("match"));
                            }
                            r#match__ = Some(map_.next_value()?);
                        }
                        GeneratedField::Keep => {
                            if keep__.is_some() {
                                return Err(serde::de::Error::duplicate_field("keep"));
                            }
                            keep__ = Some(map_.next_value()?);
                        }
                        GeneratedField::Transform => {
                            if transform__.is_some() {
                                return Err(serde::de::Error::duplicate_field("transform"));
                            }
                            transform__ = map_.next_value()?;
                        }
                        GeneratedField::SampleKey => {
                            if sample_key__.is_some() {
                                return Err(serde::de::Error::duplicate_field("sampleKey"));
                            }
                            sample_key__ = map_.next_value()?;
                        }
                    }
                }
                Ok(LogTarget {
                    r#match: r#match__.unwrap_or_default(),
                    keep: keep__.unwrap_or_default(),
                    transform: transform__,
                    sample_key: sample_key__,
                })
            }
        }
        deserializer.deserialize_struct("tero.policy.v1.LogTarget", FIELDS, GeneratedVisitor)
    }
}
impl serde::Serialize for LogTransform {
    #[allow(deprecated)]
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut len = 0;
        if !self.remove.is_empty() {
            len += 1;
        }
        if !self.redact.is_empty() {
            len += 1;
        }
        if !self.rename.is_empty() {
            len += 1;
        }
        if !self.add.is_empty() {
            len += 1;
        }
        let mut struct_ser = serializer.serialize_struct("tero.policy.v1.LogTransform", len)?;
        if !self.remove.is_empty() {
            struct_ser.serialize_field("remove", &self.remove)?;
        }
        if !self.redact.is_empty() {
            struct_ser.serialize_field("redact", &self.redact)?;
        }
        if !self.rename.is_empty() {
            struct_ser.serialize_field("rename", &self.rename)?;
        }
        if !self.add.is_empty() {
            struct_ser.serialize_field("add", &self.add)?;
        }
        struct_ser.end()
    }
}
impl<'de> serde::Deserialize<'de> for LogTransform {
    #[allow(deprecated)]
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        const FIELDS: &[&str] = &[
            "remove",
            "redact",
            "rename",
            "add",
        ];

        #[allow(clippy::enum_variant_names)]
        enum GeneratedField {
            Remove,
            Redact,
            Rename,
            Add,
        }
        impl<'de> serde::Deserialize<'de> for GeneratedField {
            fn deserialize<D>(deserializer: D) -> std::result::Result<GeneratedField, D::Error>
            where
                D: serde::Deserializer<'de>,
            {
                struct GeneratedVisitor;

                impl<'de> serde::de::Visitor<'de> for GeneratedVisitor {
                    type Value = GeneratedField;

                    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                        write!(formatter, "expected one of: {:?}", &FIELDS)
                    }

                    #[allow(unused_variables)]
                    fn visit_str<E>(self, value: &str) -> std::result::Result<GeneratedField, E>
                    where
                        E: serde::de::Error,
                    {
                        match value {
                            "remove" => Ok(GeneratedField::Remove),
                            "redact" => Ok(GeneratedField::Redact),
                            "rename" => Ok(GeneratedField::Rename),
                            "add" => Ok(GeneratedField::Add),
                            _ => Err(serde::de::Error::unknown_field(value, FIELDS)),
                        }
                    }
                }
                deserializer.deserialize_identifier(GeneratedVisitor)
            }
        }
        struct GeneratedVisitor;
        impl<'de> serde::de::Visitor<'de> for GeneratedVisitor {
            type Value = LogTransform;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("struct tero.policy.v1.LogTransform")
            }

            fn visit_map<V>(self, mut map_: V) -> std::result::Result<LogTransform, V::Error>
                where
                    V: serde::de::MapAccess<'de>,
            {
                let mut remove__ = None;
                let mut redact__ = None;
                let mut rename__ = None;
                let mut add__ = None;
                while let Some(k) = map_.next_key()? {
                    match k {
                        GeneratedField::Remove => {
                            if remove__.is_some() {
                                return Err(serde::de::Error::duplicate_field("remove"));
                            }
                            remove__ = Some(map_.next_value()?);
                        }
                        GeneratedField::Redact => {
                            if redact__.is_some() {
                                return Err(serde::de::Error::duplicate_field("redact"));
                            }
                            redact__ = Some(map_.next_value()?);
                        }
                        GeneratedField::Rename => {
                            if rename__.is_some() {
                                return Err(serde::de::Error::duplicate_field("rename"));
                            }
                            rename__ = Some(map_.next_value()?);
                        }
                        GeneratedField::Add => {
                            if add__.is_some() {
                                return Err(serde::de::Error::duplicate_field("add"));
                            }
                            add__ = Some(map_.next_value()?);
                        }
                    }
                }
                Ok(LogTransform {
                    remove: remove__.unwrap_or_default(),
                    redact: redact__.unwrap_or_default(),
                    rename: rename__.unwrap_or_default(),
                    add: add__.unwrap_or_default(),
                })
            }
        }
        deserializer.deserialize_struct("tero.policy.v1.LogTransform", FIELDS, GeneratedVisitor)
    }
}
impl serde::Serialize for MetricField {
    #[allow(deprecated)]
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let variant = match self {
            Self::Unspecified => "METRIC_FIELD_UNSPECIFIED",
            Self::Name => "METRIC_FIELD_NAME",
            Self::Description => "METRIC_FIELD_DESCRIPTION",
            Self::Unit => "METRIC_FIELD_UNIT",
            Self::ResourceSchemaUrl => "METRIC_FIELD_RESOURCE_SCHEMA_URL",
            Self::ScopeSchemaUrl => "METRIC_FIELD_SCOPE_SCHEMA_URL",
            Self::ScopeName => "METRIC_FIELD_SCOPE_NAME",
            Self::ScopeVersion => "METRIC_FIELD_SCOPE_VERSION",
        };
        serializer.serialize_str(variant)
    }
}
impl<'de> serde::Deserialize<'de> for MetricField {
    #[allow(deprecated)]
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        const FIELDS: &[&str] = &[
            "METRIC_FIELD_UNSPECIFIED",
            "METRIC_FIELD_NAME",
            "METRIC_FIELD_DESCRIPTION",
            "METRIC_FIELD_UNIT",
            "METRIC_FIELD_RESOURCE_SCHEMA_URL",
            "METRIC_FIELD_SCOPE_SCHEMA_URL",
            "METRIC_FIELD_SCOPE_NAME",
            "METRIC_FIELD_SCOPE_VERSION",
        ];

        struct GeneratedVisitor;

        impl<'de> serde::de::Visitor<'de> for GeneratedVisitor {
            type Value = MetricField;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(formatter, "expected one of: {:?}", &FIELDS)
            }

            fn visit_i64<E>(self, v: i64) -> std::result::Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                i32::try_from(v)
                    .ok()
                    .and_then(|x| x.try_into().ok())
                    .ok_or_else(|| {
                        serde::de::Error::invalid_value(serde::de::Unexpected::Signed(v), &self)
                    })
            }

            fn visit_u64<E>(self, v: u64) -> std::result::Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                i32::try_from(v)
                    .ok()
                    .and_then(|x| x.try_into().ok())
                    .ok_or_else(|| {
                        serde::de::Error::invalid_value(serde::de::Unexpected::Unsigned(v), &self)
                    })
            }

            fn visit_str<E>(self, value: &str) -> std::result::Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                match value {
                    "METRIC_FIELD_UNSPECIFIED" => Ok(MetricField::Unspecified),
                    "METRIC_FIELD_NAME" => Ok(MetricField::Name),
                    "METRIC_FIELD_DESCRIPTION" => Ok(MetricField::Description),
                    "METRIC_FIELD_UNIT" => Ok(MetricField::Unit),
                    "METRIC_FIELD_RESOURCE_SCHEMA_URL" => Ok(MetricField::ResourceSchemaUrl),
                    "METRIC_FIELD_SCOPE_SCHEMA_URL" => Ok(MetricField::ScopeSchemaUrl),
                    "METRIC_FIELD_SCOPE_NAME" => Ok(MetricField::ScopeName),
                    "METRIC_FIELD_SCOPE_VERSION" => Ok(MetricField::ScopeVersion),
                    _ => Err(serde::de::Error::unknown_variant(value, FIELDS)),
                }
            }
        }
        deserializer.deserialize_any(GeneratedVisitor)
    }
}
impl serde::Serialize for MetricMatcher {
    #[allow(deprecated)]
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut len = 0;
        if self.negate {
            len += 1;
        }
        if self.case_insensitive {
            len += 1;
        }
        if self.field.is_some() {
            len += 1;
        }
        if self.r#match.is_some() {
            len += 1;
        }
        let mut struct_ser = serializer.serialize_struct("tero.policy.v1.MetricMatcher", len)?;
        if self.negate {
            struct_ser.serialize_field("negate", &self.negate)?;
        }
        if self.case_insensitive {
            struct_ser.serialize_field("caseInsensitive", &self.case_insensitive)?;
        }
        if let Some(v) = self.field.as_ref() {
            match v {
                metric_matcher::Field::MetricField(v) => {
                    let v = MetricField::try_from(*v)
                        .map_err(|_| serde::ser::Error::custom(format!("Invalid variant {}", *v)))?;
                    struct_ser.serialize_field("metricField", &v)?;
                }
                metric_matcher::Field::DatapointAttribute(v) => {
                    struct_ser.serialize_field("datapointAttribute", v)?;
                }
                metric_matcher::Field::ResourceAttribute(v) => {
                    struct_ser.serialize_field("resourceAttribute", v)?;
                }
                metric_matcher::Field::ScopeAttribute(v) => {
                    struct_ser.serialize_field("scopeAttribute", v)?;
                }
                metric_matcher::Field::MetricType(v) => {
                    let v = MetricType::try_from(*v)
                        .map_err(|_| serde::ser::Error::custom(format!("Invalid variant {}", *v)))?;
                    struct_ser.serialize_field("metricType", &v)?;
                }
                metric_matcher::Field::AggregationTemporality(v) => {
                    let v = AggregationTemporality::try_from(*v)
                        .map_err(|_| serde::ser::Error::custom(format!("Invalid variant {}", *v)))?;
                    struct_ser.serialize_field("aggregationTemporality", &v)?;
                }
            }
        }
        if let Some(v) = self.r#match.as_ref() {
            match v {
                metric_matcher::Match::Exact(v) => {
                    struct_ser.serialize_field("exact", v)?;
                }
                metric_matcher::Match::Regex(v) => {
                    struct_ser.serialize_field("regex", v)?;
                }
                metric_matcher::Match::Exists(v) => {
                    struct_ser.serialize_field("exists", v)?;
                }
                metric_matcher::Match::StartsWith(v) => {
                    struct_ser.serialize_field("startsWith", v)?;
                }
                metric_matcher::Match::EndsWith(v) => {
                    struct_ser.serialize_field("endsWith", v)?;
                }
                metric_matcher::Match::Contains(v) => {
                    struct_ser.serialize_field("contains", v)?;
                }
            }
        }
        struct_ser.end()
    }
}
impl<'de> serde::Deserialize<'de> for MetricMatcher {
    #[allow(deprecated)]
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        const FIELDS: &[&str] = &[
            "negate",
            "case_insensitive",
            "caseInsensitive",
            "metric_field",
            "metricField",
            "datapoint_attribute",
            "datapointAttribute",
            "resource_attribute",
            "resourceAttribute",
            "scope_attribute",
            "scopeAttribute",
            "metric_type",
            "metricType",
            "aggregation_temporality",
            "aggregationTemporality",
            "exact",
            "regex",
            "exists",
            "starts_with",
            "startsWith",
            "ends_with",
            "endsWith",
            "contains",
        ];

        #[allow(clippy::enum_variant_names)]
        enum GeneratedField {
            Negate,
            CaseInsensitive,
            MetricField,
            DatapointAttribute,
            ResourceAttribute,
            ScopeAttribute,
            MetricType,
            AggregationTemporality,
            Exact,
            Regex,
            Exists,
            StartsWith,
            EndsWith,
            Contains,
        }
        impl<'de> serde::Deserialize<'de> for GeneratedField {
            fn deserialize<D>(deserializer: D) -> std::result::Result<GeneratedField, D::Error>
            where
                D: serde::Deserializer<'de>,
            {
                struct GeneratedVisitor;

                impl<'de> serde::de::Visitor<'de> for GeneratedVisitor {
                    type Value = GeneratedField;

                    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                        write!(formatter, "expected one of: {:?}", &FIELDS)
                    }

                    #[allow(unused_variables)]
                    fn visit_str<E>(self, value: &str) -> std::result::Result<GeneratedField, E>
                    where
                        E: serde::de::Error,
                    {
                        match value {
                            "negate" => Ok(GeneratedField::Negate),
                            "caseInsensitive" | "case_insensitive" => Ok(GeneratedField::CaseInsensitive),
                            "metricField" | "metric_field" => Ok(GeneratedField::MetricField),
                            "datapointAttribute" | "datapoint_attribute" => Ok(GeneratedField::DatapointAttribute),
                            "resourceAttribute" | "resource_attribute" => Ok(GeneratedField::ResourceAttribute),
                            "scopeAttribute" | "scope_attribute" => Ok(GeneratedField::ScopeAttribute),
                            "metricType" | "metric_type" => Ok(GeneratedField::MetricType),
                            "aggregationTemporality" | "aggregation_temporality" => Ok(GeneratedField::AggregationTemporality),
                            "exact" => Ok(GeneratedField::Exact),
                            "regex" => Ok(GeneratedField::Regex),
                            "exists" => Ok(GeneratedField::Exists),
                            "startsWith" | "starts_with" => Ok(GeneratedField::StartsWith),
                            "endsWith" | "ends_with" => Ok(GeneratedField::EndsWith),
                            "contains" => Ok(GeneratedField::Contains),
                            _ => Err(serde::de::Error::unknown_field(value, FIELDS)),
                        }
                    }
                }
                deserializer.deserialize_identifier(GeneratedVisitor)
            }
        }
        struct GeneratedVisitor;
        impl<'de> serde::de::Visitor<'de> for GeneratedVisitor {
            type Value = MetricMatcher;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("struct tero.policy.v1.MetricMatcher")
            }

            fn visit_map<V>(self, mut map_: V) -> std::result::Result<MetricMatcher, V::Error>
                where
                    V: serde::de::MapAccess<'de>,
            {
                let mut negate__ = None;
                let mut case_insensitive__ = None;
                let mut field__ = None;
                let mut r#match__ = None;
                while let Some(k) = map_.next_key()? {
                    match k {
                        GeneratedField::Negate => {
                            if negate__.is_some() {
                                return Err(serde::de::Error::duplicate_field("negate"));
                            }
                            negate__ = Some(map_.next_value()?);
                        }
                        GeneratedField::CaseInsensitive => {
                            if case_insensitive__.is_some() {
                                return Err(serde::de::Error::duplicate_field("caseInsensitive"));
                            }
                            case_insensitive__ = Some(map_.next_value()?);
                        }
                        GeneratedField::MetricField => {
                            if field__.is_some() {
                                return Err(serde::de::Error::duplicate_field("metricField"));
                            }
                            field__ = map_.next_value::<::std::option::Option<MetricField>>()?.map(|x| metric_matcher::Field::MetricField(x as i32));
                        }
                        GeneratedField::DatapointAttribute => {
                            if field__.is_some() {
                                return Err(serde::de::Error::duplicate_field("datapointAttribute"));
                            }
                            field__ = map_.next_value::<::std::option::Option<_>>()?.map(metric_matcher::Field::DatapointAttribute)
;
                        }
                        GeneratedField::ResourceAttribute => {
                            if field__.is_some() {
                                return Err(serde::de::Error::duplicate_field("resourceAttribute"));
                            }
                            field__ = map_.next_value::<::std::option::Option<_>>()?.map(metric_matcher::Field::ResourceAttribute)
;
                        }
                        GeneratedField::ScopeAttribute => {
                            if field__.is_some() {
                                return Err(serde::de::Error::duplicate_field("scopeAttribute"));
                            }
                            field__ = map_.next_value::<::std::option::Option<_>>()?.map(metric_matcher::Field::ScopeAttribute)
;
                        }
                        GeneratedField::MetricType => {
                            if field__.is_some() {
                                return Err(serde::de::Error::duplicate_field("metricType"));
                            }
                            field__ = map_.next_value::<::std::option::Option<MetricType>>()?.map(|x| metric_matcher::Field::MetricType(x as i32));
                        }
                        GeneratedField::AggregationTemporality => {
                            if field__.is_some() {
                                return Err(serde::de::Error::duplicate_field("aggregationTemporality"));
                            }
                            field__ = map_.next_value::<::std::option::Option<AggregationTemporality>>()?.map(|x| metric_matcher::Field::AggregationTemporality(x as i32));
                        }
                        GeneratedField::Exact => {
                            if r#match__.is_some() {
                                return Err(serde::de::Error::duplicate_field("exact"));
                            }
                            r#match__ = map_.next_value::<::std::option::Option<_>>()?.map(metric_matcher::Match::Exact);
                        }
                        GeneratedField::Regex => {
                            if r#match__.is_some() {
                                return Err(serde::de::Error::duplicate_field("regex"));
                            }
                            r#match__ = map_.next_value::<::std::option::Option<_>>()?.map(metric_matcher::Match::Regex);
                        }
                        GeneratedField::Exists => {
                            if r#match__.is_some() {
                                return Err(serde::de::Error::duplicate_field("exists"));
                            }
                            r#match__ = map_.next_value::<::std::option::Option<_>>()?.map(metric_matcher::Match::Exists);
                        }
                        GeneratedField::StartsWith => {
                            if r#match__.is_some() {
                                return Err(serde::de::Error::duplicate_field("startsWith"));
                            }
                            r#match__ = map_.next_value::<::std::option::Option<_>>()?.map(metric_matcher::Match::StartsWith);
                        }
                        GeneratedField::EndsWith => {
                            if r#match__.is_some() {
                                return Err(serde::de::Error::duplicate_field("endsWith"));
                            }
                            r#match__ = map_.next_value::<::std::option::Option<_>>()?.map(metric_matcher::Match::EndsWith);
                        }
                        GeneratedField::Contains => {
                            if r#match__.is_some() {
                                return Err(serde::de::Error::duplicate_field("contains"));
                            }
                            r#match__ = map_.next_value::<::std::option::Option<_>>()?.map(metric_matcher::Match::Contains);
                        }
                    }
                }
                Ok(MetricMatcher {
                    negate: negate__.unwrap_or_default(),
                    case_insensitive: case_insensitive__.unwrap_or_default(),
                    field: field__,
                    r#match: r#match__,
                })
            }
        }
        deserializer.deserialize_struct("tero.policy.v1.MetricMatcher", FIELDS, GeneratedVisitor)
    }
}
impl serde::Serialize for MetricTarget {
    #[allow(deprecated)]
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut len = 0;
        if !self.r#match.is_empty() {
            len += 1;
        }
        if self.keep {
            len += 1;
        }
        let mut struct_ser = serializer.serialize_struct("tero.policy.v1.MetricTarget", len)?;
        if !self.r#match.is_empty() {
            struct_ser.serialize_field("match", &self.r#match)?;
        }
        if self.keep {
            struct_ser.serialize_field("keep", &self.keep)?;
        }
        struct_ser.end()
    }
}
impl<'de> serde::Deserialize<'de> for MetricTarget {
    #[allow(deprecated)]
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        const FIELDS: &[&str] = &[
            "match",
            "keep",
        ];

        #[allow(clippy::enum_variant_names)]
        enum GeneratedField {
            Match,
            Keep,
        }
        impl<'de> serde::Deserialize<'de> for GeneratedField {
            fn deserialize<D>(deserializer: D) -> std::result::Result<GeneratedField, D::Error>
            where
                D: serde::Deserializer<'de>,
            {
                struct GeneratedVisitor;

                impl<'de> serde::de::Visitor<'de> for GeneratedVisitor {
                    type Value = GeneratedField;

                    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                        write!(formatter, "expected one of: {:?}", &FIELDS)
                    }

                    #[allow(unused_variables)]
                    fn visit_str<E>(self, value: &str) -> std::result::Result<GeneratedField, E>
                    where
                        E: serde::de::Error,
                    {
                        match value {
                            "match" => Ok(GeneratedField::Match),
                            "keep" => Ok(GeneratedField::Keep),
                            _ => Err(serde::de::Error::unknown_field(value, FIELDS)),
                        }
                    }
                }
                deserializer.deserialize_identifier(GeneratedVisitor)
            }
        }
        struct GeneratedVisitor;
        impl<'de> serde::de::Visitor<'de> for GeneratedVisitor {
            type Value = MetricTarget;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("struct tero.policy.v1.MetricTarget")
            }

            fn visit_map<V>(self, mut map_: V) -> std::result::Result<MetricTarget, V::Error>
                where
                    V: serde::de::MapAccess<'de>,
            {
                let mut r#match__ = None;
                let mut keep__ = None;
                while let Some(k) = map_.next_key()? {
                    match k {
                        GeneratedField::Match => {
                            if r#match__.is_some() {
                                return Err(serde::de::Error::duplicate_field("match"));
                            }
                            r#match__ = Some(map_.next_value()?);
                        }
                        GeneratedField::Keep => {
                            if keep__.is_some() {
                                return Err(serde::de::Error::duplicate_field("keep"));
                            }
                            keep__ = Some(map_.next_value()?);
                        }
                    }
                }
                Ok(MetricTarget {
                    r#match: r#match__.unwrap_or_default(),
                    keep: keep__.unwrap_or_default(),
                })
            }
        }
        deserializer.deserialize_struct("tero.policy.v1.MetricTarget", FIELDS, GeneratedVisitor)
    }
}
impl serde::Serialize for MetricType {
    #[allow(deprecated)]
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let variant = match self {
            Self::Unspecified => "METRIC_TYPE_UNSPECIFIED",
            Self::Gauge => "METRIC_TYPE_GAUGE",
            Self::Sum => "METRIC_TYPE_SUM",
            Self::Histogram => "METRIC_TYPE_HISTOGRAM",
            Self::ExponentialHistogram => "METRIC_TYPE_EXPONENTIAL_HISTOGRAM",
            Self::Summary => "METRIC_TYPE_SUMMARY",
        };
        serializer.serialize_str(variant)
    }
}
impl<'de> serde::Deserialize<'de> for MetricType {
    #[allow(deprecated)]
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        const FIELDS: &[&str] = &[
            "METRIC_TYPE_UNSPECIFIED",
            "METRIC_TYPE_GAUGE",
            "METRIC_TYPE_SUM",
            "METRIC_TYPE_HISTOGRAM",
            "METRIC_TYPE_EXPONENTIAL_HISTOGRAM",
            "METRIC_TYPE_SUMMARY",
        ];

        struct GeneratedVisitor;

        impl<'de> serde::de::Visitor<'de> for GeneratedVisitor {
            type Value = MetricType;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(formatter, "expected one of: {:?}", &FIELDS)
            }

            fn visit_i64<E>(self, v: i64) -> std::result::Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                i32::try_from(v)
                    .ok()
                    .and_then(|x| x.try_into().ok())
                    .ok_or_else(|| {
                        serde::de::Error::invalid_value(serde::de::Unexpected::Signed(v), &self)
                    })
            }

            fn visit_u64<E>(self, v: u64) -> std::result::Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                i32::try_from(v)
                    .ok()
                    .and_then(|x| x.try_into().ok())
                    .ok_or_else(|| {
                        serde::de::Error::invalid_value(serde::de::Unexpected::Unsigned(v), &self)
                    })
            }

            fn visit_str<E>(self, value: &str) -> std::result::Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                match value {
                    "METRIC_TYPE_UNSPECIFIED" => Ok(MetricType::Unspecified),
                    "METRIC_TYPE_GAUGE" => Ok(MetricType::Gauge),
                    "METRIC_TYPE_SUM" => Ok(MetricType::Sum),
                    "METRIC_TYPE_HISTOGRAM" => Ok(MetricType::Histogram),
                    "METRIC_TYPE_EXPONENTIAL_HISTOGRAM" => Ok(MetricType::ExponentialHistogram),
                    "METRIC_TYPE_SUMMARY" => Ok(MetricType::Summary),
                    _ => Err(serde::de::Error::unknown_variant(value, FIELDS)),
                }
            }
        }
        deserializer.deserialize_any(GeneratedVisitor)
    }
}
impl serde::Serialize for Policy {
    #[allow(deprecated)]
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut len = 0;
        if !self.id.is_empty() {
            len += 1;
        }
        if !self.name.is_empty() {
            len += 1;
        }
        if !self.description.is_empty() {
            len += 1;
        }
        if self.enabled {
            len += 1;
        }
        if self.created_at_unix_nano != 0 {
            len += 1;
        }
        if self.modified_at_unix_nano != 0 {
            len += 1;
        }
        if !self.labels.is_empty() {
            len += 1;
        }
        if self.target.is_some() {
            len += 1;
        }
        let mut struct_ser = serializer.serialize_struct("tero.policy.v1.Policy", len)?;
        if !self.id.is_empty() {
            struct_ser.serialize_field("id", &self.id)?;
        }
        if !self.name.is_empty() {
            struct_ser.serialize_field("name", &self.name)?;
        }
        if !self.description.is_empty() {
            struct_ser.serialize_field("description", &self.description)?;
        }
        if self.enabled {
            struct_ser.serialize_field("enabled", &self.enabled)?;
        }
        if self.created_at_unix_nano != 0 {
            #[allow(clippy::needless_borrow)]
            #[allow(clippy::needless_borrows_for_generic_args)]
            struct_ser.serialize_field("createdAtUnixNano", ToString::to_string(&self.created_at_unix_nano).as_str())?;
        }
        if self.modified_at_unix_nano != 0 {
            #[allow(clippy::needless_borrow)]
            #[allow(clippy::needless_borrows_for_generic_args)]
            struct_ser.serialize_field("modifiedAtUnixNano", ToString::to_string(&self.modified_at_unix_nano).as_str())?;
        }
        if !self.labels.is_empty() {
            struct_ser.serialize_field("labels", &self.labels)?;
        }
        if let Some(v) = self.target.as_ref() {
            match v {
                policy::Target::Log(v) => {
                    struct_ser.serialize_field("log", v)?;
                }
                policy::Target::Metric(v) => {
                    struct_ser.serialize_field("metric", v)?;
                }
                policy::Target::Trace(v) => {
                    struct_ser.serialize_field("trace", v)?;
                }
            }
        }
        struct_ser.end()
    }
}
impl<'de> serde::Deserialize<'de> for Policy {
    #[allow(deprecated)]
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        const FIELDS: &[&str] = &[
            "id",
            "name",
            "description",
            "enabled",
            "created_at_unix_nano",
            "createdAtUnixNano",
            "modified_at_unix_nano",
            "modifiedAtUnixNano",
            "labels",
            "log",
            "metric",
            "trace",
        ];

        #[allow(clippy::enum_variant_names)]
        enum GeneratedField {
            Id,
            Name,
            Description,
            Enabled,
            CreatedAtUnixNano,
            ModifiedAtUnixNano,
            Labels,
            Log,
            Metric,
            Trace,
        }
        impl<'de> serde::Deserialize<'de> for GeneratedField {
            fn deserialize<D>(deserializer: D) -> std::result::Result<GeneratedField, D::Error>
            where
                D: serde::Deserializer<'de>,
            {
                struct GeneratedVisitor;

                impl<'de> serde::de::Visitor<'de> for GeneratedVisitor {
                    type Value = GeneratedField;

                    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                        write!(formatter, "expected one of: {:?}", &FIELDS)
                    }

                    #[allow(unused_variables)]
                    fn visit_str<E>(self, value: &str) -> std::result::Result<GeneratedField, E>
                    where
                        E: serde::de::Error,
                    {
                        match value {
                            "id" => Ok(GeneratedField::Id),
                            "name" => Ok(GeneratedField::Name),
                            "description" => Ok(GeneratedField::Description),
                            "enabled" => Ok(GeneratedField::Enabled),
                            "createdAtUnixNano" | "created_at_unix_nano" => Ok(GeneratedField::CreatedAtUnixNano),
                            "modifiedAtUnixNano" | "modified_at_unix_nano" => Ok(GeneratedField::ModifiedAtUnixNano),
                            "labels" => Ok(GeneratedField::Labels),
                            "log" => Ok(GeneratedField::Log),
                            "metric" => Ok(GeneratedField::Metric),
                            "trace" => Ok(GeneratedField::Trace),
                            _ => Err(serde::de::Error::unknown_field(value, FIELDS)),
                        }
                    }
                }
                deserializer.deserialize_identifier(GeneratedVisitor)
            }
        }
        struct GeneratedVisitor;
        impl<'de> serde::de::Visitor<'de> for GeneratedVisitor {
            type Value = Policy;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("struct tero.policy.v1.Policy")
            }

            fn visit_map<V>(self, mut map_: V) -> std::result::Result<Policy, V::Error>
                where
                    V: serde::de::MapAccess<'de>,
            {
                let mut id__ = None;
                let mut name__ = None;
                let mut description__ = None;
                let mut enabled__ = None;
                let mut created_at_unix_nano__ = None;
                let mut modified_at_unix_nano__ = None;
                let mut labels__ = None;
                let mut target__ = None;
                while let Some(k) = map_.next_key()? {
                    match k {
                        GeneratedField::Id => {
                            if id__.is_some() {
                                return Err(serde::de::Error::duplicate_field("id"));
                            }
                            id__ = Some(map_.next_value()?);
                        }
                        GeneratedField::Name => {
                            if name__.is_some() {
                                return Err(serde::de::Error::duplicate_field("name"));
                            }
                            name__ = Some(map_.next_value()?);
                        }
                        GeneratedField::Description => {
                            if description__.is_some() {
                                return Err(serde::de::Error::duplicate_field("description"));
                            }
                            description__ = Some(map_.next_value()?);
                        }
                        GeneratedField::Enabled => {
                            if enabled__.is_some() {
                                return Err(serde::de::Error::duplicate_field("enabled"));
                            }
                            enabled__ = Some(map_.next_value()?);
                        }
                        GeneratedField::CreatedAtUnixNano => {
                            if created_at_unix_nano__.is_some() {
                                return Err(serde::de::Error::duplicate_field("createdAtUnixNano"));
                            }
                            created_at_unix_nano__ = 
                                Some(map_.next_value::<::pbjson::private::NumberDeserialize<_>>()?.0)
                            ;
                        }
                        GeneratedField::ModifiedAtUnixNano => {
                            if modified_at_unix_nano__.is_some() {
                                return Err(serde::de::Error::duplicate_field("modifiedAtUnixNano"));
                            }
                            modified_at_unix_nano__ = 
                                Some(map_.next_value::<::pbjson::private::NumberDeserialize<_>>()?.0)
                            ;
                        }
                        GeneratedField::Labels => {
                            if labels__.is_some() {
                                return Err(serde::de::Error::duplicate_field("labels"));
                            }
                            labels__ = Some(map_.next_value()?);
                        }
                        GeneratedField::Log => {
                            if target__.is_some() {
                                return Err(serde::de::Error::duplicate_field("log"));
                            }
                            target__ = map_.next_value::<::std::option::Option<_>>()?.map(policy::Target::Log)
;
                        }
                        GeneratedField::Metric => {
                            if target__.is_some() {
                                return Err(serde::de::Error::duplicate_field("metric"));
                            }
                            target__ = map_.next_value::<::std::option::Option<_>>()?.map(policy::Target::Metric)
;
                        }
                        GeneratedField::Trace => {
                            if target__.is_some() {
                                return Err(serde::de::Error::duplicate_field("trace"));
                            }
                            target__ = map_.next_value::<::std::option::Option<_>>()?.map(policy::Target::Trace)
;
                        }
                    }
                }
                Ok(Policy {
                    id: id__.unwrap_or_default(),
                    name: name__.unwrap_or_default(),
                    description: description__.unwrap_or_default(),
                    enabled: enabled__.unwrap_or_default(),
                    created_at_unix_nano: created_at_unix_nano__.unwrap_or_default(),
                    modified_at_unix_nano: modified_at_unix_nano__.unwrap_or_default(),
                    labels: labels__.unwrap_or_default(),
                    target: target__,
                })
            }
        }
        deserializer.deserialize_struct("tero.policy.v1.Policy", FIELDS, GeneratedVisitor)
    }
}
impl serde::Serialize for PolicyStage {
    #[allow(deprecated)]
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let variant = match self {
            Self::Unspecified => "POLICY_STAGE_UNSPECIFIED",
            Self::LogFilter => "POLICY_STAGE_LOG_FILTER",
            Self::LogTransform => "POLICY_STAGE_LOG_TRANSFORM",
            Self::MetricFilter => "POLICY_STAGE_METRIC_FILTER",
            Self::TraceSampling => "POLICY_STAGE_TRACE_SAMPLING",
        };
        serializer.serialize_str(variant)
    }
}
impl<'de> serde::Deserialize<'de> for PolicyStage {
    #[allow(deprecated)]
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        const FIELDS: &[&str] = &[
            "POLICY_STAGE_UNSPECIFIED",
            "POLICY_STAGE_LOG_FILTER",
            "POLICY_STAGE_LOG_TRANSFORM",
            "POLICY_STAGE_METRIC_FILTER",
            "POLICY_STAGE_TRACE_SAMPLING",
        ];

        struct GeneratedVisitor;

        impl<'de> serde::de::Visitor<'de> for GeneratedVisitor {
            type Value = PolicyStage;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(formatter, "expected one of: {:?}", &FIELDS)
            }

            fn visit_i64<E>(self, v: i64) -> std::result::Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                i32::try_from(v)
                    .ok()
                    .and_then(|x| x.try_into().ok())
                    .ok_or_else(|| {
                        serde::de::Error::invalid_value(serde::de::Unexpected::Signed(v), &self)
                    })
            }

            fn visit_u64<E>(self, v: u64) -> std::result::Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                i32::try_from(v)
                    .ok()
                    .and_then(|x| x.try_into().ok())
                    .ok_or_else(|| {
                        serde::de::Error::invalid_value(serde::de::Unexpected::Unsigned(v), &self)
                    })
            }

            fn visit_str<E>(self, value: &str) -> std::result::Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                match value {
                    "POLICY_STAGE_UNSPECIFIED" => Ok(PolicyStage::Unspecified),
                    "POLICY_STAGE_LOG_FILTER" => Ok(PolicyStage::LogFilter),
                    "POLICY_STAGE_LOG_TRANSFORM" => Ok(PolicyStage::LogTransform),
                    "POLICY_STAGE_METRIC_FILTER" => Ok(PolicyStage::MetricFilter),
                    "POLICY_STAGE_TRACE_SAMPLING" => Ok(PolicyStage::TraceSampling),
                    _ => Err(serde::de::Error::unknown_variant(value, FIELDS)),
                }
            }
        }
        deserializer.deserialize_any(GeneratedVisitor)
    }
}
impl serde::Serialize for PolicySyncStatus {
    #[allow(deprecated)]
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut len = 0;
        if !self.id.is_empty() {
            len += 1;
        }
        if self.match_hits != 0 {
            len += 1;
        }
        if self.match_misses != 0 {
            len += 1;
        }
        if !self.errors.is_empty() {
            len += 1;
        }
        if self.remove.is_some() {
            len += 1;
        }
        if self.redact.is_some() {
            len += 1;
        }
        if self.rename.is_some() {
            len += 1;
        }
        if self.add.is_some() {
            len += 1;
        }
        let mut struct_ser = serializer.serialize_struct("tero.policy.v1.PolicySyncStatus", len)?;
        if !self.id.is_empty() {
            struct_ser.serialize_field("id", &self.id)?;
        }
        if self.match_hits != 0 {
            #[allow(clippy::needless_borrow)]
            #[allow(clippy::needless_borrows_for_generic_args)]
            struct_ser.serialize_field("matchHits", ToString::to_string(&self.match_hits).as_str())?;
        }
        if self.match_misses != 0 {
            #[allow(clippy::needless_borrow)]
            #[allow(clippy::needless_borrows_for_generic_args)]
            struct_ser.serialize_field("matchMisses", ToString::to_string(&self.match_misses).as_str())?;
        }
        if !self.errors.is_empty() {
            struct_ser.serialize_field("errors", &self.errors)?;
        }
        if let Some(v) = self.remove.as_ref() {
            struct_ser.serialize_field("remove", v)?;
        }
        if let Some(v) = self.redact.as_ref() {
            struct_ser.serialize_field("redact", v)?;
        }
        if let Some(v) = self.rename.as_ref() {
            struct_ser.serialize_field("rename", v)?;
        }
        if let Some(v) = self.add.as_ref() {
            struct_ser.serialize_field("add", v)?;
        }
        struct_ser.end()
    }
}
impl<'de> serde::Deserialize<'de> for PolicySyncStatus {
    #[allow(deprecated)]
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        const FIELDS: &[&str] = &[
            "id",
            "match_hits",
            "matchHits",
            "match_misses",
            "matchMisses",
            "errors",
            "remove",
            "redact",
            "rename",
            "add",
        ];

        #[allow(clippy::enum_variant_names)]
        enum GeneratedField {
            Id,
            MatchHits,
            MatchMisses,
            Errors,
            Remove,
            Redact,
            Rename,
            Add,
        }
        impl<'de> serde::Deserialize<'de> for GeneratedField {
            fn deserialize<D>(deserializer: D) -> std::result::Result<GeneratedField, D::Error>
            where
                D: serde::Deserializer<'de>,
            {
                struct GeneratedVisitor;

                impl<'de> serde::de::Visitor<'de> for GeneratedVisitor {
                    type Value = GeneratedField;

                    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                        write!(formatter, "expected one of: {:?}", &FIELDS)
                    }

                    #[allow(unused_variables)]
                    fn visit_str<E>(self, value: &str) -> std::result::Result<GeneratedField, E>
                    where
                        E: serde::de::Error,
                    {
                        match value {
                            "id" => Ok(GeneratedField::Id),
                            "matchHits" | "match_hits" => Ok(GeneratedField::MatchHits),
                            "matchMisses" | "match_misses" => Ok(GeneratedField::MatchMisses),
                            "errors" => Ok(GeneratedField::Errors),
                            "remove" => Ok(GeneratedField::Remove),
                            "redact" => Ok(GeneratedField::Redact),
                            "rename" => Ok(GeneratedField::Rename),
                            "add" => Ok(GeneratedField::Add),
                            _ => Err(serde::de::Error::unknown_field(value, FIELDS)),
                        }
                    }
                }
                deserializer.deserialize_identifier(GeneratedVisitor)
            }
        }
        struct GeneratedVisitor;
        impl<'de> serde::de::Visitor<'de> for GeneratedVisitor {
            type Value = PolicySyncStatus;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("struct tero.policy.v1.PolicySyncStatus")
            }

            fn visit_map<V>(self, mut map_: V) -> std::result::Result<PolicySyncStatus, V::Error>
                where
                    V: serde::de::MapAccess<'de>,
            {
                let mut id__ = None;
                let mut match_hits__ = None;
                let mut match_misses__ = None;
                let mut errors__ = None;
                let mut remove__ = None;
                let mut redact__ = None;
                let mut rename__ = None;
                let mut add__ = None;
                while let Some(k) = map_.next_key()? {
                    match k {
                        GeneratedField::Id => {
                            if id__.is_some() {
                                return Err(serde::de::Error::duplicate_field("id"));
                            }
                            id__ = Some(map_.next_value()?);
                        }
                        GeneratedField::MatchHits => {
                            if match_hits__.is_some() {
                                return Err(serde::de::Error::duplicate_field("matchHits"));
                            }
                            match_hits__ = 
                                Some(map_.next_value::<::pbjson::private::NumberDeserialize<_>>()?.0)
                            ;
                        }
                        GeneratedField::MatchMisses => {
                            if match_misses__.is_some() {
                                return Err(serde::de::Error::duplicate_field("matchMisses"));
                            }
                            match_misses__ = 
                                Some(map_.next_value::<::pbjson::private::NumberDeserialize<_>>()?.0)
                            ;
                        }
                        GeneratedField::Errors => {
                            if errors__.is_some() {
                                return Err(serde::de::Error::duplicate_field("errors"));
                            }
                            errors__ = Some(map_.next_value()?);
                        }
                        GeneratedField::Remove => {
                            if remove__.is_some() {
                                return Err(serde::de::Error::duplicate_field("remove"));
                            }
                            remove__ = map_.next_value()?;
                        }
                        GeneratedField::Redact => {
                            if redact__.is_some() {
                                return Err(serde::de::Error::duplicate_field("redact"));
                            }
                            redact__ = map_.next_value()?;
                        }
                        GeneratedField::Rename => {
                            if rename__.is_some() {
                                return Err(serde::de::Error::duplicate_field("rename"));
                            }
                            rename__ = map_.next_value()?;
                        }
                        GeneratedField::Add => {
                            if add__.is_some() {
                                return Err(serde::de::Error::duplicate_field("add"));
                            }
                            add__ = map_.next_value()?;
                        }
                    }
                }
                Ok(PolicySyncStatus {
                    id: id__.unwrap_or_default(),
                    match_hits: match_hits__.unwrap_or_default(),
                    match_misses: match_misses__.unwrap_or_default(),
                    errors: errors__.unwrap_or_default(),
                    remove: remove__,
                    redact: redact__,
                    rename: rename__,
                    add: add__,
                })
            }
        }
        deserializer.deserialize_struct("tero.policy.v1.PolicySyncStatus", FIELDS, GeneratedVisitor)
    }
}
impl serde::Serialize for SamplingMode {
    #[allow(deprecated)]
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let variant = match self {
            Self::Unspecified => "SAMPLING_MODE_UNSPECIFIED",
            Self::HashSeed => "SAMPLING_MODE_HASH_SEED",
            Self::Proportional => "SAMPLING_MODE_PROPORTIONAL",
            Self::Equalizing => "SAMPLING_MODE_EQUALIZING",
        };
        serializer.serialize_str(variant)
    }
}
impl<'de> serde::Deserialize<'de> for SamplingMode {
    #[allow(deprecated)]
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        const FIELDS: &[&str] = &[
            "SAMPLING_MODE_UNSPECIFIED",
            "SAMPLING_MODE_HASH_SEED",
            "SAMPLING_MODE_PROPORTIONAL",
            "SAMPLING_MODE_EQUALIZING",
        ];

        struct GeneratedVisitor;

        impl<'de> serde::de::Visitor<'de> for GeneratedVisitor {
            type Value = SamplingMode;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(formatter, "expected one of: {:?}", &FIELDS)
            }

            fn visit_i64<E>(self, v: i64) -> std::result::Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                i32::try_from(v)
                    .ok()
                    .and_then(|x| x.try_into().ok())
                    .ok_or_else(|| {
                        serde::de::Error::invalid_value(serde::de::Unexpected::Signed(v), &self)
                    })
            }

            fn visit_u64<E>(self, v: u64) -> std::result::Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                i32::try_from(v)
                    .ok()
                    .and_then(|x| x.try_into().ok())
                    .ok_or_else(|| {
                        serde::de::Error::invalid_value(serde::de::Unexpected::Unsigned(v), &self)
                    })
            }

            fn visit_str<E>(self, value: &str) -> std::result::Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                match value {
                    "SAMPLING_MODE_UNSPECIFIED" => Ok(SamplingMode::Unspecified),
                    "SAMPLING_MODE_HASH_SEED" => Ok(SamplingMode::HashSeed),
                    "SAMPLING_MODE_PROPORTIONAL" => Ok(SamplingMode::Proportional),
                    "SAMPLING_MODE_EQUALIZING" => Ok(SamplingMode::Equalizing),
                    _ => Err(serde::de::Error::unknown_variant(value, FIELDS)),
                }
            }
        }
        deserializer.deserialize_any(GeneratedVisitor)
    }
}
impl serde::Serialize for SpanKind {
    #[allow(deprecated)]
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let variant = match self {
            Self::Unspecified => "SPAN_KIND_UNSPECIFIED",
            Self::Internal => "SPAN_KIND_INTERNAL",
            Self::Server => "SPAN_KIND_SERVER",
            Self::Client => "SPAN_KIND_CLIENT",
            Self::Producer => "SPAN_KIND_PRODUCER",
            Self::Consumer => "SPAN_KIND_CONSUMER",
        };
        serializer.serialize_str(variant)
    }
}
impl<'de> serde::Deserialize<'de> for SpanKind {
    #[allow(deprecated)]
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        const FIELDS: &[&str] = &[
            "SPAN_KIND_UNSPECIFIED",
            "SPAN_KIND_INTERNAL",
            "SPAN_KIND_SERVER",
            "SPAN_KIND_CLIENT",
            "SPAN_KIND_PRODUCER",
            "SPAN_KIND_CONSUMER",
        ];

        struct GeneratedVisitor;

        impl<'de> serde::de::Visitor<'de> for GeneratedVisitor {
            type Value = SpanKind;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(formatter, "expected one of: {:?}", &FIELDS)
            }

            fn visit_i64<E>(self, v: i64) -> std::result::Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                i32::try_from(v)
                    .ok()
                    .and_then(|x| x.try_into().ok())
                    .ok_or_else(|| {
                        serde::de::Error::invalid_value(serde::de::Unexpected::Signed(v), &self)
                    })
            }

            fn visit_u64<E>(self, v: u64) -> std::result::Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                i32::try_from(v)
                    .ok()
                    .and_then(|x| x.try_into().ok())
                    .ok_or_else(|| {
                        serde::de::Error::invalid_value(serde::de::Unexpected::Unsigned(v), &self)
                    })
            }

            fn visit_str<E>(self, value: &str) -> std::result::Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                match value {
                    "SPAN_KIND_UNSPECIFIED" => Ok(SpanKind::Unspecified),
                    "SPAN_KIND_INTERNAL" => Ok(SpanKind::Internal),
                    "SPAN_KIND_SERVER" => Ok(SpanKind::Server),
                    "SPAN_KIND_CLIENT" => Ok(SpanKind::Client),
                    "SPAN_KIND_PRODUCER" => Ok(SpanKind::Producer),
                    "SPAN_KIND_CONSUMER" => Ok(SpanKind::Consumer),
                    _ => Err(serde::de::Error::unknown_variant(value, FIELDS)),
                }
            }
        }
        deserializer.deserialize_any(GeneratedVisitor)
    }
}
impl serde::Serialize for SpanStatusCode {
    #[allow(deprecated)]
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let variant = match self {
            Self::Unspecified => "SPAN_STATUS_CODE_UNSPECIFIED",
            Self::Ok => "SPAN_STATUS_CODE_OK",
            Self::Error => "SPAN_STATUS_CODE_ERROR",
        };
        serializer.serialize_str(variant)
    }
}
impl<'de> serde::Deserialize<'de> for SpanStatusCode {
    #[allow(deprecated)]
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        const FIELDS: &[&str] = &[
            "SPAN_STATUS_CODE_UNSPECIFIED",
            "SPAN_STATUS_CODE_OK",
            "SPAN_STATUS_CODE_ERROR",
        ];

        struct GeneratedVisitor;

        impl<'de> serde::de::Visitor<'de> for GeneratedVisitor {
            type Value = SpanStatusCode;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(formatter, "expected one of: {:?}", &FIELDS)
            }

            fn visit_i64<E>(self, v: i64) -> std::result::Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                i32::try_from(v)
                    .ok()
                    .and_then(|x| x.try_into().ok())
                    .ok_or_else(|| {
                        serde::de::Error::invalid_value(serde::de::Unexpected::Signed(v), &self)
                    })
            }

            fn visit_u64<E>(self, v: u64) -> std::result::Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                i32::try_from(v)
                    .ok()
                    .and_then(|x| x.try_into().ok())
                    .ok_or_else(|| {
                        serde::de::Error::invalid_value(serde::de::Unexpected::Unsigned(v), &self)
                    })
            }

            fn visit_str<E>(self, value: &str) -> std::result::Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                match value {
                    "SPAN_STATUS_CODE_UNSPECIFIED" => Ok(SpanStatusCode::Unspecified),
                    "SPAN_STATUS_CODE_OK" => Ok(SpanStatusCode::Ok),
                    "SPAN_STATUS_CODE_ERROR" => Ok(SpanStatusCode::Error),
                    _ => Err(serde::de::Error::unknown_variant(value, FIELDS)),
                }
            }
        }
        deserializer.deserialize_any(GeneratedVisitor)
    }
}
impl serde::Serialize for SyncRequest {
    #[allow(deprecated)]
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut len = 0;
        if self.client_metadata.is_some() {
            len += 1;
        }
        if self.full_sync {
            len += 1;
        }
        if self.last_sync_timestamp_unix_nano != 0 {
            len += 1;
        }
        if !self.last_successful_hash.is_empty() {
            len += 1;
        }
        if !self.policy_statuses.is_empty() {
            len += 1;
        }
        let mut struct_ser = serializer.serialize_struct("tero.policy.v1.SyncRequest", len)?;
        if let Some(v) = self.client_metadata.as_ref() {
            struct_ser.serialize_field("clientMetadata", v)?;
        }
        if self.full_sync {
            struct_ser.serialize_field("fullSync", &self.full_sync)?;
        }
        if self.last_sync_timestamp_unix_nano != 0 {
            #[allow(clippy::needless_borrow)]
            #[allow(clippy::needless_borrows_for_generic_args)]
            struct_ser.serialize_field("lastSyncTimestampUnixNano", ToString::to_string(&self.last_sync_timestamp_unix_nano).as_str())?;
        }
        if !self.last_successful_hash.is_empty() {
            struct_ser.serialize_field("lastSuccessfulHash", &self.last_successful_hash)?;
        }
        if !self.policy_statuses.is_empty() {
            struct_ser.serialize_field("policyStatuses", &self.policy_statuses)?;
        }
        struct_ser.end()
    }
}
impl<'de> serde::Deserialize<'de> for SyncRequest {
    #[allow(deprecated)]
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        const FIELDS: &[&str] = &[
            "client_metadata",
            "clientMetadata",
            "full_sync",
            "fullSync",
            "last_sync_timestamp_unix_nano",
            "lastSyncTimestampUnixNano",
            "last_successful_hash",
            "lastSuccessfulHash",
            "policy_statuses",
            "policyStatuses",
        ];

        #[allow(clippy::enum_variant_names)]
        enum GeneratedField {
            ClientMetadata,
            FullSync,
            LastSyncTimestampUnixNano,
            LastSuccessfulHash,
            PolicyStatuses,
        }
        impl<'de> serde::Deserialize<'de> for GeneratedField {
            fn deserialize<D>(deserializer: D) -> std::result::Result<GeneratedField, D::Error>
            where
                D: serde::Deserializer<'de>,
            {
                struct GeneratedVisitor;

                impl<'de> serde::de::Visitor<'de> for GeneratedVisitor {
                    type Value = GeneratedField;

                    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                        write!(formatter, "expected one of: {:?}", &FIELDS)
                    }

                    #[allow(unused_variables)]
                    fn visit_str<E>(self, value: &str) -> std::result::Result<GeneratedField, E>
                    where
                        E: serde::de::Error,
                    {
                        match value {
                            "clientMetadata" | "client_metadata" => Ok(GeneratedField::ClientMetadata),
                            "fullSync" | "full_sync" => Ok(GeneratedField::FullSync),
                            "lastSyncTimestampUnixNano" | "last_sync_timestamp_unix_nano" => Ok(GeneratedField::LastSyncTimestampUnixNano),
                            "lastSuccessfulHash" | "last_successful_hash" => Ok(GeneratedField::LastSuccessfulHash),
                            "policyStatuses" | "policy_statuses" => Ok(GeneratedField::PolicyStatuses),
                            _ => Err(serde::de::Error::unknown_field(value, FIELDS)),
                        }
                    }
                }
                deserializer.deserialize_identifier(GeneratedVisitor)
            }
        }
        struct GeneratedVisitor;
        impl<'de> serde::de::Visitor<'de> for GeneratedVisitor {
            type Value = SyncRequest;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("struct tero.policy.v1.SyncRequest")
            }

            fn visit_map<V>(self, mut map_: V) -> std::result::Result<SyncRequest, V::Error>
                where
                    V: serde::de::MapAccess<'de>,
            {
                let mut client_metadata__ = None;
                let mut full_sync__ = None;
                let mut last_sync_timestamp_unix_nano__ = None;
                let mut last_successful_hash__ = None;
                let mut policy_statuses__ = None;
                while let Some(k) = map_.next_key()? {
                    match k {
                        GeneratedField::ClientMetadata => {
                            if client_metadata__.is_some() {
                                return Err(serde::de::Error::duplicate_field("clientMetadata"));
                            }
                            client_metadata__ = map_.next_value()?;
                        }
                        GeneratedField::FullSync => {
                            if full_sync__.is_some() {
                                return Err(serde::de::Error::duplicate_field("fullSync"));
                            }
                            full_sync__ = Some(map_.next_value()?);
                        }
                        GeneratedField::LastSyncTimestampUnixNano => {
                            if last_sync_timestamp_unix_nano__.is_some() {
                                return Err(serde::de::Error::duplicate_field("lastSyncTimestampUnixNano"));
                            }
                            last_sync_timestamp_unix_nano__ = 
                                Some(map_.next_value::<::pbjson::private::NumberDeserialize<_>>()?.0)
                            ;
                        }
                        GeneratedField::LastSuccessfulHash => {
                            if last_successful_hash__.is_some() {
                                return Err(serde::de::Error::duplicate_field("lastSuccessfulHash"));
                            }
                            last_successful_hash__ = Some(map_.next_value()?);
                        }
                        GeneratedField::PolicyStatuses => {
                            if policy_statuses__.is_some() {
                                return Err(serde::de::Error::duplicate_field("policyStatuses"));
                            }
                            policy_statuses__ = Some(map_.next_value()?);
                        }
                    }
                }
                Ok(SyncRequest {
                    client_metadata: client_metadata__,
                    full_sync: full_sync__.unwrap_or_default(),
                    last_sync_timestamp_unix_nano: last_sync_timestamp_unix_nano__.unwrap_or_default(),
                    last_successful_hash: last_successful_hash__.unwrap_or_default(),
                    policy_statuses: policy_statuses__.unwrap_or_default(),
                })
            }
        }
        deserializer.deserialize_struct("tero.policy.v1.SyncRequest", FIELDS, GeneratedVisitor)
    }
}
impl serde::Serialize for SyncResponse {
    #[allow(deprecated)]
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut len = 0;
        if !self.policies.is_empty() {
            len += 1;
        }
        if !self.hash.is_empty() {
            len += 1;
        }
        if self.sync_timestamp_unix_nano != 0 {
            len += 1;
        }
        if self.recommended_sync_interval_seconds != 0 {
            len += 1;
        }
        if self.sync_type != 0 {
            len += 1;
        }
        if !self.error_message.is_empty() {
            len += 1;
        }
        let mut struct_ser = serializer.serialize_struct("tero.policy.v1.SyncResponse", len)?;
        if !self.policies.is_empty() {
            struct_ser.serialize_field("policies", &self.policies)?;
        }
        if !self.hash.is_empty() {
            struct_ser.serialize_field("hash", &self.hash)?;
        }
        if self.sync_timestamp_unix_nano != 0 {
            #[allow(clippy::needless_borrow)]
            #[allow(clippy::needless_borrows_for_generic_args)]
            struct_ser.serialize_field("syncTimestampUnixNano", ToString::to_string(&self.sync_timestamp_unix_nano).as_str())?;
        }
        if self.recommended_sync_interval_seconds != 0 {
            struct_ser.serialize_field("recommendedSyncIntervalSeconds", &self.recommended_sync_interval_seconds)?;
        }
        if self.sync_type != 0 {
            let v = SyncType::try_from(self.sync_type)
                .map_err(|_| serde::ser::Error::custom(format!("Invalid variant {}", self.sync_type)))?;
            struct_ser.serialize_field("syncType", &v)?;
        }
        if !self.error_message.is_empty() {
            struct_ser.serialize_field("errorMessage", &self.error_message)?;
        }
        struct_ser.end()
    }
}
impl<'de> serde::Deserialize<'de> for SyncResponse {
    #[allow(deprecated)]
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        const FIELDS: &[&str] = &[
            "policies",
            "hash",
            "sync_timestamp_unix_nano",
            "syncTimestampUnixNano",
            "recommended_sync_interval_seconds",
            "recommendedSyncIntervalSeconds",
            "sync_type",
            "syncType",
            "error_message",
            "errorMessage",
        ];

        #[allow(clippy::enum_variant_names)]
        enum GeneratedField {
            Policies,
            Hash,
            SyncTimestampUnixNano,
            RecommendedSyncIntervalSeconds,
            SyncType,
            ErrorMessage,
        }
        impl<'de> serde::Deserialize<'de> for GeneratedField {
            fn deserialize<D>(deserializer: D) -> std::result::Result<GeneratedField, D::Error>
            where
                D: serde::Deserializer<'de>,
            {
                struct GeneratedVisitor;

                impl<'de> serde::de::Visitor<'de> for GeneratedVisitor {
                    type Value = GeneratedField;

                    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                        write!(formatter, "expected one of: {:?}", &FIELDS)
                    }

                    #[allow(unused_variables)]
                    fn visit_str<E>(self, value: &str) -> std::result::Result<GeneratedField, E>
                    where
                        E: serde::de::Error,
                    {
                        match value {
                            "policies" => Ok(GeneratedField::Policies),
                            "hash" => Ok(GeneratedField::Hash),
                            "syncTimestampUnixNano" | "sync_timestamp_unix_nano" => Ok(GeneratedField::SyncTimestampUnixNano),
                            "recommendedSyncIntervalSeconds" | "recommended_sync_interval_seconds" => Ok(GeneratedField::RecommendedSyncIntervalSeconds),
                            "syncType" | "sync_type" => Ok(GeneratedField::SyncType),
                            "errorMessage" | "error_message" => Ok(GeneratedField::ErrorMessage),
                            _ => Err(serde::de::Error::unknown_field(value, FIELDS)),
                        }
                    }
                }
                deserializer.deserialize_identifier(GeneratedVisitor)
            }
        }
        struct GeneratedVisitor;
        impl<'de> serde::de::Visitor<'de> for GeneratedVisitor {
            type Value = SyncResponse;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("struct tero.policy.v1.SyncResponse")
            }

            fn visit_map<V>(self, mut map_: V) -> std::result::Result<SyncResponse, V::Error>
                where
                    V: serde::de::MapAccess<'de>,
            {
                let mut policies__ = None;
                let mut hash__ = None;
                let mut sync_timestamp_unix_nano__ = None;
                let mut recommended_sync_interval_seconds__ = None;
                let mut sync_type__ = None;
                let mut error_message__ = None;
                while let Some(k) = map_.next_key()? {
                    match k {
                        GeneratedField::Policies => {
                            if policies__.is_some() {
                                return Err(serde::de::Error::duplicate_field("policies"));
                            }
                            policies__ = Some(map_.next_value()?);
                        }
                        GeneratedField::Hash => {
                            if hash__.is_some() {
                                return Err(serde::de::Error::duplicate_field("hash"));
                            }
                            hash__ = Some(map_.next_value()?);
                        }
                        GeneratedField::SyncTimestampUnixNano => {
                            if sync_timestamp_unix_nano__.is_some() {
                                return Err(serde::de::Error::duplicate_field("syncTimestampUnixNano"));
                            }
                            sync_timestamp_unix_nano__ = 
                                Some(map_.next_value::<::pbjson::private::NumberDeserialize<_>>()?.0)
                            ;
                        }
                        GeneratedField::RecommendedSyncIntervalSeconds => {
                            if recommended_sync_interval_seconds__.is_some() {
                                return Err(serde::de::Error::duplicate_field("recommendedSyncIntervalSeconds"));
                            }
                            recommended_sync_interval_seconds__ = 
                                Some(map_.next_value::<::pbjson::private::NumberDeserialize<_>>()?.0)
                            ;
                        }
                        GeneratedField::SyncType => {
                            if sync_type__.is_some() {
                                return Err(serde::de::Error::duplicate_field("syncType"));
                            }
                            sync_type__ = Some(map_.next_value::<SyncType>()? as i32);
                        }
                        GeneratedField::ErrorMessage => {
                            if error_message__.is_some() {
                                return Err(serde::de::Error::duplicate_field("errorMessage"));
                            }
                            error_message__ = Some(map_.next_value()?);
                        }
                    }
                }
                Ok(SyncResponse {
                    policies: policies__.unwrap_or_default(),
                    hash: hash__.unwrap_or_default(),
                    sync_timestamp_unix_nano: sync_timestamp_unix_nano__.unwrap_or_default(),
                    recommended_sync_interval_seconds: recommended_sync_interval_seconds__.unwrap_or_default(),
                    sync_type: sync_type__.unwrap_or_default(),
                    error_message: error_message__.unwrap_or_default(),
                })
            }
        }
        deserializer.deserialize_struct("tero.policy.v1.SyncResponse", FIELDS, GeneratedVisitor)
    }
}
impl serde::Serialize for SyncType {
    #[allow(deprecated)]
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let variant = match self {
            Self::Unspecified => "SYNC_TYPE_UNSPECIFIED",
            Self::Full => "SYNC_TYPE_FULL",
        };
        serializer.serialize_str(variant)
    }
}
impl<'de> serde::Deserialize<'de> for SyncType {
    #[allow(deprecated)]
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        const FIELDS: &[&str] = &[
            "SYNC_TYPE_UNSPECIFIED",
            "SYNC_TYPE_FULL",
        ];

        struct GeneratedVisitor;

        impl<'de> serde::de::Visitor<'de> for GeneratedVisitor {
            type Value = SyncType;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(formatter, "expected one of: {:?}", &FIELDS)
            }

            fn visit_i64<E>(self, v: i64) -> std::result::Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                i32::try_from(v)
                    .ok()
                    .and_then(|x| x.try_into().ok())
                    .ok_or_else(|| {
                        serde::de::Error::invalid_value(serde::de::Unexpected::Signed(v), &self)
                    })
            }

            fn visit_u64<E>(self, v: u64) -> std::result::Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                i32::try_from(v)
                    .ok()
                    .and_then(|x| x.try_into().ok())
                    .ok_or_else(|| {
                        serde::de::Error::invalid_value(serde::de::Unexpected::Unsigned(v), &self)
                    })
            }

            fn visit_str<E>(self, value: &str) -> std::result::Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                match value {
                    "SYNC_TYPE_UNSPECIFIED" => Ok(SyncType::Unspecified),
                    "SYNC_TYPE_FULL" => Ok(SyncType::Full),
                    _ => Err(serde::de::Error::unknown_variant(value, FIELDS)),
                }
            }
        }
        deserializer.deserialize_any(GeneratedVisitor)
    }
}
impl serde::Serialize for TraceField {
    #[allow(deprecated)]
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let variant = match self {
            Self::Unspecified => "TRACE_FIELD_UNSPECIFIED",
            Self::Name => "TRACE_FIELD_NAME",
            Self::TraceId => "TRACE_FIELD_TRACE_ID",
            Self::SpanId => "TRACE_FIELD_SPAN_ID",
            Self::ParentSpanId => "TRACE_FIELD_PARENT_SPAN_ID",
            Self::TraceState => "TRACE_FIELD_TRACE_STATE",
            Self::ResourceSchemaUrl => "TRACE_FIELD_RESOURCE_SCHEMA_URL",
            Self::ScopeSchemaUrl => "TRACE_FIELD_SCOPE_SCHEMA_URL",
            Self::ScopeName => "TRACE_FIELD_SCOPE_NAME",
            Self::ScopeVersion => "TRACE_FIELD_SCOPE_VERSION",
        };
        serializer.serialize_str(variant)
    }
}
impl<'de> serde::Deserialize<'de> for TraceField {
    #[allow(deprecated)]
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        const FIELDS: &[&str] = &[
            "TRACE_FIELD_UNSPECIFIED",
            "TRACE_FIELD_NAME",
            "TRACE_FIELD_TRACE_ID",
            "TRACE_FIELD_SPAN_ID",
            "TRACE_FIELD_PARENT_SPAN_ID",
            "TRACE_FIELD_TRACE_STATE",
            "TRACE_FIELD_RESOURCE_SCHEMA_URL",
            "TRACE_FIELD_SCOPE_SCHEMA_URL",
            "TRACE_FIELD_SCOPE_NAME",
            "TRACE_FIELD_SCOPE_VERSION",
        ];

        struct GeneratedVisitor;

        impl<'de> serde::de::Visitor<'de> for GeneratedVisitor {
            type Value = TraceField;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(formatter, "expected one of: {:?}", &FIELDS)
            }

            fn visit_i64<E>(self, v: i64) -> std::result::Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                i32::try_from(v)
                    .ok()
                    .and_then(|x| x.try_into().ok())
                    .ok_or_else(|| {
                        serde::de::Error::invalid_value(serde::de::Unexpected::Signed(v), &self)
                    })
            }

            fn visit_u64<E>(self, v: u64) -> std::result::Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                i32::try_from(v)
                    .ok()
                    .and_then(|x| x.try_into().ok())
                    .ok_or_else(|| {
                        serde::de::Error::invalid_value(serde::de::Unexpected::Unsigned(v), &self)
                    })
            }

            fn visit_str<E>(self, value: &str) -> std::result::Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                match value {
                    "TRACE_FIELD_UNSPECIFIED" => Ok(TraceField::Unspecified),
                    "TRACE_FIELD_NAME" => Ok(TraceField::Name),
                    "TRACE_FIELD_TRACE_ID" => Ok(TraceField::TraceId),
                    "TRACE_FIELD_SPAN_ID" => Ok(TraceField::SpanId),
                    "TRACE_FIELD_PARENT_SPAN_ID" => Ok(TraceField::ParentSpanId),
                    "TRACE_FIELD_TRACE_STATE" => Ok(TraceField::TraceState),
                    "TRACE_FIELD_RESOURCE_SCHEMA_URL" => Ok(TraceField::ResourceSchemaUrl),
                    "TRACE_FIELD_SCOPE_SCHEMA_URL" => Ok(TraceField::ScopeSchemaUrl),
                    "TRACE_FIELD_SCOPE_NAME" => Ok(TraceField::ScopeName),
                    "TRACE_FIELD_SCOPE_VERSION" => Ok(TraceField::ScopeVersion),
                    _ => Err(serde::de::Error::unknown_variant(value, FIELDS)),
                }
            }
        }
        deserializer.deserialize_any(GeneratedVisitor)
    }
}
impl serde::Serialize for TraceMatcher {
    #[allow(deprecated)]
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut len = 0;
        if self.negate {
            len += 1;
        }
        if self.case_insensitive {
            len += 1;
        }
        if self.field.is_some() {
            len += 1;
        }
        if self.r#match.is_some() {
            len += 1;
        }
        let mut struct_ser = serializer.serialize_struct("tero.policy.v1.TraceMatcher", len)?;
        if self.negate {
            struct_ser.serialize_field("negate", &self.negate)?;
        }
        if self.case_insensitive {
            struct_ser.serialize_field("caseInsensitive", &self.case_insensitive)?;
        }
        if let Some(v) = self.field.as_ref() {
            match v {
                trace_matcher::Field::TraceField(v) => {
                    let v = TraceField::try_from(*v)
                        .map_err(|_| serde::ser::Error::custom(format!("Invalid variant {}", *v)))?;
                    struct_ser.serialize_field("traceField", &v)?;
                }
                trace_matcher::Field::SpanAttribute(v) => {
                    struct_ser.serialize_field("spanAttribute", v)?;
                }
                trace_matcher::Field::ResourceAttribute(v) => {
                    struct_ser.serialize_field("resourceAttribute", v)?;
                }
                trace_matcher::Field::ScopeAttribute(v) => {
                    struct_ser.serialize_field("scopeAttribute", v)?;
                }
                trace_matcher::Field::SpanKind(v) => {
                    let v = SpanKind::try_from(*v)
                        .map_err(|_| serde::ser::Error::custom(format!("Invalid variant {}", *v)))?;
                    struct_ser.serialize_field("spanKind", &v)?;
                }
                trace_matcher::Field::SpanStatus(v) => {
                    let v = SpanStatusCode::try_from(*v)
                        .map_err(|_| serde::ser::Error::custom(format!("Invalid variant {}", *v)))?;
                    struct_ser.serialize_field("spanStatus", &v)?;
                }
                trace_matcher::Field::EventName(v) => {
                    struct_ser.serialize_field("eventName", v)?;
                }
                trace_matcher::Field::EventAttribute(v) => {
                    struct_ser.serialize_field("eventAttribute", v)?;
                }
                trace_matcher::Field::LinkTraceId(v) => {
                    struct_ser.serialize_field("linkTraceId", v)?;
                }
            }
        }
        if let Some(v) = self.r#match.as_ref() {
            match v {
                trace_matcher::Match::Exact(v) => {
                    struct_ser.serialize_field("exact", v)?;
                }
                trace_matcher::Match::Regex(v) => {
                    struct_ser.serialize_field("regex", v)?;
                }
                trace_matcher::Match::Exists(v) => {
                    struct_ser.serialize_field("exists", v)?;
                }
                trace_matcher::Match::StartsWith(v) => {
                    struct_ser.serialize_field("startsWith", v)?;
                }
                trace_matcher::Match::EndsWith(v) => {
                    struct_ser.serialize_field("endsWith", v)?;
                }
                trace_matcher::Match::Contains(v) => {
                    struct_ser.serialize_field("contains", v)?;
                }
            }
        }
        struct_ser.end()
    }
}
impl<'de> serde::Deserialize<'de> for TraceMatcher {
    #[allow(deprecated)]
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        const FIELDS: &[&str] = &[
            "negate",
            "case_insensitive",
            "caseInsensitive",
            "trace_field",
            "traceField",
            "span_attribute",
            "spanAttribute",
            "resource_attribute",
            "resourceAttribute",
            "scope_attribute",
            "scopeAttribute",
            "span_kind",
            "spanKind",
            "span_status",
            "spanStatus",
            "event_name",
            "eventName",
            "event_attribute",
            "eventAttribute",
            "link_trace_id",
            "linkTraceId",
            "exact",
            "regex",
            "exists",
            "starts_with",
            "startsWith",
            "ends_with",
            "endsWith",
            "contains",
        ];

        #[allow(clippy::enum_variant_names)]
        enum GeneratedField {
            Negate,
            CaseInsensitive,
            TraceField,
            SpanAttribute,
            ResourceAttribute,
            ScopeAttribute,
            SpanKind,
            SpanStatus,
            EventName,
            EventAttribute,
            LinkTraceId,
            Exact,
            Regex,
            Exists,
            StartsWith,
            EndsWith,
            Contains,
        }
        impl<'de> serde::Deserialize<'de> for GeneratedField {
            fn deserialize<D>(deserializer: D) -> std::result::Result<GeneratedField, D::Error>
            where
                D: serde::Deserializer<'de>,
            {
                struct GeneratedVisitor;

                impl<'de> serde::de::Visitor<'de> for GeneratedVisitor {
                    type Value = GeneratedField;

                    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                        write!(formatter, "expected one of: {:?}", &FIELDS)
                    }

                    #[allow(unused_variables)]
                    fn visit_str<E>(self, value: &str) -> std::result::Result<GeneratedField, E>
                    where
                        E: serde::de::Error,
                    {
                        match value {
                            "negate" => Ok(GeneratedField::Negate),
                            "caseInsensitive" | "case_insensitive" => Ok(GeneratedField::CaseInsensitive),
                            "traceField" | "trace_field" => Ok(GeneratedField::TraceField),
                            "spanAttribute" | "span_attribute" => Ok(GeneratedField::SpanAttribute),
                            "resourceAttribute" | "resource_attribute" => Ok(GeneratedField::ResourceAttribute),
                            "scopeAttribute" | "scope_attribute" => Ok(GeneratedField::ScopeAttribute),
                            "spanKind" | "span_kind" => Ok(GeneratedField::SpanKind),
                            "spanStatus" | "span_status" => Ok(GeneratedField::SpanStatus),
                            "eventName" | "event_name" => Ok(GeneratedField::EventName),
                            "eventAttribute" | "event_attribute" => Ok(GeneratedField::EventAttribute),
                            "linkTraceId" | "link_trace_id" => Ok(GeneratedField::LinkTraceId),
                            "exact" => Ok(GeneratedField::Exact),
                            "regex" => Ok(GeneratedField::Regex),
                            "exists" => Ok(GeneratedField::Exists),
                            "startsWith" | "starts_with" => Ok(GeneratedField::StartsWith),
                            "endsWith" | "ends_with" => Ok(GeneratedField::EndsWith),
                            "contains" => Ok(GeneratedField::Contains),
                            _ => Err(serde::de::Error::unknown_field(value, FIELDS)),
                        }
                    }
                }
                deserializer.deserialize_identifier(GeneratedVisitor)
            }
        }
        struct GeneratedVisitor;
        impl<'de> serde::de::Visitor<'de> for GeneratedVisitor {
            type Value = TraceMatcher;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("struct tero.policy.v1.TraceMatcher")
            }

            fn visit_map<V>(self, mut map_: V) -> std::result::Result<TraceMatcher, V::Error>
                where
                    V: serde::de::MapAccess<'de>,
            {
                let mut negate__ = None;
                let mut case_insensitive__ = None;
                let mut field__ = None;
                let mut r#match__ = None;
                while let Some(k) = map_.next_key()? {
                    match k {
                        GeneratedField::Negate => {
                            if negate__.is_some() {
                                return Err(serde::de::Error::duplicate_field("negate"));
                            }
                            negate__ = Some(map_.next_value()?);
                        }
                        GeneratedField::CaseInsensitive => {
                            if case_insensitive__.is_some() {
                                return Err(serde::de::Error::duplicate_field("caseInsensitive"));
                            }
                            case_insensitive__ = Some(map_.next_value()?);
                        }
                        GeneratedField::TraceField => {
                            if field__.is_some() {
                                return Err(serde::de::Error::duplicate_field("traceField"));
                            }
                            field__ = map_.next_value::<::std::option::Option<TraceField>>()?.map(|x| trace_matcher::Field::TraceField(x as i32));
                        }
                        GeneratedField::SpanAttribute => {
                            if field__.is_some() {
                                return Err(serde::de::Error::duplicate_field("spanAttribute"));
                            }
                            field__ = map_.next_value::<::std::option::Option<_>>()?.map(trace_matcher::Field::SpanAttribute)
;
                        }
                        GeneratedField::ResourceAttribute => {
                            if field__.is_some() {
                                return Err(serde::de::Error::duplicate_field("resourceAttribute"));
                            }
                            field__ = map_.next_value::<::std::option::Option<_>>()?.map(trace_matcher::Field::ResourceAttribute)
;
                        }
                        GeneratedField::ScopeAttribute => {
                            if field__.is_some() {
                                return Err(serde::de::Error::duplicate_field("scopeAttribute"));
                            }
                            field__ = map_.next_value::<::std::option::Option<_>>()?.map(trace_matcher::Field::ScopeAttribute)
;
                        }
                        GeneratedField::SpanKind => {
                            if field__.is_some() {
                                return Err(serde::de::Error::duplicate_field("spanKind"));
                            }
                            field__ = map_.next_value::<::std::option::Option<SpanKind>>()?.map(|x| trace_matcher::Field::SpanKind(x as i32));
                        }
                        GeneratedField::SpanStatus => {
                            if field__.is_some() {
                                return Err(serde::de::Error::duplicate_field("spanStatus"));
                            }
                            field__ = map_.next_value::<::std::option::Option<SpanStatusCode>>()?.map(|x| trace_matcher::Field::SpanStatus(x as i32));
                        }
                        GeneratedField::EventName => {
                            if field__.is_some() {
                                return Err(serde::de::Error::duplicate_field("eventName"));
                            }
                            field__ = map_.next_value::<::std::option::Option<_>>()?.map(trace_matcher::Field::EventName);
                        }
                        GeneratedField::EventAttribute => {
                            if field__.is_some() {
                                return Err(serde::de::Error::duplicate_field("eventAttribute"));
                            }
                            field__ = map_.next_value::<::std::option::Option<_>>()?.map(trace_matcher::Field::EventAttribute)
;
                        }
                        GeneratedField::LinkTraceId => {
                            if field__.is_some() {
                                return Err(serde::de::Error::duplicate_field("linkTraceId"));
                            }
                            field__ = map_.next_value::<::std::option::Option<_>>()?.map(trace_matcher::Field::LinkTraceId);
                        }
                        GeneratedField::Exact => {
                            if r#match__.is_some() {
                                return Err(serde::de::Error::duplicate_field("exact"));
                            }
                            r#match__ = map_.next_value::<::std::option::Option<_>>()?.map(trace_matcher::Match::Exact);
                        }
                        GeneratedField::Regex => {
                            if r#match__.is_some() {
                                return Err(serde::de::Error::duplicate_field("regex"));
                            }
                            r#match__ = map_.next_value::<::std::option::Option<_>>()?.map(trace_matcher::Match::Regex);
                        }
                        GeneratedField::Exists => {
                            if r#match__.is_some() {
                                return Err(serde::de::Error::duplicate_field("exists"));
                            }
                            r#match__ = map_.next_value::<::std::option::Option<_>>()?.map(trace_matcher::Match::Exists);
                        }
                        GeneratedField::StartsWith => {
                            if r#match__.is_some() {
                                return Err(serde::de::Error::duplicate_field("startsWith"));
                            }
                            r#match__ = map_.next_value::<::std::option::Option<_>>()?.map(trace_matcher::Match::StartsWith);
                        }
                        GeneratedField::EndsWith => {
                            if r#match__.is_some() {
                                return Err(serde::de::Error::duplicate_field("endsWith"));
                            }
                            r#match__ = map_.next_value::<::std::option::Option<_>>()?.map(trace_matcher::Match::EndsWith);
                        }
                        GeneratedField::Contains => {
                            if r#match__.is_some() {
                                return Err(serde::de::Error::duplicate_field("contains"));
                            }
                            r#match__ = map_.next_value::<::std::option::Option<_>>()?.map(trace_matcher::Match::Contains);
                        }
                    }
                }
                Ok(TraceMatcher {
                    negate: negate__.unwrap_or_default(),
                    case_insensitive: case_insensitive__.unwrap_or_default(),
                    field: field__,
                    r#match: r#match__,
                })
            }
        }
        deserializer.deserialize_struct("tero.policy.v1.TraceMatcher", FIELDS, GeneratedVisitor)
    }
}
impl serde::Serialize for TraceSamplingConfig {
    #[allow(deprecated)]
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut len = 0;
        if self.percentage != 0. {
            len += 1;
        }
        if self.mode.is_some() {
            len += 1;
        }
        if self.sampling_precision.is_some() {
            len += 1;
        }
        if self.hash_seed.is_some() {
            len += 1;
        }
        if self.fail_closed.is_some() {
            len += 1;
        }
        let mut struct_ser = serializer.serialize_struct("tero.policy.v1.TraceSamplingConfig", len)?;
        if self.percentage != 0. {
            struct_ser.serialize_field("percentage", &self.percentage)?;
        }
        if let Some(v) = self.mode.as_ref() {
            let v = SamplingMode::try_from(*v)
                .map_err(|_| serde::ser::Error::custom(format!("Invalid variant {}", *v)))?;
            struct_ser.serialize_field("mode", &v)?;
        }
        if let Some(v) = self.sampling_precision.as_ref() {
            struct_ser.serialize_field("samplingPrecision", v)?;
        }
        if let Some(v) = self.hash_seed.as_ref() {
            struct_ser.serialize_field("hashSeed", v)?;
        }
        if let Some(v) = self.fail_closed.as_ref() {
            struct_ser.serialize_field("failClosed", v)?;
        }
        struct_ser.end()
    }
}
impl<'de> serde::Deserialize<'de> for TraceSamplingConfig {
    #[allow(deprecated)]
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        const FIELDS: &[&str] = &[
            "percentage",
            "mode",
            "sampling_precision",
            "samplingPrecision",
            "hash_seed",
            "hashSeed",
            "fail_closed",
            "failClosed",
        ];

        #[allow(clippy::enum_variant_names)]
        enum GeneratedField {
            Percentage,
            Mode,
            SamplingPrecision,
            HashSeed,
            FailClosed,
        }
        impl<'de> serde::Deserialize<'de> for GeneratedField {
            fn deserialize<D>(deserializer: D) -> std::result::Result<GeneratedField, D::Error>
            where
                D: serde::Deserializer<'de>,
            {
                struct GeneratedVisitor;

                impl<'de> serde::de::Visitor<'de> for GeneratedVisitor {
                    type Value = GeneratedField;

                    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                        write!(formatter, "expected one of: {:?}", &FIELDS)
                    }

                    #[allow(unused_variables)]
                    fn visit_str<E>(self, value: &str) -> std::result::Result<GeneratedField, E>
                    where
                        E: serde::de::Error,
                    {
                        match value {
                            "percentage" => Ok(GeneratedField::Percentage),
                            "mode" => Ok(GeneratedField::Mode),
                            "samplingPrecision" | "sampling_precision" => Ok(GeneratedField::SamplingPrecision),
                            "hashSeed" | "hash_seed" => Ok(GeneratedField::HashSeed),
                            "failClosed" | "fail_closed" => Ok(GeneratedField::FailClosed),
                            _ => Err(serde::de::Error::unknown_field(value, FIELDS)),
                        }
                    }
                }
                deserializer.deserialize_identifier(GeneratedVisitor)
            }
        }
        struct GeneratedVisitor;
        impl<'de> serde::de::Visitor<'de> for GeneratedVisitor {
            type Value = TraceSamplingConfig;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("struct tero.policy.v1.TraceSamplingConfig")
            }

            fn visit_map<V>(self, mut map_: V) -> std::result::Result<TraceSamplingConfig, V::Error>
                where
                    V: serde::de::MapAccess<'de>,
            {
                let mut percentage__ = None;
                let mut mode__ = None;
                let mut sampling_precision__ = None;
                let mut hash_seed__ = None;
                let mut fail_closed__ = None;
                while let Some(k) = map_.next_key()? {
                    match k {
                        GeneratedField::Percentage => {
                            if percentage__.is_some() {
                                return Err(serde::de::Error::duplicate_field("percentage"));
                            }
                            percentage__ = 
                                Some(map_.next_value::<::pbjson::private::NumberDeserialize<_>>()?.0)
                            ;
                        }
                        GeneratedField::Mode => {
                            if mode__.is_some() {
                                return Err(serde::de::Error::duplicate_field("mode"));
                            }
                            mode__ = map_.next_value::<::std::option::Option<SamplingMode>>()?.map(|x| x as i32);
                        }
                        GeneratedField::SamplingPrecision => {
                            if sampling_precision__.is_some() {
                                return Err(serde::de::Error::duplicate_field("samplingPrecision"));
                            }
                            sampling_precision__ = 
                                map_.next_value::<::std::option::Option<::pbjson::private::NumberDeserialize<_>>>()?.map(|x| x.0)
                            ;
                        }
                        GeneratedField::HashSeed => {
                            if hash_seed__.is_some() {
                                return Err(serde::de::Error::duplicate_field("hashSeed"));
                            }
                            hash_seed__ = 
                                map_.next_value::<::std::option::Option<::pbjson::private::NumberDeserialize<_>>>()?.map(|x| x.0)
                            ;
                        }
                        GeneratedField::FailClosed => {
                            if fail_closed__.is_some() {
                                return Err(serde::de::Error::duplicate_field("failClosed"));
                            }
                            fail_closed__ = map_.next_value()?;
                        }
                    }
                }
                Ok(TraceSamplingConfig {
                    percentage: percentage__.unwrap_or_default(),
                    mode: mode__,
                    sampling_precision: sampling_precision__,
                    hash_seed: hash_seed__,
                    fail_closed: fail_closed__,
                })
            }
        }
        deserializer.deserialize_struct("tero.policy.v1.TraceSamplingConfig", FIELDS, GeneratedVisitor)
    }
}
impl serde::Serialize for TraceTarget {
    #[allow(deprecated)]
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut len = 0;
        if !self.r#match.is_empty() {
            len += 1;
        }
        if self.keep.is_some() {
            len += 1;
        }
        let mut struct_ser = serializer.serialize_struct("tero.policy.v1.TraceTarget", len)?;
        if !self.r#match.is_empty() {
            struct_ser.serialize_field("match", &self.r#match)?;
        }
        if let Some(v) = self.keep.as_ref() {
            struct_ser.serialize_field("keep", v)?;
        }
        struct_ser.end()
    }
}
impl<'de> serde::Deserialize<'de> for TraceTarget {
    #[allow(deprecated)]
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        const FIELDS: &[&str] = &[
            "match",
            "keep",
        ];

        #[allow(clippy::enum_variant_names)]
        enum GeneratedField {
            Match,
            Keep,
        }
        impl<'de> serde::Deserialize<'de> for GeneratedField {
            fn deserialize<D>(deserializer: D) -> std::result::Result<GeneratedField, D::Error>
            where
                D: serde::Deserializer<'de>,
            {
                struct GeneratedVisitor;

                impl<'de> serde::de::Visitor<'de> for GeneratedVisitor {
                    type Value = GeneratedField;

                    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                        write!(formatter, "expected one of: {:?}", &FIELDS)
                    }

                    #[allow(unused_variables)]
                    fn visit_str<E>(self, value: &str) -> std::result::Result<GeneratedField, E>
                    where
                        E: serde::de::Error,
                    {
                        match value {
                            "match" => Ok(GeneratedField::Match),
                            "keep" => Ok(GeneratedField::Keep),
                            _ => Err(serde::de::Error::unknown_field(value, FIELDS)),
                        }
                    }
                }
                deserializer.deserialize_identifier(GeneratedVisitor)
            }
        }
        struct GeneratedVisitor;
        impl<'de> serde::de::Visitor<'de> for GeneratedVisitor {
            type Value = TraceTarget;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("struct tero.policy.v1.TraceTarget")
            }

            fn visit_map<V>(self, mut map_: V) -> std::result::Result<TraceTarget, V::Error>
                where
                    V: serde::de::MapAccess<'de>,
            {
                let mut r#match__ = None;
                let mut keep__ = None;
                while let Some(k) = map_.next_key()? {
                    match k {
                        GeneratedField::Match => {
                            if r#match__.is_some() {
                                return Err(serde::de::Error::duplicate_field("match"));
                            }
                            r#match__ = Some(map_.next_value()?);
                        }
                        GeneratedField::Keep => {
                            if keep__.is_some() {
                                return Err(serde::de::Error::duplicate_field("keep"));
                            }
                            keep__ = map_.next_value()?;
                        }
                    }
                }
                Ok(TraceTarget {
                    r#match: r#match__.unwrap_or_default(),
                    keep: keep__,
                })
            }
        }
        deserializer.deserialize_struct("tero.policy.v1.TraceTarget", FIELDS, GeneratedVisitor)
    }
}
impl serde::Serialize for TransformStageStatus {
    #[allow(deprecated)]
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut len = 0;
        if self.hits != 0 {
            len += 1;
        }
        if self.misses != 0 {
            len += 1;
        }
        let mut struct_ser = serializer.serialize_struct("tero.policy.v1.TransformStageStatus", len)?;
        if self.hits != 0 {
            #[allow(clippy::needless_borrow)]
            #[allow(clippy::needless_borrows_for_generic_args)]
            struct_ser.serialize_field("hits", ToString::to_string(&self.hits).as_str())?;
        }
        if self.misses != 0 {
            #[allow(clippy::needless_borrow)]
            #[allow(clippy::needless_borrows_for_generic_args)]
            struct_ser.serialize_field("misses", ToString::to_string(&self.misses).as_str())?;
        }
        struct_ser.end()
    }
}
impl<'de> serde::Deserialize<'de> for TransformStageStatus {
    #[allow(deprecated)]
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        const FIELDS: &[&str] = &[
            "hits",
            "misses",
        ];

        #[allow(clippy::enum_variant_names)]
        enum GeneratedField {
            Hits,
            Misses,
        }
        impl<'de> serde::Deserialize<'de> for GeneratedField {
            fn deserialize<D>(deserializer: D) -> std::result::Result<GeneratedField, D::Error>
            where
                D: serde::Deserializer<'de>,
            {
                struct GeneratedVisitor;

                impl<'de> serde::de::Visitor<'de> for GeneratedVisitor {
                    type Value = GeneratedField;

                    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                        write!(formatter, "expected one of: {:?}", &FIELDS)
                    }

                    #[allow(unused_variables)]
                    fn visit_str<E>(self, value: &str) -> std::result::Result<GeneratedField, E>
                    where
                        E: serde::de::Error,
                    {
                        match value {
                            "hits" => Ok(GeneratedField::Hits),
                            "misses" => Ok(GeneratedField::Misses),
                            _ => Err(serde::de::Error::unknown_field(value, FIELDS)),
                        }
                    }
                }
                deserializer.deserialize_identifier(GeneratedVisitor)
            }
        }
        struct GeneratedVisitor;
        impl<'de> serde::de::Visitor<'de> for GeneratedVisitor {
            type Value = TransformStageStatus;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("struct tero.policy.v1.TransformStageStatus")
            }

            fn visit_map<V>(self, mut map_: V) -> std::result::Result<TransformStageStatus, V::Error>
                where
                    V: serde::de::MapAccess<'de>,
            {
                let mut hits__ = None;
                let mut misses__ = None;
                while let Some(k) = map_.next_key()? {
                    match k {
                        GeneratedField::Hits => {
                            if hits__.is_some() {
                                return Err(serde::de::Error::duplicate_field("hits"));
                            }
                            hits__ = 
                                Some(map_.next_value::<::pbjson::private::NumberDeserialize<_>>()?.0)
                            ;
                        }
                        GeneratedField::Misses => {
                            if misses__.is_some() {
                                return Err(serde::de::Error::duplicate_field("misses"));
                            }
                            misses__ = 
                                Some(map_.next_value::<::pbjson::private::NumberDeserialize<_>>()?.0)
                            ;
                        }
                    }
                }
                Ok(TransformStageStatus {
                    hits: hits__.unwrap_or_default(),
                    misses: misses__.unwrap_or_default(),
                })
            }
        }
        deserializer.deserialize_struct("tero.policy.v1.TransformStageStatus", FIELDS, GeneratedVisitor)
    }
}

use base64::{Engine, engine::general_purpose::STANDARD};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

pub mod base64_vec {
    use super::*;

    pub fn serialize<S: Serializer>(bytes: &Vec<u8>, s: S) -> Result<S::Ok, S::Error> {
        STANDARD.encode(bytes).serialize(s)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let s = String::deserialize(d)?;
        STANDARD.decode(&s).map_err(serde::de::Error::custom)
    }
}

pub mod hex_32 {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8; 32], s: S) -> Result<S::Ok, S::Error> {
        hex::encode(bytes).serialize(s)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 32], D::Error> {
        let s = String::deserialize(d)?;
        let decoded = hex::decode(&s).map_err(serde::de::Error::custom)?;
        let arr: [u8; 32] = decoded.try_into().map_err(|v: Vec<u8>| {
            serde::de::Error::custom(format!("expected 32 bytes, got {}", v.len()))
        })?;
        Ok(arr)
    }
}

pub mod hex_vec {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S: Serializer>(bytes: &Vec<u8>, s: S) -> Result<S::Ok, S::Error> {
        hex::encode(bytes).serialize(s)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let s = String::deserialize(d)?;
        hex::decode(&s).map_err(serde::de::Error::custom)
    }
}

pub mod hex_vec_option {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S: Serializer>(opt: &Option<Vec<u8>>, s: S) -> Result<S::Ok, S::Error> {
        match opt {
            Some(bytes) => hex::encode(bytes).serialize(s),
            None => s.serialize_none(),
        }
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Option<Vec<u8>>, D::Error> {
        let opt: Option<String> = Option::deserialize(d)?;
        match opt {
            Some(s) => {
                let decoded = hex::decode(&s).map_err(serde::de::Error::custom)?;
                Ok(Some(decoded))
            }
            None => Ok(None),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_32_round_trip() {
        #[derive(serde::Serialize, serde::Deserialize, PartialEq, Debug)]
        struct W {
            #[serde(with = "hex_32")]
            val: [u8; 32],
        }
        let w = W { val: [0xab; 32] };
        let json = serde_json::to_string(&w).unwrap();
        assert!(json.contains("abababab"), "hex output: {json}");
        assert_eq!(
            json.matches("ab").count(),
            32,
            "must be 64 hex chars (32 bytes)"
        );
        let parsed: W = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, w);
    }

    #[test]
    fn hex_vec_round_trip() {
        #[derive(serde::Serialize, serde::Deserialize, PartialEq, Debug)]
        struct W {
            #[serde(with = "hex_vec")]
            val: Vec<u8>,
        }
        let w = W {
            val: vec![0xde, 0xad, 0xbe, 0xef],
        };
        let json = serde_json::to_string(&w).unwrap();
        assert!(json.contains("deadbeef"), "hex output: {json}");
        let parsed: W = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, w);
    }

    #[test]
    fn hex_vec_option_round_trip() {
        #[derive(serde::Serialize, serde::Deserialize, PartialEq, Debug)]
        struct W {
            #[serde(
                with = "hex_vec_option",
                default,
                skip_serializing_if = "Option::is_none"
            )]
            val: Option<Vec<u8>>,
        }
        let some = W {
            val: Some(vec![0xff, 0x00]),
        };
        let json = serde_json::to_string(&some).unwrap();
        assert!(json.contains("ff00"), "hex output: {json}");
        let parsed: W = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, some);

        let none = W { val: None };
        let json = serde_json::to_string(&none).unwrap();
        assert!(!json.contains("val"), "None should be skipped: {json}");
        let parsed: W = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, none);
    }
}

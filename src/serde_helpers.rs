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

pub mod base64_32 {
    use super::*;

    pub fn serialize<S: Serializer>(bytes: &[u8; 32], s: S) -> Result<S::Ok, S::Error> {
        STANDARD.encode(bytes).serialize(s)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 32], D::Error> {
        let s = String::deserialize(d)?;
        let decoded = STANDARD.decode(&s).map_err(serde::de::Error::custom)?;
        let arr: [u8; 32] = decoded.try_into().map_err(|v: Vec<u8>| {
            serde::de::Error::custom(format!("expected 32 bytes, got {}", v.len()))
        })?;
        Ok(arr)
    }
}

pub mod base64_vec_option {
    use super::*;

    pub fn serialize<S: Serializer>(opt: &Option<Vec<u8>>, s: S) -> Result<S::Ok, S::Error> {
        match opt {
            Some(bytes) => STANDARD.encode(bytes).serialize(s),
            None => s.serialize_none(),
        }
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Option<Vec<u8>>, D::Error> {
        let opt: Option<String> = Option::deserialize(d)?;
        match opt {
            Some(s) => {
                let decoded = STANDARD.decode(&s).map_err(serde::de::Error::custom)?;
                Ok(Some(decoded))
            }
            None => Ok(None),
        }
    }
}

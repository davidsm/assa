use rustc_serialize::{Encodable, Decodable, Encoder, Decoder};
use rustc_serialize::json;
use rustc_serialize::base64;
use rustc_serialize::base64::{ToBase64, FromBase64};
use std::collections::HashMap;
use std::result;

use password::PasswordData;
use crypto::{SALTBYTES, NONCEBYTES};

type AccountMap = HashMap<String, PasswordData>;

#[derive(Debug, PartialEq)]
pub struct BinaryData<T: Base64Encodable>(pub T);

impl<T: Base64Encodable> ToBase64 for BinaryData<T> {
    fn to_base64(&self, config: base64::Config) -> String {
        self.0.base64_encode(config)
    }
}

impl<T: Base64Encodable> Encodable for BinaryData<T> {
    fn encode<S: Encoder>(&self, s: &mut S) -> result::Result<(), S::Error> {
        s.emit_str(&self.to_base64(base64::STANDARD))
    }
}

impl Decodable for BinaryData<Vec<u8>> {
    fn decode<D: Decoder>(d: &mut D) -> result::Result<Self, D::Error> {
        let base64_str = try!(d.read_str());
        base64_str.from_base64().or(Err(d.error("Base64 decoding failed"))).
            and_then(|val| { Ok(BinaryData(val)) })
    }
}

impl Decodable for BinaryData<[u8; SALTBYTES]> {
    fn decode<D: Decoder>(d: &mut D) -> result::Result<Self, D::Error> {
        let base64_str = try!(d.read_str());
        base64_str.from_base64().or(Err(d.error("Base64 decoding failed"))).
            and_then(|val| {
                let mut sb = [0; SALTBYTES];
                for i in 0..val.len() {
                    sb[i] = val[i];
                }
                Ok(BinaryData(sb))
            })
    }
}

impl Decodable for BinaryData<[u8; NONCEBYTES]> {
    fn decode<D: Decoder>(d: &mut D) -> result::Result<Self, D::Error> {
        let base64_str = try!(d.read_str());
        base64_str.from_base64().or(Err(d.error("Base64 decoding failed"))).
            and_then(|val| {
                let mut nb = [0; NONCEBYTES];
                for i in 0..val.len() {
                    nb[i] = val[i];
                }
                Ok(BinaryData(nb))
            })
    }
}


// Needed because ToBase64 isn't implemented for Vec,
// and can't implement it as neither trait nor struct is
// defined here
pub trait Base64Encodable {
    fn base64_encode(&self, config: base64::Config) -> String;
}

impl Base64Encodable for Vec<u8> {
    fn base64_encode(&self, config: base64::Config)  -> String {
        // Funny enough, this works, probably
        // due to deref coercion to &[u8]
        self.to_base64(config)
    }
}

impl Base64Encodable for [u8; SALTBYTES] {
    fn base64_encode(&self, config: base64::Config)  -> String {
        self.to_base64(config)
    }
}

impl Base64Encodable for [u8; NONCEBYTES] {
    fn base64_encode(&self, config: base64::Config) -> String {
        self.to_base64(config)
    }
}


#[derive(Debug, PartialEq)]
pub enum AccountError {
    DeserializationError(DeserializationErrorType),
    SerializationError(SerializationErrorType),
    AccountNotFound,
    AccountAlreadyExists
}

pub type Result<T> = result::Result<T, AccountError>;

impl From<json::DecoderError> for AccountError {
    fn from(err: json::DecoderError) -> AccountError {
        match err {
            json::DecoderError::ApplicationError(_) => DeserializationError(Base64Error),
            _ => DeserializationError(InvalidJSON)
        }
    }
}

impl From<json::EncoderError> for AccountError {
    fn from (err: json::EncoderError) -> AccountError {
        match err {
            json::EncoderError::FmtError(_) => SerializationError(FormattingError),
            json::EncoderError::BadHashmapKey => SerializationError(InvalidKey)
        }
    }
}


use self::AccountError::*;

#[derive(Debug, PartialEq)]
pub enum DeserializationErrorType {
    Base64Error,
    InvalidJSON,
}

use self::DeserializationErrorType::*;


#[derive(Debug, PartialEq)]
pub enum SerializationErrorType {
    InvalidKey,
    FormattingError
}

use self::SerializationErrorType::*;


pub fn get_password_data_for(account_name: &str,
                             accounts: &str,) -> Result<PasswordData> {

    let mut account_map = try!(get_account_map(accounts));

    // Pluck the PasswordData struct from the map to gain ownership of it
    account_map.remove(account_name).ok_or(AccountNotFound)
}

pub fn add_account(account_name: &str, password_data: PasswordData,
                   accounts: &str) -> Result<String> {
    let mut account_map = try!(get_account_map(accounts));
    if account_map.contains_key(account_name) {
        Err(AccountAlreadyExists)
    }
    else {
        account_map.insert(account_name.to_string(), password_data);
        json::encode(&account_map).map_err(|err| { AccountError::from(err) })
    }
}

pub fn change_account(account_name: &str, password_data: PasswordData,
                      accounts: &str) -> Result<String> {
    let mut account_map = try!(get_account_map(accounts));
    if !account_map.contains_key(account_name) {
        Err(AccountNotFound)
    }
    else {
        account_map.insert(account_name.to_string(), password_data);
        json::encode(&account_map).map_err(|err| { AccountError::from(err) })
    }
}

pub fn remove_account(account_name: &str,
                      accounts: &str,) -> Result<String> {
    let mut account_map = try!(get_account_map(accounts));

    if account_map.remove(account_name).is_none() {
        return Err(AccountNotFound)
    }
    json::encode(&account_map).map_err(|err| { AccountError::from(err) })
}

fn get_account_map(accounts: &str) -> Result<AccountMap> {
    let accmap: AccountMap = try!(json::decode(accounts));
    Ok(accmap)
}

#[cfg(test)]
mod test {
    use super::*;
    use super::{get_account_map, AccountMap};
    use super::super::password::PasswordData;


    // gmail
    // nonce [2; 24]
    // salt [1; 32]
    // password 0xDE, 0xAD, 0xBE, 0xEF
    //
    // something
    // nonce [4; 24]
    // salt [3; 24]
    // password 0xF0, 0x0D, 0xBE, 0xEF
    const VALID_ACCOUNT_STRUCTURE: &'static str = "{
    \"gmail\": {
        \"nonce\": \"AgICAgICAgICAgICAgICAgICAgICAgIC\",
        \"salt\": \"AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=\",
        \"password\": \"3q2+7w==\"
    },

    \"something\": {
        \"nonce\": \"BAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE\",
        \"salt\": \"AwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwM=\",
        \"password\": \"8A2+7w==\"
    }
}";

    #[test]
    fn test_get_password_data() {
        let password_data = get_password_data_for("gmail", VALID_ACCOUNT_STRUCTURE).unwrap();
        assert_eq!(&password_data.nonce, &BinaryData([2; super::super::crypto::NONCEBYTES]));
        assert_eq!(&password_data.salt, &BinaryData([1; super::super::crypto::SALTBYTES]));
        assert_eq!(&password_data.password, &BinaryData(vec![0xDE,0xAD,0xBE,0xEF]));
    }

    #[test]
    fn test_account_doesnt_exist() {
        let result = get_password_data_for("nosuchaccount", VALID_ACCOUNT_STRUCTURE);
        assert_eq!(result, Err(AccountError::AccountNotFound));
    }

    #[test]
    fn test_empty_account_structure() {
        let account_structure = "{}";
        let result = get_password_data_for("gmail", account_structure);
        assert_eq!(result, Err(AccountError::AccountNotFound));
    }

    #[test]
    fn test_partial_account_structure() {
        let account_structure = "{
            \"gmail\": {
              \"nonce\": \"AQIlCA==\",
              \"salt\": \"EAIlCA==\",
          }
        }";
        let result = get_password_data_for("gmail", account_structure);
        assert_eq!(result, Err(AccountError::DeserializationError(DeserializationErrorType::InvalidJSON)));
    }

    #[test]
    fn test_add_new_account() {
        let nonce = [1; super::super::crypto::NONCEBYTES];
        let salt = [2; super::super::crypto::SALTBYTES];
        let pwdata = PasswordData {
            salt: BinaryData(salt),
            nonce: BinaryData(nonce),
            password: BinaryData(vec![0x01, 0x02, 0x03, 0x04])
        };
        let new_json_structure = add_account("twitter", pwdata, VALID_ACCOUNT_STRUCTURE).unwrap();
        let twitter_password = get_password_data_for("twitter", &new_json_structure).unwrap();
        assert_eq!(twitter_password.password, BinaryData(vec![0x01, 0x02, 0x03, 0x04]));
        let gmail_password = get_password_data_for("gmail", &new_json_structure).unwrap();
        assert_eq!(gmail_password.password, BinaryData(vec![0xDE, 0xAD, 0xBE, 0xEF]));
    }

    #[test]
    fn test_add_account_already_exists() {
        let nonce = [1; super::super::crypto::NONCEBYTES];
        let salt = [2; super::super::crypto::SALTBYTES];
        let pwdata = PasswordData {
            salt: BinaryData(salt),
            nonce: BinaryData(nonce),
            password: BinaryData(vec![0x01, 0x02, 0x03, 0x04])
        };
        let res = add_account("gmail", pwdata, VALID_ACCOUNT_STRUCTURE);
        assert_eq!(res, Err(AccountError::AccountAlreadyExists));
    }

    #[test]
    fn test_change_account() {
        let nonce = [1; super::super::crypto::NONCEBYTES];
        let salt = [2; super::super::crypto::SALTBYTES];
        let pwdata = PasswordData {
            salt: BinaryData(salt),
            nonce: BinaryData(nonce),
            password: BinaryData(vec![0x01, 0x02, 0x03, 0x04])
        };
        let new_json_structure = change_account("gmail", pwdata, VALID_ACCOUNT_STRUCTURE).unwrap();
        let gmail_password = get_password_data_for("gmail", &new_json_structure).unwrap();
        assert_eq!(gmail_password.password, BinaryData(vec![0x01, 0x02, 0x03, 0x04]));
    }

    #[test]
    fn test_remove_account() {
        let new_json_structure = remove_account("gmail", VALID_ACCOUNT_STRUCTURE).unwrap();
        let gmail_password = get_password_data_for("gmail", &new_json_structure);
        assert_eq!(gmail_password, Err(AccountError::AccountNotFound));
        let something_password = get_password_data_for("something", &new_json_structure).unwrap();
        assert_eq!(something_password.password, BinaryData(vec![0xF0, 0x0D, 0xBE, 0xEF]));
    }

    #[test]
    fn test_get_new_account_map() {
        let acc_map = get_account_map("{}");
        assert_eq!(acc_map, Ok(AccountMap::new()));
    }
}

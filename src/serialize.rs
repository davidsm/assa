use rustc_serialize::{Encodable, Decodable, Encoder, Decoder};
use rustc_serialize::json;
use rustc_serialize::base64;
use rustc_serialize::base64::{ToBase64, FromBase64};
use std::collections::HashMap;

type AccountMap = HashMap<String, PasswordData>;

#[derive(Debug, PartialEq)]
pub struct BinaryData(pub Vec<u8>);

impl ToBase64 for BinaryData {
    fn to_base64(&self, config: base64::Config) -> String {
        self.0.to_base64(config)
    }
}

impl Encodable for BinaryData {
    fn encode<S: Encoder>(&self, s: &mut S) -> Result<(), S::Error> {
        s.emit_str(&self.to_base64(base64::STANDARD))
    }
}

impl Decodable for BinaryData {
    fn decode<D: Decoder>(d: &mut D) -> Result<Self, D::Error> {
        let base64_str = try!(d.read_str());
        base64_str.from_base64().or(Err(d.error("Base64 decoding failed"))).
            and_then(|val| { Ok(BinaryData(val)) })
    }
}

#[derive(RustcDecodable, RustcEncodable, Debug, PartialEq)]
pub struct PasswordData {
    pub nonce: BinaryData,
    pub salt: BinaryData,
    pub password: BinaryData
}

#[derive(Debug, PartialEq)]
pub enum AccountError {
    SyntaxError(SyntaxErrorType),
    AccountNotFound,
    AccountAlreadyExists
}

impl From<json::DecoderError> for AccountError {
    fn from(err: json::DecoderError) -> AccountError {
        match err {
            json::DecoderError::ApplicationError(_) => SyntaxError(Base64Error),
            _ => SyntaxError(InvalidJSON)
        }
    }
}

use self::AccountError::*;

#[derive(Debug, PartialEq)]
pub enum SyntaxErrorType {
    Base64Error,
    InvalidJSON,
}

use self::SyntaxErrorType::*;

pub fn get_password_data_for(account_name: &str,
                             accounts: &str,) -> Result<PasswordData, AccountError> {

    let mut account_map = try!(get_account_map(accounts));

    // Pluck the PasswordData struct from the map to gain ownership of it
    account_map.remove(account_name).ok_or(AccountNotFound)
}

pub fn add_account(account_name: &str, password_data: PasswordData,
                   accounts: &str) -> Result<String, AccountError> {
    let mut account_map = try!(get_account_map(accounts));
    if account_map.contains_key(account_name) {
        Err(AccountAlreadyExists)
    }
    else {
        account_map.insert(account_name.to_string(), password_data);
        match json::encode(&account_map) {
            Ok(json_account_map) => Ok(json_account_map),
            Err(_) => {
                return Err(SyntaxError(InvalidJSON));
            }
        }
    }
}

pub fn change_account(account_name: &str, password_data: PasswordData,
                      accounts: &str) -> Result<String, AccountError> {
    let mut account_map = try!(get_account_map(accounts));
    if !account_map.contains_key(account_name) {
        Err(AccountNotFound)
    }
    else {
        account_map.insert(account_name.to_string(), password_data);
        match json::encode(&account_map) {
            Ok(json_account_map) => Ok(json_account_map),
            Err(_) => {
                return Err(SyntaxError(InvalidJSON));
            }
        }
    }
}

pub fn remove_account(account_name: &str,
                      accounts: &str,) -> Result<String, AccountError> {
    let mut account_map = try!(get_account_map(accounts));

    if account_map.remove(account_name).is_none() {
        return Err(AccountNotFound)
    }
    match json::encode(&account_map) {
        Ok(json_account_map) => Ok(json_account_map),
        Err(_) => Err(SyntaxError(InvalidJSON))
    }
}

fn get_account_map(accounts: &str) -> Result<AccountMap, AccountError> {
    let accmap: AccountMap = try!(json::decode(accounts));
    Ok(accmap)
}

#[cfg(test)]
mod test {
    use super::*;


    // gmail
    // nonce 0x01, 0x02, 0x25, 0x08
    // salt 0x10, 0x02, 0x25, 0x08
    // password 0xDE, 0xAD, 0xBE, 0xEF
    //
    // something
    // nonce 0x0A, 0x0B, 0x0C, 0x0D
    // salt 0xA0, 0xB0, 0xC0, 0xD0
    // password 0xF0, 0x0D, 0xBE, 0xEF
    const VALID_ACCOUNT_STRUCTURE: &'static str = "{
    \"gmail\": {
        \"nonce\": \"AQIlCA==\",
        \"salt\": \"EAIlCA==\",
        \"password\": \"3q2+7w==\"
    },

    \"something\": {
        \"nonce\": \"CgsMDQ==\",
        \"salt\": \"oLDA0A==\",
        \"password\": \"8A2+7w==\"
    }
}";

    #[test]
    fn test_get_password_data() {
        let password_data = get_password_data_for("gmail", VALID_ACCOUNT_STRUCTURE).unwrap();
        assert_eq!(&password_data.nonce, &BinaryData(vec![0x01,0x02,0x25,0x08]));
        assert_eq!(&password_data.salt, &BinaryData(vec![0x10,0x02,0x25,0x08]));
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
        assert_eq!(result, Err(AccountError::SyntaxError(SyntaxErrorType::InvalidJSON)));
    }

    #[test]
    fn test_add_new_account() {
        let pwdata = PasswordData {
            salt: BinaryData(vec![0x04, 0x08, 0x0A, 0x0C]),
            nonce: BinaryData(vec![0x01, 0x03, 0x05, 0x07]),
            password: BinaryData(vec![0x01, 0x02, 0x03, 0x04])
        };
        let new_json_structure = add_account("twitter", pwdata, VALID_ACCOUNT_STRUCTURE).unwrap();
        let twitter_password = get_password_data_for("twitter", &new_json_structure).unwrap();
        assert_eq!(twitter_password.password, BinaryData(vec![0x01, 0x02, 0x03, 0x04]));
        let gmail_password = get_password_data_for("gmail", &new_json_structure).unwrap();
        assert_eq!(gmail_password.password, BinaryData(vec![0xDE, 0xAD, 0xBE, 0xEF]));
    }

    #[test]
    fn test_change_account() {
        let pwdata = PasswordData {
            salt: BinaryData(vec![0x04, 0x08, 0x0A, 0x0C]),
            nonce: BinaryData(vec![0x01, 0x03, 0x05, 0x07]),
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
}

use rustc_serialize::json;
use std::collections::HashMap;

type AccountMap = HashMap<String, PasswordData>;

#[derive(RustcDecodable, RustcEncodable, Debug, PartialEq)]
pub struct PasswordData {
    pub nonce: String,
    pub salt: String,
    pub password: String
}

#[derive(Debug, PartialEq)]
pub enum AccountError {
    SyntaxError,
    AccountNotFound,
    AccountAlreadyExists
}

impl From<json::DecoderError> for AccountError {
    fn from(err: json::DecoderError) -> AccountError {
        AccountError::SyntaxError
    }
}

use self::AccountError::*;

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
        // TODO: Error type is placeholder
        Err(AccountAlreadyExists)
    }
    else {
        account_map.insert(account_name.to_string(), password_data);
        match json::encode(&account_map) {
            Ok(json_account_map) => Ok(json_account_map),
            Err(_) => {
                return Err(SyntaxError);
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
                return Err(SyntaxError);
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
        Err(_) => Err(SyntaxError)
    }
}

fn get_account_map(accounts: &str) -> Result<AccountMap, AccountError> {
    let accmap: AccountMap = try!(json::decode(accounts));
    Ok(accmap)
}

#[cfg(test)]
mod test {
    use super::*;

    const VALID_ACCOUNT_STRUCTURE: &'static str = "{
    \"gmail\": {
        \"nonce\": \"sadAdsasd\",
        \"salt\": \"dadasGDsds=\",
        \"password\": \"dsadsaFGd\"
    },

    \"something\": {
        \"nonce\": \"sadAdsasd\",
        \"salt\": \"dadasGDsds=\",
        \"password\": \"Egsdsads\"
    }

}";

    #[test]
    fn test_get_password_data() {
        let password_data = get_password_data_for("gmail", VALID_ACCOUNT_STRUCTURE).unwrap();
        assert_eq!(&password_data.password, "dsadsaFGd");
        assert_eq!(&password_data.nonce, "sadAdsasd");
        assert_eq!(&password_data.salt, "dadasGDsds=");
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
                \"nonce\": \"sadAdsasd\",
                \"password\": \"dsadsaFGd\"
            }
        }";
        let result = get_password_data_for("gmail", account_structure);
        assert_eq!(result, Err(AccountError::SyntaxError));
    }

    #[test]
    fn test_add_new_account() {
        let pwdata = PasswordData {
            salt: "dsdsds".to_string(),
            nonce: "abvcasd".to_string(),
            password: "dsadsaD".to_string()
        };
        let new_json_structure = add_account("twitter", pwdata, VALID_ACCOUNT_STRUCTURE).unwrap();
        let twitter_password = get_password_data_for("twitter", &new_json_structure).unwrap();
        assert_eq!(&twitter_password.password, "dsadsaD");
        let gmail_password = get_password_data_for("gmail", &new_json_structure).unwrap();
        assert_eq!(&gmail_password.password, "dsadsaFGd");
    }

    #[test]
    fn test_change_account() {
        let pwdata = PasswordData {
            salt: "dsdsds".to_string(),
            nonce: "abvcasd".to_string(),
            password: "dsadsaD".to_string()
        };
        let new_json_structure = change_account("gmail", pwdata, VALID_ACCOUNT_STRUCTURE).unwrap();
        let gmail_password = get_password_data_for("gmail", &new_json_structure).unwrap();
        assert_eq!(&gmail_password.password, "dsadsaD");
    }

    #[test]
    fn test_remove_account() {
        let new_json_structure = remove_account("gmail", VALID_ACCOUNT_STRUCTURE).unwrap();
        let gmail_password = get_password_data_for("gmail", &new_json_structure);
        assert_eq!(gmail_password, Err(AccountError::AccountNotFound));
        let something_password = get_password_data_for("something", &new_json_structure).unwrap();
        assert_eq!(&something_password.password, "Egsdsads");
    }
}

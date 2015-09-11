use rustc_serialize::json;
use std::collections::HashMap;

type AccountMap = HashMap<String, PasswordData>;

#[derive(RustcDecodable, RustcEncodable, Debug, PartialEq)]
pub struct PasswordData {
    pub nonce: String,
    pub salt: String,
    pub password_hash: String
}

#[derive(Debug, PartialEq)]
pub enum AccountError {
    SyntaxError,
    AccountNotFound,
    AccountAlreadyExists
}

use self::AccountError::*;

pub fn get_password_data_for(account_name: &str,
                             accounts: &str,) -> Result<PasswordData, AccountError> {

    let mut account_map = try!(get_account_map(accounts));

    // Pluck the PasswordData struct from the map to gain ownership of it
    let password_data = match account_map.remove(account_name) {
        Some(pwdata) => pwdata,
        None => {
            return Err(AccountNotFound);
        }
    };

    Ok(password_data)
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
                      accounts: &str,) -> Result<(), AccountError> {
    let mut account_map = try!(get_account_map(accounts));

    match account_map.remove(account_name) {
        Some(pwdata) => pwdata,
        None => {
            return Err(AccountNotFound);
        }
    };

    Ok(())
}

fn get_account_map(accounts: &str) -> Result<AccountMap, AccountError> {
    let account_map: AccountMap = match json::decode(accounts) {
        Ok(accmap) => accmap,
        Err(_) => {
            return Err(SyntaxError);
        }
    };

    Ok(account_map)
}

#[cfg(test)]
mod test {
    use super::*;

    const VALID_ACCOUNT_STRUCTURE: &'static str = "{
    \"gmail\": {
        \"nonce\": \"sadAdsasd\",
        \"salt\": \"dadasGDsds=\",
        \"password_hash\": \"dsadsaFGd\"
    },

    \"something\": {
        \"nonce\": \"sadAdsasd\",
        \"salt\": \"dadasGDsds=\",
        \"password_hash\": \"dsadsaFGd\"
    }

}";

    #[test]
    fn test_get_password_data() {
        let password_data = get_password_data_for("gmail", VALID_ACCOUNT_STRUCTURE).unwrap();
        assert_eq!(&password_data.password_hash, "dsadsaFGd");
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
                \"password_hash\": \"dsadsaFGd\"
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
            password_hash: "dsadsaD".to_string()
        };
        let new_json_structure = add_account("twitter", pwdata, VALID_ACCOUNT_STRUCTURE).unwrap();
        let twitter_password = get_password_data_for("twitter", &new_json_structure).unwrap();
        assert_eq!(&twitter_password.password_hash, "dsadsaD");
        let gmail_password = get_password_data_for("gmail", &new_json_structure).unwrap();
        assert_eq!(&gmail_password.password_hash, "dsadsaFGd");
    }

    #[test]
    fn test_change_account() {
        let pwdata = PasswordData {
            salt: "dsdsds".to_string(),
            nonce: "abvcasd".to_string(),
            password_hash: "dsadsaD".to_string()
        };
        let new_json_structure = change_account("gmail", pwdata, VALID_ACCOUNT_STRUCTURE).unwrap();
        let gmail_password = get_password_data_for("gmail", &new_json_structure).unwrap();
        assert_eq!(&gmail_password.password_hash, "dsadsaD");
    }
}

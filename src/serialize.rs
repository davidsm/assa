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
pub enum PasswordRetrieveError {
    SyntaxError,
    AccountNotFound
}

use self::PasswordRetrieveError::*;

pub fn get_password_data_for(account_name: &str,
                             accounts: &str,) -> Result<PasswordData, PasswordRetrieveError> {

    let mut account_map: AccountMap = match json::decode(accounts) {
        Ok(accmap) => accmap,
        Err(_) => {
            return Err(SyntaxError);
        }
    };

    // Pluck the PasswordData struct from the map to gain ownership of it
    let password_data = match account_map.remove(account_name) {
        Some(pwdata) => pwdata,
        None => {
            return Err(AccountNotFound);
        }
    };

    Ok(password_data)
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
        assert_eq!(result, Err(PasswordRetrieveError::AccountNotFound));

    }

    #[test]
    fn test_empty_account_structure() {
        let account_structure = "{}";
        let result = get_password_data_for("gmail", account_structure);
        assert_eq!(result, Err(PasswordRetrieveError::AccountNotFound));
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
        assert_eq!(result, Err(PasswordRetrieveError::SyntaxError));
    }
}

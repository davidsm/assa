use sodiumoxide::crypto::pwhash;
use sodiumoxide::crypto::secretbox;
use sodiumoxide::crypto::hash::sha256;
use rustc_serialize::base64::STANDARD as BASE64_STANDARD;
use rustc_serialize::base64::ToBase64;
use std::string::String;

use super::password::PasswordData;

pub use sodiumoxide::crypto::pwhash::SALTBYTES;
pub use sodiumoxide::crypto::secretbox::NONCEBYTES;

pub enum CryptoError {
    KeyDerivationFailure,
    DecryptionFailure,
    DecodingFailure
}

use self::CryptoError::*;


fn get_key(password: &str, salt: &pwhash::Salt) -> Result<secretbox::Key, CryptoError> {
    let password_bytes = password.as_bytes();
    let mut key = secretbox::Key([0; secretbox::KEYBYTES]);
    {
        let secretbox::Key(ref mut key_bytes) = key;
        try!(pwhash::derive_key(key_bytes, password_bytes, &salt,
                                pwhash::OPSLIMIT_INTERACTIVE,
                                pwhash::MEMLIMIT_INTERACTIVE)
             .or(Err(KeyDerivationFailure)));
    }
    Ok(key)
}

fn encrypt_password(plaintext: &str, key: &secretbox::Key,
                        nonce: &secretbox::Nonce) -> Vec<u8> {
    let plaintext_bytes = plaintext.as_bytes();
    return secretbox::seal(&plaintext_bytes, &nonce, &key);
}

fn decrypt_password(ciphertext: &Vec<u8>, key: &secretbox::Key,
                        nonce: &secretbox::Nonce) -> Result<String, CryptoError> {
    let decrypted = try!(secretbox::open(&ciphertext, &nonce, &key)
                         .or(Err(DecryptionFailure)));
    match String::from_utf8(decrypted) {
        Ok(decrypted_text) => Ok(decrypted_text),
        Err(_) => Err(DecodingFailure)
    }
}

pub fn create_encrypted_password(plaintext_password: &str, master_password: &str)
                                 -> Result<PasswordData, CryptoError> {
    let salt = pwhash::gen_salt();
    let key = try!(get_key(master_password, &salt));

    let nonce = secretbox::gen_nonce();
    let encrypted_password = encrypt_password(plaintext_password, &key, &nonce);

    let secretbox::Nonce(nonce_bytes) = nonce;
    let pwhash::Salt(salt_bytes) = salt;
    Ok(PasswordData::new(encrypted_password, salt_bytes, nonce_bytes))
}

pub fn get_decrypted_password(master_password: &str, password_data: PasswordData)
                              -> Result<String, CryptoError> {
    let key = try!(get_key(master_password, &pwhash::Salt(password_data.salt())));
    let decrypted_password = try!(decrypt_password(&password_data.password(),&key,
                                                   &secretbox::Nonce(password_data.nonce())));
    Ok(decrypted_password)
}

pub fn hash_account_name(account_name: &str) -> String {
    let sha256::Digest(hashed_name) = sha256::hash(account_name.as_bytes());
    hashed_name.to_base64(BASE64_STANDARD)
}

#[cfg(test)]
mod test {
    use super::{get_key, encrypt_password, decrypt_password, hash_account_name};
    use sodiumoxide::crypto::pwhash;
    use sodiumoxide::crypto::secretbox;

    /// Test that get_key always returns the same key given the same
    /// password, and that its result can be used as a key for
    /// encrypt/decrypt
    #[test]
    fn test_key_derivation_and_encryption() {
        let password = "super secret password";
        let plaintext = "secret content";
        let nonce = secretbox::gen_nonce();
        let key_salt = pwhash::gen_salt();
        let encrypted: Vec<u8>;
        {
            let key = get_key(password, &key_salt).unwrap();
            encrypted = encrypt_password(plaintext, &key, &nonce);
        }
        let key = get_key(password, &key_salt).unwrap();
        let decrypted = decrypt_password(&encrypted, &key, &nonce)
            .unwrap();
        assert_eq!(plaintext.to_string(), decrypted);
    }

    #[test]
    fn test_hash() {
        // Silly sanity check
        let account_name = "gmail";
        let hash1 = hash_account_name(account_name);
        let hash2 = hash_account_name(account_name);
        assert_eq!(hash1, hash2);
    }

}

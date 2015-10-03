use sodiumoxide::crypto::pwhash;
use sodiumoxide::crypto::secretbox;
use std::string::String;

use super::password::{PasswordData, generate_password};

pub fn get_key(password: &str, salt: pwhash::Salt) -> Result<secretbox::Key, ()> {
    let password_bytes = password.as_bytes();
    let mut key = secretbox::Key([0; secretbox::KEYBYTES]);
    {
        let secretbox::Key(ref mut key_bytes) = key;
        try!(pwhash::derive_key(key_bytes, password_bytes, &salt,
                           pwhash::OPSLIMIT_INTERACTIVE,
                           pwhash::MEMLIMIT_INTERACTIVE));
    }
    Ok(key)
}

pub fn encrypt_password(plaintext: &str, key: &secretbox::Key,
                        nonce: &secretbox::Nonce) -> Vec<u8> {
    let plaintext_bytes = plaintext.as_bytes();
    return secretbox::seal(&plaintext_bytes, &nonce, &key);
}

pub fn decrypt_password(ciphertext: &Vec<u8>, key: &secretbox::Key,
                        nonce: &secretbox::Nonce) -> Result<String, ()> {
    let decrypted = try!(secretbox::open(&ciphertext, &nonce, &key));
    match String::from_utf8(decrypted) {
        Ok(decrypted_text) => Ok(decrypted_text),
        Err(_) => Err(())
    }
}

pub fn create_encrypted_password(master_password: &str) -> Result<PasswordData, ()> {
    let plaintext_password = generate_password();

    let salt = pwhash::gen_salt();
    let key = try!(get_key(master_password, salt));

    let nonce = secretbox::gen_nonce();
    let encrypted_password = encrypt_password(&plaintext_password, &key, &nonce);

    let secretbox::Nonce(nonce_bytes) = nonce;
    let pwhash::Salt(salt_bytes) = salt;
    Ok(PasswordData::new(encrypted_password, salt_bytes.to_vec(), nonce_bytes.to_vec()))
}

#[cfg(test)]
mod test {
    use super::{get_key, encrypt_password, decrypt_password};
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
            let key = get_key(password, key_salt).unwrap();
            encrypted = encrypt_password(plaintext, &key, &nonce);
        }
        let key = get_key(password, key_salt).unwrap();
        let decrypted = decrypt_password(&encrypted, &key, &nonce)
            .unwrap();
        assert_eq!(plaintext.to_string(), decrypted);
    }

}

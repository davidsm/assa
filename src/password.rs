use sodiumoxide::randombytes::randombytes;
use rustc_serialize::base64;
use rustc_serialize::base64::{ToBase64};

use serialize::BinaryData;
use crypto::SALTBYTES;
use crypto::NONCEBYTES;

const PASSWORD_BYTES_LENGTH: usize = 15;


#[derive(RustcDecodable, RustcEncodable, Debug, PartialEq)]
pub struct PasswordData {
    pub nonce: BinaryData<[u8; NONCEBYTES]>,
    pub salt: BinaryData<[u8; SALTBYTES]>,
    pub password: BinaryData<Vec<u8>>
}

impl PasswordData {
    pub fn new(password: Vec<u8>, salt: [u8; SALTBYTES], nonce: [u8; NONCEBYTES]) -> PasswordData {
        PasswordData {
            password: BinaryData(password),
            salt: BinaryData(salt),
            nonce: BinaryData(nonce)
        }
    }

    pub fn password(&self) -> &[u8] {
        let BinaryData(ref pw) = self.password;
        pw
    }

    pub fn salt(&self) -> [u8; SALTBYTES] {
        let BinaryData(ref salt) = self.salt;
        salt.clone()
    }

    pub fn nonce(&self) -> [u8; NONCEBYTES] {
        let BinaryData(ref nonce) = self.nonce;
        nonce.clone()
    }
}

pub fn generate_password() -> String {
    // Create a random string by base64-encoding
    // randomly generated bytes for now
    //
    // TODO: Do this in a better manner when I've figured out
    // a good way. Should probably include more characters than
    // the ones used for base64-encoding
    let random_bytes = randombytes(PASSWORD_BYTES_LENGTH);
    random_bytes.to_base64(base64::STANDARD)
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_generate_password() {
        // Just test that we get a password
        // of length PASSWORD_BYTES_LENGTH / 0.75 = 20, which
        // is the expected result if everything works as expected
        let password = generate_password();
        assert_eq!(password.len(), 20);
    }
}

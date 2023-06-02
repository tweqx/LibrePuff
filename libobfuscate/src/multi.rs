// Copyright 2023 tweqx

// This file is part of LibrePuff.
//
// LibrePuff is free software: you can redistribute it and/or modify it
// under the terms of the GNU General Public License as published by the Free
// Software Foundation, either version 3 of the License, or (at your option) any
// later version.
//
// LibrePuff is distributed in the hope that it will be useful, but WITHOUT ANY
// WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
// A PARTICULAR PURPOSE. See the GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with LibrePuff. If not, see <https://www.gnu.org/licenses/>.

use std::{mem, ptr};

use crate::bindings::*;
use crate::{to_password_buffer, Error};

/// Initialization vector
pub type Iv = [u8; DATA_BLOCK_SIZE as usize];

/// Initialization vectors for different cryptographic primitives
#[derive(Default, Debug, Copy, Clone)]
#[repr(C)]
pub struct Ivs {
    pub anubis: Iv,
    pub camellia: Iv,
    pub cast256: Iv,
    pub clefia: Iv,
    pub frog: Iv,
    pub hierocrypt3: Iv,
    pub idea_nxt128: Iv,
    pub mars: Iv,
    pub rc6: Iv,
    pub rijndael: Iv,
    pub saferp: Iv,
    pub sc2000: Iv,
    pub serpent: Iv,
    pub speed: Iv,
    pub twofish: Iv,
    pub unicorn_a: Iv,
}

impl Ivs {
    pub fn from_bytes(source: &[u8; (MAX_ALG * DATA_BLOCK_SIZE) as usize]) -> &Ivs {
        unsafe { mem::transmute(source) }
    }
    pub fn as_bytes(&self) -> &[u8; (MAX_ALG * DATA_BLOCK_SIZE) as usize] {
        unsafe { mem::transmute(self) }
    }
}

/// Wrapper around libObfuscate's `MULTI_DATA`
///
/// The object's state cannot be reset. As a result, calling `decrypt` after having called
/// `encrypt` won't give back the original data.
pub struct Multi(MULTI_DATA);

impl Multi {
    /// Creates a new `Multi`.
    pub fn new(ivs: &Ivs, password_1: &str, password_2: &str, nonce: u32) -> Result<Self, Error> {
        let max_length = MAX_PASSW_SIZE as usize;
        if password_1.len() > max_length || password_2.len() > max_length {
            return Err(Error::PasswordTooLong);
        }
        let password_1 = to_password_buffer(password_1)?;
        let password_2 = to_password_buffer(password_2)?;

        let mut multi = Multi(unsafe { mem::zeroed() });

        unsafe {
            Multi_setkey(
                &mut multi.0 as *mut MULTI_DATA,
                ivs.as_bytes().as_ptr(),
                password_1.as_ptr(),
                password_2.as_ptr(),
                nonce,
            );
        }

        Ok(multi)
    }

    /// Encrypts `data`.
    ///
    /// # Panics
    ///
    /// Panics if the length of `data` does not fit in a `u32`.
    pub fn encrypt(&mut self, data: &mut [u8]) {
        let len = u32::try_from(data.len()).unwrap();

        unsafe {
            Multi_CBC_encrypt(
                &mut self.0 as *mut MULTI_DATA,
                len,
                data.as_mut_ptr(),
                None,
                ptr::null_mut(),
                None,
                ptr::null_mut(),
            );
        }
    }

    /// Decrypts `data`.
    ///
    /// # Panics
    ///
    /// Panics if the length of `data` does not fit in a `u32`.
    pub fn decrypt(&mut self, data: &mut [u8]) {
        let len = u32::try_from(data.len()).unwrap();

        unsafe {
            Multi_CBC_decrypt(
                &mut self.0 as *mut MULTI_DATA,
                len,
                data.as_mut_ptr(),
                None,
                ptr::null_mut(),
                None,
                ptr::null_mut(),
            );
        }
    }
}

/// Encrypts `data`.
pub fn encrypt(
    data: &mut [u8],
    ivs: &Ivs,
    password_1: &str,
    password_2: &str,
    nonce: u32,
) -> Result<(), Error> {
    let mut multi = Multi::new(ivs, password_1, password_2, nonce)?;
    multi.encrypt(data);
    Ok(())
}

/// Decrypts `data`.
pub fn decrypt(
    data: &mut [u8],
    ivs: &Ivs,
    password_1: &str,
    password_2: &str,
    nonce: u32,
) -> Result<(), Error> {
    let mut multi = Multi::new(ivs, password_1, password_2, nonce)?;
    multi.decrypt(data);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypt_decrypt() {
        let mut buffer = [51u8; 32];
        let ivs = Default::default();

        encrypt(&mut buffer, &ivs, "testpass1", "password2", 2023).unwrap();
        assert_eq!(
            buffer,
            [
                248, 175, 201, 135, 113, 165, 88, 220, 59, 250, 187, 253, 33, 80, 211, 38, 130,
                159, 146, 77, 198, 71, 19, 197, 54, 154, 108, 199, 65, 92, 127, 116
            ]
        );

        decrypt(&mut buffer, &ivs, "testpass1", "password2", 2023).unwrap();
        assert_eq!(buffer, [51u8; 32]);
    }
}

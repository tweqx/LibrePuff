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

pub enum Hash {
    Sha512,
    Grostl512,
    Keccak512,
    Skein512,
}

/// Wrapper around libObfuscate's `CSPRNG_DATA`
pub struct Csprng(CSPRNG_DATA);

impl Csprng {
    /// Creates a new `Csprng`. It will initialized using a random seed.
    pub fn new() -> Self {
        let mut csprng = Csprng(unsafe { mem::zeroed() });

        unsafe {
            CSPRNG_autoseed(&mut csprng.0 as *mut CSPRNG_DATA, None, ptr::null_mut());
        }

        csprng
    }

    /// Creates a new `Csprng` seeded using `password`, `nonce` and `hash`
    pub fn new_with_seed(hash: Hash, password: &str, nonce: u32) -> Result<Self, Error> {
        if password.len() > MAX_PASSW_SIZE as usize {
            return Err(Error::PasswordTooLong);
        }
        let password = to_password_buffer(password)?;

        let mut csprng = Csprng(unsafe { mem::zeroed() });

        let hash = match hash {
            Hash::Sha512 => ENUM_HASH_SHA512_HASH,
            Hash::Grostl512 => ENUM_HASH_GROSTL512_HASH,
            Hash::Keccak512 => ENUM_HASH_KECCAK512_HASH,
            Hash::Skein512 => ENUM_HASH_SKEIN512_HASH,
        };

        unsafe {
            CSPRNG_set_seed(
                &mut csprng.0 as *mut CSPRNG_DATA,
                hash,
                mem::transmute(password.as_ptr()),
                nonce,
            );
        }

        Ok(csprng)
    }

    /// Returns a cryptographically-secure random byte.
    pub fn get_byte(&mut self) -> u8 {
        unsafe { CSPRNG_get_byte(&mut self.0 as *mut CSPRNG_DATA) }
    }

    /// Returns a cryptographically-secure random byte.
    pub fn get_word(&mut self) -> u16 {
        unsafe { CSPRNG_get_word(&mut self.0 as *mut CSPRNG_DATA) }
    }

    /// Returns a cryptographically-secure random byte.
    pub fn get_dword(&mut self) -> u32 {
        unsafe { CSPRNG_get_dword(&mut self.0 as *mut CSPRNG_DATA) }
    }

    /// Randomizes `buffer`.
    ///
    /// # Panics
    ///
    /// Panics if the length of `buffer` doesn't fit in a `u32`.
    pub fn randomize(&mut self, buffer: &mut [u8]) {
        let len = u32::try_from(buffer.len()).unwrap();

        unsafe {
            CSPRNG_randomize(
                &mut self.0 as *mut CSPRNG_DATA,
                len,
                buffer.as_mut_ptr(),
                None,
                ptr::null_mut(),
                None,
                ptr::null_mut(),
            );
        }
    }

    /// Initializes `buffer` as a permutation.
    ///
    /// # Panics
    ///
    /// Panics if the length of `buffer` exceeds 255.
    pub fn randomize_permutation(&mut self, buffer: &mut [u8]) {
        let len = u32::try_from(buffer.len()).unwrap();

        unsafe {
            CSPRNG_array_init(&mut self.0 as *mut CSPRNG_DATA, len, buffer.as_mut_ptr());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn set_seed() {
        let mut csprng = Csprng::new_with_seed(Hash::Sha512, "password", 0x1234).unwrap();

        let mut data = [0u8; 32];
        csprng.randomize(&mut data);

        assert_eq!(
            data,
            [
                172, 204, 233, 30, 154, 246, 92, 90, 94, 189, 31, 247, 50, 220, 59, 160, 216, 196,
                36, 151, 113, 176, 27, 173, 43, 130, 212, 60, 50, 144, 238, 227
            ]
        );
    }
}

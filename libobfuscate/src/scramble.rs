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

/// Wrapper around libObfuscate's `SCRAMBLE_DATA`.
pub struct Scramble {
    data: SCRAMBLE_DATA,
    block_size: usize,
}

impl Scramble {
    /// Creates a new `Scramble`.
    ///
    /// # Panics
    ///
    /// Panics if `block_size` does not fit in a `u32`.
    pub fn new(block_size: usize, password: &str, nonce: u32) -> Result<Self, Error> {
        if password.len() > MAX_PASSW_SIZE as usize {
            return Err(Error::PasswordTooLong);
        }
        let password = to_password_buffer(password)?;

        let mut scramble = Scramble {
            data: unsafe { mem::zeroed() },
            block_size,
        };

        unsafe {
            Scramble_seed(
                &mut scramble.data as *mut SCRAMBLE_DATA,
                block_size.try_into().unwrap(),
                password.as_ptr(),
                nonce,
            );
        }

        Ok(scramble)
    }

    /// Scrambles `data`, a slice of `u8`s.
    ///
    /// # Panics
    ///
    /// Panics if the length of `data` differs from the block size specified during construction.
    pub fn scramble(&mut self, block: &mut [u8]) {
        assert_eq!(self.block_size, block.len());

        unsafe {
            Seg_scramble(
                &mut self.data as *mut SCRAMBLE_DATA,
                block.as_mut_ptr(),
                None,
                ptr::null_mut(),
                None,
                ptr::null_mut(),
            );
        }
    }

    /// Descrambles `block`, a slice of `u8`s.
    ///
    /// # Panics
    ///
    /// Panics if the length of `block` differs from the block size specified during construction.
    pub fn descramble(&mut self, block: &mut [u8]) {
        assert_eq!(self.block_size, block.len());

        unsafe {
            Seg_descramble(
                &mut self.data as *mut SCRAMBLE_DATA,
                block.as_mut_ptr(),
                None,
                ptr::null_mut(),
                None,
                ptr::null_mut(),
            );
        }
    }
}

impl Drop for Scramble {
    fn drop(&mut self) {
        unsafe {
            Scramble_end(&mut self.data as *mut SCRAMBLE_DATA);
        }
    }
}

/// Scrambles `data`.
pub fn scramble(data: &mut [u8], password: &str, nonce: u32) -> Result<(), Error> {
    let mut scrambler = Scramble::new(data.len(), password, nonce)?;
    scrambler.scramble(data);
    Ok(())
}
/// Descrambles `data`.
pub fn descramble(data: &mut [u8], password: &str, nonce: u32) -> Result<(), Error> {
    let mut scrambler = Scramble::new(data.len(), password, nonce)?;
    scrambler.descramble(data);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scramble_descramble() {
        let mut scrambler = Scramble::new(10, "testpassword1", 13).unwrap();

        const TEST_ARRAY: [u8; 10] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
        let mut data = TEST_ARRAY;
        scrambler.scramble(&mut data);
        assert_eq!(data, [9, 3, 2, 6, 1, 5, 7, 8, 4, 10]);
        scrambler.descramble(&mut data);
        assert_eq!(data, TEST_ARRAY);
    }
}

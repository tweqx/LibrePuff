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

#[allow(non_upper_case_globals)]
#[allow(non_camel_case_types)]
#[allow(non_snake_case)]
#[allow(unused)]
mod bindings {
    include!(concat!(env!("OUT_DIR"), "/bindings.rs"));
}

use std::ffi::{CString, NulError};

#[derive(Debug)]
pub enum Error {
    PasswordTooLong,
    ContainsNulByte,
}
impl From<NulError> for Error {
    fn from(_value: NulError) -> Self {
        Error::ContainsNulByte
    }
}

/// Returns a password buffer from a string slice.
///
/// # Panics
///
/// Panics if `password.len() >= MAX_PASSW_SIZE`
fn to_password_buffer(password: &str) -> Result<Vec<u8>, Error> {
    let password = CString::new(password)?;
    let mut password = Vec::from(password.as_bytes());
    password.resize(bindings::MAX_PASSW_SIZE as usize, 0);
    Ok(password)
}

pub mod csprng;
pub mod multi;
pub mod scramble;

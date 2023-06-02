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

#![feature(buf_read_has_data_left)]

use std::error;
use std::fmt::{self, Display};
use std::io;

pub mod bit_selection;
pub mod carrier;
pub mod carrier_type;
pub mod chain;
pub mod crc32;
pub mod embedded_file;
mod parser;
pub mod passwords;

use parser::ParsingError;

#[derive(Debug)]
pub enum Error {
    IoError(io::Error),
    UnknownFiletype,
    CarrierTooSmall,
    PasswordTooLong,
}
impl Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::IoError(err) => write!(f, "I/O error: {err}"),
            Self::UnknownFiletype => write!(f, "unknown file type"),
            Self::CarrierTooSmall => write!(f, "carrier too small"),
            Self::PasswordTooLong => write!(f, "password is longer than 32 characters"),
        }
    }
}
impl From<io::Error> for Error {
    fn from(error: io::Error) -> Error {
        Self::IoError(error)
    }
}
impl From<ParsingError> for Error {
    fn from(error: ParsingError) -> Error {
        match error {
            ParsingError::InvalidFormat => Self::UnknownFiletype,
            ParsingError::IoError(error) => Self::IoError(error),
        }
    }
}
impl error::Error for Error {}

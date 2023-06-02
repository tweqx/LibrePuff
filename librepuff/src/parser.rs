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

use std::io::{self, ErrorKind};

#[derive(Debug)]
pub enum ParsingError {
    InvalidFormat,
    IoError(io::Error),
}
impl From<io::Error> for ParsingError {
    fn from(error: io::Error) -> Self {
        match error.kind() {
            // When parsing a file, an unhandled EOF is a parsing error
            ErrorKind::UnexpectedEof => ParsingError::InvalidFormat,

            _ => ParsingError::IoError(error),
        }
    }
}

/// Parsing modules for the different file types.
///
/// Each module exports a `parse(mut reader: &mut impl Read)` function,
/// which returns a `Result<BitVec, ParsingError>`.
/// Each parser must strictly only read bytes part of the file format.
/// This allows users of this module to tell if a file has trailing data, for instance.
pub mod wav;


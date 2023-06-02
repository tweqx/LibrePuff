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

use byteorder::{LittleEndian, ReadBytesExt};
use std::io::Cursor;

use crate::crc32;

#[derive(Debug)]
pub struct EmbeddedFile<'a> {
    pub filename: &'a [u8],
    pub content: &'a [u8],
    pub crc32: u32,

    pub remaining_bytes: &'a [u8],
}

const HEADER_SIZE: usize = 10;

impl<'a> EmbeddedFile<'a> {
    // TODO: maybe extract this function out of the impl
    pub fn from_bits(bits: &'a [u8]) -> Option<Self> {
        if bits.len() < HEADER_SIZE {
            return None;
        }

        let mut cursor = Cursor::new(bits);

        // Header
        let filename_length = cursor.read_u16::<LittleEndian>().unwrap() as usize;
        let content_size = cursor.read_u32::<LittleEndian>().unwrap() as usize;
        let crc32 = cursor.read_u32::<LittleEndian>().unwrap();

        let size_needed = HEADER_SIZE + content_size + filename_length;
        if size_needed > bits.len() {
            return None;
        }

        // Filename
        let filename_offset = HEADER_SIZE;
        let filename = &bits[filename_offset..(filename_offset + filename_length)];

        // Content
        let content_offset = filename_offset + filename_length;
        let content = &bits[content_offset..(content_offset + content_size)];

        let computed_crc32 = crc32::compute(&content);
        if crc32 != computed_crc32 {
            return None;
        }

        let remaining_bytes = &bits[(content_offset + content_size)..];

        Some(EmbeddedFile {
            filename,
            content,
            crc32,

            remaining_bytes,
        })
    }
}

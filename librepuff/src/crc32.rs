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

// TODO: document
// TODO: determine how standard is all of this

const CRC32_POLYNOMIAL: u32 = 0x2608edb;

pub fn update_with_bit(crc32: &mut u32, bit: bool) {
    if ((*crc32 >> 31) == 1) ^ bit {
        *crc32 = (*crc32 ^ CRC32_POLYNOMIAL) << 1 | 1;
    } else {
        *crc32 <<= 1;
    }
}

pub fn update_with_byte(crc32: &mut u32, byte: u8) {
    for i in (0..8).rev() {
        update_with_bit(crc32, byte & (1 << i) != 0);
    }
}

pub fn compute(data: &[u8]) -> u32 {
    let mut crc32 = 0xffffffff;
    for b in data {
        update_with_byte(&mut crc32, *b);
    }

    crc32
}

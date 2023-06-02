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

use bit_vec::BitVec;
use libobfuscate::csprng::{self, Csprng};
use log::warn;
use std::fs::File;
use std::io::{BufRead, BufReader, Read};
use std::path::Path;

use crate::bit_selection::BitSelection;
use crate::carrier_type::CarrierType;
use crate::crc32;
use crate::parser;
use crate::Error;

fn generate_whitening_lookup_table(seed: usize) -> [u8; 1 << 13] {
    let mut csprng = Csprng::new_with_seed(
        csprng::Hash::Skein512,
        &format!("{:010}", seed),
        seed as u32,
    )
    .unwrap();

    let mut bit_mask = [0u32; 13];
    let mut index = 0;
    while index < 13 {
        let bit_mask_index = (csprng.get_dword() % 13) as usize;

        if bit_mask[bit_mask_index] == 0 {
            bit_mask[bit_mask_index] = 1 << (index & 0b11111);
            index += 1;
        }
    }

    let bit_assembly_order: [u32; 6] = match csprng.get_byte() % 20 {
        00 => [1 << 00, 1 << 02, 1 << 13, 1 << 17, 1 << 19, 1 << 28],
        01 => [1 << 00, 1 << 04, 1 << 11, 1 << 16, 1 << 18, 1 << 28],
        02 => [1 << 00, 1 << 04, 1 << 12, 1 << 18, 1 << 26, 1 << 28],
        03 => [1 << 00, 1 << 07, 1 << 11, 1 << 12, 1 << 14, 1 << 16],
        04 => [1 << 01, 1 << 04, 1 << 11, 1 << 15, 1 << 26, 1 << 28],
        05 => [1 << 01, 1 << 04, 1 << 11, 1 << 15, 1 << 26, 1 << 30],
        06 => [1 << 01, 1 << 04, 1 << 11, 1 << 15, 1 << 27, 1 << 30],
        07 => [1 << 01, 1 << 04, 1 << 11, 1 << 26, 1 << 27, 1 << 30],
        08 => [1 << 01, 1 << 12, 1 << 16, 1 << 18, 1 << 26, 1 << 31],
        09 => [1 << 02, 1 << 03, 1 << 10, 1 << 12, 1 << 27, 1 << 31],
        10 => [1 << 02, 1 << 08, 1 << 10, 1 << 12, 1 << 27, 1 << 31],
        11 => [1 << 02, 1 << 13, 1 << 16, 1 << 17, 1 << 27, 1 << 30],
        12 => [1 << 03, 1 << 10, 1 << 12, 1 << 17, 1 << 27, 1 << 31],
        13 => [1 << 04, 1 << 11, 1 << 15, 1 << 18, 1 << 26, 1 << 28],
        14 => [1 << 04, 1 << 11, 1 << 15, 1 << 26, 1 << 27, 1 << 30],
        15 => [1 << 08, 1 << 10, 1 << 14, 1 << 15, 1 << 23, 1 << 27],
        16 => [1 << 08, 1 << 12, 1 << 20, 1 << 22, 1 << 24, 1 << 31],
        17 => [1 << 10, 1 << 14, 1 << 15, 1 << 23, 1 << 26, 1 << 29],
        18 => [1 << 11, 1 << 15, 1 << 18, 1 << 26, 1 << 27, 1 << 29],
        19 => [1 << 11, 1 << 17, 1 << 19, 1 << 27, 1 << 28, 1 << 30],
        _ => unreachable!(),
    };

    let mut whitening_table = [0u8; 1 << 13];
    for i in 0..(1 << 13) {
        // Computing the CRC32 of the bits of i, in a custom order, using the polynomial 0x2608edb
        // TODO: is it really standard?
        let mut crc32: u32 = 0xffffffff;
        for j in 0..13 {
            let bit = i & bit_mask[j] != 0;
            crc32::update_with_bit(&mut crc32, bit);
        }

        // Selects bits
        let mut value = 0u8;
        for j in 0..6 {
            if crc32 & bit_assembly_order[j] != 0 {
                value |= 1 << j;
            }
        }

        whitening_table[i as usize] = value;
    }

    whitening_table
}

type EncryptedIv = [u8; 256];

#[derive(Debug, PartialEq)]
pub struct EncryptedCarrier {
    // TODO: document fields
    pub iv: EncryptedIv,

    pub data: Vec<u8>,
    pub decoy: Vec<u8>,

    pub other_bits: BitVec,
}
impl EncryptedCarrier {
    /// Returns the number of data or decoy bits selected in this carrier.
    pub fn selected_bit_count(&self) -> usize {
        self.data.len()
    }
}

pub fn from_file(path: &Path, selection_level: BitSelection) -> Result<EncryptedCarrier, Error> {
    let file = File::open(path)?;

    // Detect file type
    //
    // Compatiblity note: OpenPuff determines the file format solely based on the file
    // extension. See `CarrierType::from_extension` for the list of recognized extensions.
    let extension = path.extension().ok_or(Error::UnknownFiletype)?;
    let extension = extension.to_str().ok_or(Error::UnknownFiletype)?;
    let file_type = CarrierType::from_extension(extension).ok_or(Error::UnknownFiletype)?;

    let mut reader = BufReader::new(file);
    let carrier = from_reader(&mut reader, file_type, selection_level)?;

    // Oddities detection - not present in OpenPuff
    if reader.has_data_left()? {
        warn!("{} has trailing data", path.display());
    }

    Ok(carrier)
}

pub fn from_reader(
    reader: &mut impl Read,
    file_type: CarrierType,
    selection_level: BitSelection,
) -> Result<EncryptedCarrier, Error> {
    // TODO: what about add_carriers' first parameter?
    let whitened_bits = match file_type {
        CarrierType::Wav => parser::wav::parse(reader),
        _ => unimplemented!(), // TODO
    }?;

    let whitening_lookup_table = generate_whitening_lookup_table(whitened_bits.len());

    let mut unwhitened_bits = BitVec::new();
    for chunk_index in 0..(whitened_bits.len() / 13) {
        let mut chunk: u16 = 0;
        for j in 0..13 {
            chunk <<= 1;
            if whitened_bits[13 * chunk_index + j] {
                chunk |= 1;
            }
        }

        let unwhitened_chunk = whitening_lookup_table[chunk as usize];
        for j in (0..6).rev() {
            unwhitened_bits.push(unwhitened_chunk & (1 << j) != 0);
        }
    }
    // TODO: should we warn about the %13 bits remaining ?

    // TODO: explain the magic constant 2984
    // TODO: find a way to read `selected_bit_count` bits more naturally
    const MAGIC_VALUE: usize = 2984;
    if unwhitened_bits.len() < MAGIC_VALUE {
        return Err(Error::CarrierTooSmall);
    }
    let selected_bit_count =
        ((unwhitened_bits.len() - MAGIC_VALUE) / selection_level.divisor()) & !0b1111111;

    let mut bits_iter = unwhitened_bits.into_iter();

    // The first 256 bytes is an encrypted IV used to encrypt the data.
    let encrypted_iv_bits: BitVec = (&mut bits_iter).take(8 * 256).collect();

    // Then, one bit out of `selection_level.divisor()` is used for the hidden file,
    // one bit is used for the decoy file and the others are skipped.
    let mut data_bits = BitVec::new();
    let mut decoy_bits = BitVec::new();
    let mut other_bits = BitVec::new();

    for (i, bit) in bits_iter
        .take((selected_bit_count - 1) * selection_level.divisor() + 2)
        .enumerate()
    {
        let i = i % selection_level.divisor();

        if i == 0 {
            data_bits.push(bit);
        } else if i == 1 {
            decoy_bits.push(bit);
        } else {
            // Filler bits, ignored by OpenPuff
            other_bits.push(bit);
        }
    }

    // Note: nothing can be decrypted yet, as the decryption key depends on the other carriers.

    let mut encrypted_iv = [0u8; 256];
    for (i, bit) in encrypted_iv_bits.iter().enumerate() {
        encrypted_iv[i / 8] <<= 1;
        if bit {
            encrypted_iv[i / 8] |= 1;
        }
    }

    fn pack_bits(bits: BitVec) -> Vec<u8> {
        let mut bytes = Vec::new();
        // TODO: check for correctness
        bytes.resize((bits.len() + 7) / 8, 0);

        for (i, bit) in bits.iter().enumerate() {
            bytes[i / 8] <<= 1;
            if bit {
                bytes[i / 8] |= 1;
            }
        }

        bytes
    }

    Ok(EncryptedCarrier {
        iv: encrypted_iv,

        data: pack_bits(data_bits),
        decoy: pack_bits(decoy_bits),

        other_bits,
    })
}

#[cfg(test)]
// TODO
mod tests {
    use super::*;
    use crate::bit_selection::BitSelection;
    use std::io;

    #[test]
    fn carrier_not_existing() {
        let does_not_exist = Path::new("./does/not/exist.png");
        let result = from_file(does_not_exist, BitSelection::Medium);

        match result {
            Err(Error::IoError(e)) if e.kind() == io::ErrorKind::NotFound => {}
            _ => panic!(),
        }
    }

    #[test]
    fn carrier_no_file_extension() {}
}

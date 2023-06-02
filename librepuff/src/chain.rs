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

use libobfuscate::{multi, scramble};

use crate::carrier::EncryptedCarrier;
use crate::passwords::Passwords;

fn derive_next_prekey(previous_prekey: u16, previous_iv: &[u8; 256]) -> u16 {
    let function_of_iv = previous_iv
        .iter()
        .map(|&iv_value| {
            if iv_value & 1 == 1 {
                (iv_value as u16) << 8
            } else {
                iv_value as u16
            }
        })
        .sum::<u16>();

    previous_prekey + function_of_iv
}

fn derive_key(carrier_position: usize, prekey: u16) -> u32 {
    let carrier_position = u32::try_from(carrier_position).unwrap();
    let prekey = u32::from(prekey);

    prekey * 0x10000 + 0x502239c3 + carrier_position
}

/// IVs used to decrypt carrier IVs.
const INITIALIZATION_VECTORS: multi::Ivs = multi::Ivs {
    anubis: *b"\xcd\xa0\x11\xe5\x83\x82\xe5\xb2\x84\x63\x9e\xc6\x49\x54\xdd\xd7",
    camellia: *b"\x2f\xf4\x8b\x66\x58\xf7\x4b\x66\x19\x10\xf2\x05\x86\x51\x07\x64",
    cast256: *b"\x0e\x81\xa1\x07\x19\xd1\x9e\x96\x51\xc7\x5a\xf3\xca\x72\x4a\x43",
    clefia: *b"\x75\xd3\x57\xc7\x62\x97\x26\xb4\x07\x85\x3f\xf4\x99\xf4\x88\x71",
    frog: *b"\xa7\x87\x66\xd7\x67\xc4\x87\x74\xdc\x85\x1f\xc2\xf8\xa2\x74\xc4",
    hierocrypt3: *b"\x98\x74\x7b\xe0\xb1\x00\x49\xc0\xce\x46\xa8\x34\xee\xd0\x47\x46",
    idea_nxt128: *b"\x85\xe7\x8b\xd1\xba\xa1\x98\x04\x8f\xe2\x10\x16\x59\xa3\x2c\x76",
    mars: *b"\xcd\x64\x90\x46\x94\xd5\x0a\x85\x00\x56\x4a\x96\x1a\xf2\x16\xe2",
    rc6: *b"\xa6\xd1\xfe\x45\xe0\xd6\x65\x10\x18\x42\xb2\x97\xe1\x66\x52\xe2",
    rijndael: *b"\x2d\xa3\xb3\x64\x3e\xc3\x4f\x52\x69\xc7\x46\x81\x94\x62\xb5\x75",
    saferp: *b"\xd8\x30\xee\x85\xd0\x21\xbd\x24\xe1\x44\x3c\xc4\x73\x77\x0a\xd2",
    sc2000: *b"\x3a\xc0\x63\xd1\xa1\x22\x58\x90\x13\x36\x9d\xf0\x98\x06\x07\xf1",
    serpent: *b"\x1c\x43\x55\xf5\xf6\xf7\x21\xd0\x40\x27\x09\x25\x2f\x71\xd2\x31",
    speed: *b"\xa5\x22\x6a\xc6\x91\x47\x66\xc3\xe7\x25\xc6\x26\x17\xe1\x7a\xf3",
    twofish: *b"\xd7\xd5\xc0\x06\xa9\x21\xf6\x14\x7e\x14\x64\x83\x1c\x15\xab\x32",
    unicorn_a: *b"\xc0\x66\xb8\x23\xc0\xf6\xdf\x62\xa7\xc7\x60\x37\x88\xd1\xef\x95",
};
fn decrypt_iv(iv: &mut [u8; 256], key: u32) {
    let password = &format!("{key:010}");
    scramble::descramble(iv, password, key).unwrap();
    multi::decrypt(iv, &INITIALIZATION_VECTORS, password, password, key).unwrap();
}

fn decrypt_content(content: &mut [u8], ivs: &multi::Ivs, key: u32, passwords: &Passwords) {
    scramble::descramble(content, &passwords.c, key).unwrap();
    multi::decrypt(content, ivs, &passwords.a, &passwords.b, key).unwrap();
}

pub struct CarrierEmbeddings {
    pub data: Vec<u8>,
    pub decoy: Vec<u8>,
}

pub fn decrypt_carrier_chain(
    carriers: impl IntoIterator<Item = EncryptedCarrier>,
    passwords: Passwords,
) -> Vec<CarrierEmbeddings> {
    let mut embeddings = Vec::new();

    let mut previous_parameters: Option<(u16, [u8; 256])> = None;

    for (i, encrypted_carrier) in carriers.into_iter().enumerate() {
        // A prekey is refered as a function of the previous carriers.
        // The first carrier's prekey is 0; for the following ones the decrypted IVs are also
        // taken into consideration.
        let prekey = match previous_parameters {
            None => 0,
            Some((prekey, iv)) => derive_next_prekey(prekey, &iv),
        };

        let key = derive_key(i, prekey);

        // Decrypts the IV
        let mut iv: [u8; 256] = encrypted_carrier.iv;
        decrypt_iv(&mut iv, key);

        let ivs = multi::Ivs::from_bytes(&iv);

        // Decrypt the two contents
        let mut data: Vec<u8> = encrypted_carrier.data;
        decrypt_content(&mut data, ivs, key, &passwords);

        let mut decoy: Vec<u8> = encrypted_carrier.decoy;
        decrypt_content(&mut decoy, ivs, key, &passwords);

        embeddings.push(CarrierEmbeddings { data, decoy });

        previous_parameters = Some((prekey, iv));
    }

    embeddings
}

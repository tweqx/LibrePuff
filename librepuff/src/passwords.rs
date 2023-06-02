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

use log::warn;
use std::cmp::max;

use crate::Error;

/// Computes the hamming distance between `password_1` and `password_2`, returning a percentage
/// where 100 corresponds to `password_1` and `password_2` being the most different as possible.
fn compute_hamming_distance(password_1: &[u8], password_2: &[u8]) -> usize {
    let total = max(password_1.len(), password_2.len());

    let mut differences: usize = 0;
    for i in 0..total {
        let c1 = if i < password_1.len() {
            password_1[i]
        } else {
            0
        };
        let c2 = if i < password_2.len() {
            password_2[i]
        } else {
            0
        };

        differences += (c1 ^ c2).count_ones() as usize;
    }

    (differences * 100) / (total * 8)
}

#[derive(Debug)]
pub struct Passwords<'a> {
    /// Password A. Used for multi-cryptography.
    pub a: &'a str,
    /// Password B. Used for multi-cryptography.
    pub b: &'a str,
    /// Password C. Used for scrambling.
    pub c: &'a str,
}
impl<'a> Passwords<'a> {
    /// TODO: be more consistent with when to warn
    pub fn from_fields(a: &'a str, b: Option<&'a str>, c: Option<&'a str>) -> Result<Self, Error> {
        if !c.is_none() && b.is_none() {
            warn!("password B not specified while password C is, this would be impossible in OpenPuff");
        }

        // Length checks
        if let Some(b) = b {
            if b.len() < 8 {
                warn!("password B is less than 8 characters long, OpenPuff wouldn't allow this");
            }
            if b.len() > 32 {
                return Err(Error::PasswordTooLong);
            }
        }
        if let Some(c) = c {
            if c.len() < 8 {
                warn!("password C is less than 8 characters long, OpenPuff wouldn't allow this");
            }
            if c.len() > 32 {
                return Err(Error::PasswordTooLong);
            }
        }

        // Distance checks
        if let Some(b) = b {
            let distance_ab = compute_hamming_distance(a.as_bytes(), b.as_bytes());
            if distance_ab < 25 {
                warn!("passwords A and B are too correlated (distance of {distance_ab}% < 25%), OpenPuff would complain.");
            }
        }
        if let Some(c) = c {
            let distance_ac = compute_hamming_distance(a.as_bytes(), c.as_bytes());
            if distance_ac < 25 {
                warn!("passwords A and C are too correlated (distance of {distance_ac}% < 25%), OpenPuff would complain.");
            }
        }
        if let Some(b) = b {
            if let Some(c) = c {
                let distance_bc = compute_hamming_distance(b.as_bytes(), c.as_bytes());
                if distance_bc < 25 {
                    warn!("passwords B and C are too correlated (distance of {distance_bc}% < 25%), OpenPuff would complain.");
                }
            }
        }

        // If password B or C aren't specified, they default to password A.
        let mut passwords = Passwords { a: a, b: a, c: a };
        if let Some(b) = b {
            passwords.b = b;
        }
        if let Some(c) = c {
            passwords.c = c;
        }

        Ok(passwords)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hamming_distances() {
        assert_eq!(compute_hamming_distance(b"testtest", b"testtest"), 0);
        assert_eq!(compute_hamming_distance(b"aaaaaaaa", b"aaaaaaab"), 3);
        assert_eq!(compute_hamming_distance(b"aaaaaaaa", b"raaaaaab"), 7);
        assert_eq!(compute_hamming_distance(b"aaaaaaaa", b"12345678"), 45);
        assert_eq!(compute_hamming_distance(b"aaaaaaaa", b"aaaaaaaaa"), 4);
        assert_eq!(compute_hamming_distance(b"aaaaaaaa", b"aaaaaaaaaaa"), 10);
        assert_eq!(
            compute_hamming_distance(b"aaaaaaaa", b"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
            21
        );
        assert_eq!(
            compute_hamming_distance(
                b"01234567890123456789012345678901",
                b"012345678901234567890123456789"
            ),
            1
        );
    }
}

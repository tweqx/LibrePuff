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

/// Corresponds to OpenPuff's bit selection level.
#[derive(Debug, PartialEq, Eq)]
pub enum BitSelection {
    Minimum,
    VeryLow,
    Low,
    Medium,
    High,
    VeryHigh,
    Maximum,
}

impl Default for BitSelection {
    fn default() -> Self {
        // OpenPuff's default
        Self::Medium
    }
}

impl BitSelection {
    /// Returns the density of bits to select, ie. the ratio of selected bits to data bits.
    /// (Or decoy bits).
    pub fn divisor(&self) -> usize {
        match self {
            Self::Minimum => 8,
            Self::VeryLow => 7,
            Self::Low => 6,
            Self::Medium => 5,
            Self::High => 4,
            Self::VeryHigh => 3,
            Self::Maximum => 2,
        }
    }
}

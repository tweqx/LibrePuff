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

use std::fmt;

#[derive(Debug, Eq, PartialEq, Copy, Clone)]
pub enum CarrierType {
    _3gp,
    Aiff,
    Flv,
    Jpeg,
    Mp3,
    Mp4,
    Au,
    Pcx,
    Pdf,
    Png,
    Swf,
    Tga,
    Vob,
    Wav,
}

impl CarrierType {
    /// Returns a type from a file extension.
    ///
    /// The extensions recognized by OpenPuff are:
    ///  - 3GP: `3gp`, `3gpp`, `3g2`, `3gp2`;
    ///  - AIFF: `aif`, `aiff`;
    ///  - FLV: `flv`, `f4v`, `f4p`, `f4a`, `f4b`;
    ///  - JPEG: `jpg`, `jpe`, `jpeg`, `jfif`;
    ///  - MP3: `mp3`;
    ///  - MP4: `mp4`, `mpg4`, `mpeg4`, `m4a`, `m4v`, `mp4a`;
    ///  - AU: `au`, `snd`;
    ///  - PCX: `pcx`;
    ///  - PDF: `pdf`;
    ///  - PNG: `png`;
    ///  - SWF: `swf`;
    ///  - TGA: `tga`, `vda`, `icb`, `vst`;
    ///  - VOB: `vob`;
    ///  - WAV: `wav`, `wave`;
    pub fn from_extension(extension: &str) -> Option<Self> {
        match extension {
            "3gp" | "3gpp" | "3g2" | "3gp2" => Some(Self::_3gp),
            "aif" | "aiff" => Some(Self::Aiff),
            "flv" | "f4v" | "f4p" | "f4a" | "f4b" => Some(Self::Flv),
            "jpg" | "jpe" | "jpeg" | "jfif" => Some(Self::Jpeg),
            "mp3" => Some(Self::Mp3),
            "mp4" | "mpg4" | "mpeg4" | "m4a" | "m4v" | "mp4a" => Some(Self::Mp4),
            "au" | "snd" => Some(Self::Au),
            "pcx" => Some(Self::Pcx),
            "pdf" => Some(Self::Pdf),
            "png" => Some(Self::Png),
            "swf" => Some(Self::Swf),
            "tga" | "vda" | "icb" | "vst" => Some(Self::Tga),
            "vob" => Some(Self::Vob),
            "wav" | "wave" => Some(Self::Wav),

            _ => None,
        }
    }
}

impl fmt::Display for CarrierType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            Self::_3gp => "3GP",
            Self::Aiff => "AIFF",
            Self::Flv => "FLV",
            Self::Jpeg => "JPEG",
            Self::Mp3 => "MP3",
            Self::Mp4 => "MP4",
            Self::Au => "AU",
            Self::Pcx => "PCX",
            Self::Pdf => "PDF",
            Self::Png => "PNG",
            Self::Swf => "SWF",
            Self::Tga => "TGA",
            Self::Vob => "VOB",
            Self::Wav => "WAV",
        };

        write!(f, "{}", name)
    }
}

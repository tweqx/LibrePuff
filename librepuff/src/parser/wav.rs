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
use byteorder::{LittleEndian, ReadBytesExt};
use log::{debug, warn};
use std::cmp;
use std::io::Read;

use super::ParsingError;

#[derive(Default)]
struct Metadata {
    audio_format: u16,
    num_channels: u16,
    sample_rate: u32,
    byte_rate: u32,
    block_align: u16,
    bits_per_sample: u16,
}

/// Determine whether a sample should be chosen to contain a bit in its least significant position.
fn should_choose_sample(sample: u16, first_relevant_bit: usize) -> bool {
    // Don't count the sign bit
    let sample = sample & !0b10000000_00000000;
    let ones = (sample >> (first_relevant_bit - 1)).count_ones();

    ones > 0 && ones <= (14 - first_relevant_bit) as u32
}

/// Extract bits from WAVE PCM data
fn extract_bits_from_data(
    reader: &mut impl Read,
    samples_count: u32,
) -> Result<BitVec, ParsingError> {
    let mut bit_storage = BitVec::new();

    for _ in 0..samples_count {
        let sample = reader.read_u16::<LittleEndian>()?;

        if should_choose_sample(sample, 4) {
            bit_storage.push(sample & 1 == 1);
        }
    }

    Ok(bit_storage)
}

pub fn parse(mut reader: &mut impl Read) -> Result<BitVec, ParsingError> {
    let mut bit_storage = None;

    // Can info->file_offset be anything other than 0 here?
    // TODO: SetFilePointer(hFile,info->file_offset,(PLONG)0x0,FILE_BEGIN);

    let mut metadata: Metadata = Default::default();

    // Reference: http://soundfile.sapp.org/doc/WaveFormat/, http://www.tactilemedia.com/info/MCI_Control_Info.html

    // RIFF header
    let mut chunk_id = [0u8; 4];
    reader.read_exact(&mut chunk_id)?;
    if !chunk_id.eq_ignore_ascii_case(b"RIFF") {
        debug!("expected ChunkID to be 'RIFF', got '{:?}'", chunk_id);
        return Err(ParsingError::InvalidFormat);
    }

    // The size of the entire WAVE file minus 8 bytes for the two fields not included in this
    // count: ChunkID and ChunkSize.
    let chunk_size = reader.read_u32::<LittleEndian>()?;
    if chunk_size & 0x80000000 != 0 {
        debug!("expected the 32th bit of ChunkSize to be zero, for compatibility with OpenPuff");
        return Err(ParsingError::InvalidFormat);
    }
    if chunk_size < 4 {
        debug!("expected ChunkSize to be at least 4");
        return Err(ParsingError::InvalidFormat);
    }

    let mut format = [0u8; 4];
    reader.read_exact(&mut format)?;
    if !format.eq_ignore_ascii_case(b"WAVE") {
        debug!("expected Format to be 'WAVE', got '{:?}'", format);
        return Err(ParsingError::InvalidFormat);
    }

    let data_size = chunk_size - 4;
    let mut data_read = 0;

    // RIFF subchunks: 'fmt ' and 'data'
    let mut processed_fmt_subchunk = false;
    let mut processed_data_subchunk = false;

    while data_read < data_size {
        let mut subchunk_id = [0u8; 4];
        reader.read_exact(&mut subchunk_id)?;
        data_read += 4;

        if subchunk_id.eq_ignore_ascii_case(b"fmt ") {
            // It can only be read once.
            if processed_fmt_subchunk {
                debug!("file cannot have multiple 'fmt ' header");
                return Err(ParsingError::InvalidFormat);
            }
            processed_fmt_subchunk = true;

            let subchunk_size = reader.read_u32::<LittleEndian>()?;
            if subchunk_size & 0x80000000 != 0 {
                debug!("expected the 32th bit of the 'fmt ' SubchunkSize to be zero, for compatibility with OpenPuff");
                return Err(ParsingError::InvalidFormat);
            }

            // Read the header fields
            // BUG: OpenPuff reads `subchunk_size` bytes to a heap-array of 0x400000 bytes, resulting in a
            // possible overflow onto other heap blocks if the header `subchunk_size` is greater
            // than this constant.
            metadata.audio_format = reader.read_u16::<LittleEndian>()?;
            metadata.num_channels = reader.read_u16::<LittleEndian>()?;
            metadata.sample_rate = reader.read_u32::<LittleEndian>()?;
            metadata.byte_rate = reader.read_u32::<LittleEndian>()?;
            metadata.block_align = reader.read_u16::<LittleEndian>()?;
            metadata.bits_per_sample = reader.read_u16::<LittleEndian>()?;

            // OpenPuff computes the number of bits per sample by using that a "normal" WAVE will
            // have BlockAlign = NumChannels * BitsPerSample/8
            let computed_bits_per_sample = metadata.block_align / metadata.num_channels * 8;

            // Oddities detection - not present in OpenPuff
            if computed_bits_per_sample != metadata.bits_per_sample {
                warn!("there is a discrepancy between the BlockAlign and BitsPerSample fields in the 'fmt ' header");
            }
            if subchunk_size != 16 {
                warn!("'fmt ' header contains trailing data");
            }

            // OpenPuff only accepts WAVE file having this specific format
            if metadata.audio_format != 1
                || metadata.num_channels == 0
                || computed_bits_per_sample != 16
            {
                debug!("for compatibility with OpenPuff, only PCM WAVE files with 16 bits per sample and at least one channel are accepted");
                return Err(ParsingError::InvalidFormat);
            }

            data_read += 4 + 16;
            for _ in data_read..cmp::min(data_read + subchunk_size - 16, data_size) {
                reader.read_u8()?;
            }
            data_read += subchunk_size - 16;
        } else if subchunk_id.eq_ignore_ascii_case(b"data") {
            // It can only be read once, after having read the format subchunk.
            if processed_data_subchunk || !processed_fmt_subchunk {
                if processed_data_subchunk {
                    debug!("file cannot have multiple 'data' header");
                } else {
                    debug!("'fmt ' header must have been read before the 'data' header is");
                }
                return Err(ParsingError::InvalidFormat);
            }
            processed_data_subchunk = true;

            let subchunk_size = reader.read_u32::<LittleEndian>()?;
            data_read += 4;
            if subchunk_size == 0 {
                debug!("expected the data SubchunkSize to be non-zero");
                return Err(ParsingError::InvalidFormat);
            }

            let num_samples_per_channel = subchunk_size / (metadata.block_align as u32);
            let num_samples = num_samples_per_channel * (metadata.num_channels as u32);
            if num_samples == 0 {
                debug!("expected the WAVE file to contain at least one sample");
                return Err(ParsingError::InvalidFormat);
            }

            let maybe_bit_storage = extract_bits_from_data(&mut reader, num_samples)?;
            bit_storage = Some(maybe_bit_storage);

            data_read += subchunk_size;
        } else {
            // Other unsupported subchunk, skipping it
            let subchunk_size = reader.read_u32::<LittleEndian>()?;
            data_read += 4;
            if subchunk_size & 0x80000000 != 0 {
                debug!("expected the 32th bit of SubchunkSize to be zero, for compatibility with OpenPuff");
                return Err(ParsingError::InvalidFormat);
            }

            for _ in data_read..cmp::min(data_read + subchunk_size, data_size) {
                reader.read_u8()?;
            }
            data_read += subchunk_size;
        }
    }

    match bit_storage {
        // OpenPuff considers a WAVE file without a 'data' subchunk valid.
        // So, we have to return a new BitVec even if parsing the file didn't produce one.
        None => Ok(BitVec::new()),

        Some(bit_storage) => Ok(bit_storage),
    }
}

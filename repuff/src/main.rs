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

use clap::{Parser, ValueEnum};
use librepuff::{carrier, chain, embedded_file::EmbeddedFile, passwords::Passwords};
use log::{error, info, warn, LevelFilter};
use std::path::PathBuf;
use std::process::ExitCode;
use std::fs::File;
use std::io::{self, Write};

#[derive(Parser, Debug)]
#[command(author, version, long_about = None)]
struct Cli {
    /// Password A.
    #[arg(short, long = "password", visible_alias = "password-a")]
    password_a: String,
    /// Password B.
    #[arg(long, requires = "password_a")]
    password_b: Option<String>,
    /// Password C.
    #[arg(long, requires = "password_b")]
    password_c: Option<String>,

    /// OpenPuff version compatibility.
    #[arg(short = 'c', long = "compatibility")]
    #[arg(value_enum, default_value_t=VersionCompatibility::V4_01)]
    openpuff_version: VersionCompatibility,

    /// Specifies a filename where to output the extracted file.
    /// The special value `-` can be used to refer to the standard output.
    #[arg(short, long = "output", default_value_t=String::from("-"))]
    output: String,

    /// Carrier(s) to unhide a file from.
    ///
    /// The ordering of the carriers matters.
    #[arg(required = true)]
    #[clap(name = "CARRIER")]
    carriers: Vec<PathBuf>,
}

#[derive(Debug, Clone, ValueEnum)]
enum VersionCompatibility {
    #[clap(name = "v4.00")]
    V4_00,

    #[clap(name = "v4.01")]
    V4_01,
}

fn is_there_duplicate_paths(paths: &[PathBuf]) -> bool {
    for i in 1..paths.len() {
        for j in 0..i {
            if paths[i] == paths[j] {
                return true;
            }
        }
    }

    false
}

fn output_extracted_file(content: &[u8], destination: &str) {
    if destination == "-" {
        let mut stdout = io::stdout();
        stdout.write_all(content).unwrap();
    } else {
        let mut file = File::create(destination).unwrap();
        file.write_all(content).unwrap();
    };

}

fn main() -> ExitCode {
    pretty_env_logger::formatted_builder()
        .filter_level(LevelFilter::Debug)
        .init();

    // Parses command-line arguments.
    let cli = Cli::parse();

    // Creates passwords.
    let passwords = match Passwords::from_fields(
        cli.password_a.as_ref(),
        cli.password_b.as_ref().map(|b| b.as_str()),
        cli.password_c.as_ref().map(|c| c.as_str()),
    ) {
        Err(e) => {
            error!("{e}");
            return ExitCode::FAILURE;
        }
        Ok(passwords) => passwords,
    };

    if is_there_duplicate_paths(&cli.carriers) {
        warn!("duplicate carriers used, OpenPuff would complain.");
    }

    // Reads carriers.
    let mut carriers = Vec::new();
    for path in cli.carriers {
        let carrier = match carrier::from_file(&path, Default::default()) {
            Ok(carrier) => carrier,
            Err(err) => {
                error!("could not parse {}: {err}.", path.display());

                return ExitCode::FAILURE;
            }
        };

        carriers.push(carrier);
    }

    if carriers.len() >= 65535 {
        warn!("65535 or more carriers used, OpenPuff would complain.");
    }

    fn are_there_too_many_bits(carriers: &Vec<carrier::EncryptedCarrier>) -> bool {
        let mut total: u32 = 0;
        for carrier in carriers {
            let selected_bit_count = match u32::try_from(carrier.selected_bit_count()) {
                Err(_) => return true,
                Ok(v) => v,
            };

            total = match total.checked_add(selected_bit_count) {
                None => return true,
                Some(v) => v,
            }
        }

        false
    }
    if are_there_too_many_bits(&carriers) {
        warn!("too many carriers (the total number of selected bits overflows 32 bits), OpenPuff would complain.");
    }

    // Decrypts carriers.
    let carriers_embeddings = chain::decrypt_carrier_chain(carriers, passwords);

    let mut data_embedding = Vec::new();
    let mut decoy_embedding = Vec::new();
    for mut embeddings in carriers_embeddings {
        data_embedding.append(&mut embeddings.data);
        decoy_embedding.append(&mut embeddings.decoy);
    }

    let data_file = EmbeddedFile::from_bits(&data_embedding);
    if let Some(data_file) = data_file {
        info!(
            "sucessfully extracted data file: '{}'",
            String::from_utf8_lossy(data_file.filename)
        );

        output_extracted_file(data_file.content, &cli.output);

        return ExitCode::SUCCESS;
    }

    let decoy_file = EmbeddedFile::from_bits(&decoy_embedding);
    if let Some(decoy_file) = decoy_file {
        info!(
            "sucessfully extracted decoy file: '{}'",
            String::from_utf8_lossy(decoy_file.filename)
        );

        output_extracted_file(decoy_file.content, &cli.output);

        return ExitCode::SUCCESS;
    }

    error!("could not extract a data or decoy file using the given passwords.");

    ExitCode::FAILURE
}

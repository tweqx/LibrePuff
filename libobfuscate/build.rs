use bindgen::CargoCallbacks;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::{env, fs, io};

fn list_files(path: &Path) -> io::Result<Vec<PathBuf>> {
    fs::read_dir(path)?
        .map(|entry| Ok(entry?.path()))
        .collect::<io::Result<Vec<_>>>()
}

fn main() -> io::Result<()> {
    let library_dir = Path::new("libObfuscate").canonicalize()?;

    let library_includes = library_dir.join("include");
    let library_sources = library_dir.join("src");

    let header_files: Vec<PathBuf> = list_files(&library_includes)?;

    // Rebuild when the headers or sources change
    println!("cargo:rerun-if-changed={}", library_includes.display());
    println!("cargo:rerun-if-changed={}", library_sources.display());

    // Build libObfuscate
    let status = Command::new("make")
        .args(["-C", "libObfuscate/src", "static"])
        .status()?;
    if !status.success() {
        panic!("Build failed");
    }

    // Instruct rust to link against the built library
    let library_build = library_dir.join("build");

    println!("cargo:rustc-link-search={}", library_build.display());
    println!("cargo:rustc-link-lib=Obfuscate");

    // Generate the wrapper
    let mut builder = bindgen::Builder::default().parse_callbacks(Box::new(CargoCallbacks));
    for header in header_files {
        builder = builder.header(header.to_str().unwrap());
    }
    let bindings = builder.generate().unwrap();

    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap()).join("bindings.rs");
    bindings
        .write_to_file(out_path)
        .expect("Couldn't write bindings!");

    Ok(())
}

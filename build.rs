use std::env;
use std::fs;
use std::path::PathBuf;
use clap::ValueEnum;
use clap_complete::Shell;
use anyhow::Result;

pub mod cli {
    #![allow(unused_macros)]
    include!("src/macros.rs");
    include!("src/cli/mod.rs");
}

pub mod man {
    include!("src/man.rs");
}

fn main() {
    println!("cargo:rerun-if-changed=build.rs");

    // Generate subplot tests.
    #[cfg(feature = "subplot")]
    subplot_build::codegen("sq.subplot")
        .expect("failed to generate code with Subplot");

    let mut sq = cli::build(false);
    generate_shell_completions(&mut sq).unwrap();
    generate_man_pages(&sq).unwrap();
}

/// Variable name to control the asset out directory with.
const ASSET_OUT_DIR: &str = "ASSET_OUT_DIR";

/// Returns the directory to write the given assets to.
fn asset_out_dir(asset: &str) -> Result<PathBuf> {
    println!("cargo:rerun-if-env-changed={}", ASSET_OUT_DIR);
    let outdir: PathBuf =
        env::var_os(ASSET_OUT_DIR).unwrap_or_else(
            || env::var_os("OUT_DIR").expect("OUT_DIR not set")).into();
    if outdir.exists() && ! outdir.is_dir() {
        return Err(
            anyhow::anyhow!("{}={:?} is not a directory",
                            ASSET_OUT_DIR, outdir));
    }

    let path = outdir.join(asset);
    fs::create_dir_all(&path)?;
    Ok(path)
}

/// Generates shell completions.
fn generate_shell_completions(sq: &mut clap::Command) -> Result<()> {
    let path = asset_out_dir("shell-completions")?;

    for shell in Shell::value_variants() {
        clap_complete::generate_to(*shell, sq, "sq", &path)?;
    };

    println!("cargo:warning=shell completions written to {}", path.display());
    Ok(())
}

/// Generates man pages.
fn generate_man_pages(sq: &clap::Command) -> Result<()> {
    let path = asset_out_dir("man-pages")?;

    for man in man::manpages(sq) {
        std::fs::write(path.join(man.filename()), man.troff_source())?;
    }

    println!("cargo:warning=man pages written to {}", path.display());

    Ok(())
}

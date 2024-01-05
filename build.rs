use std::env;
use std::fs;
use std::io::Write;
use std::path::PathBuf;
use clap::ValueEnum;
use clap_complete::Shell;
use anyhow::{Context, Result};

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

    let mut sq = cli::build();
    generate_sq_usage_md(&sq).unwrap();
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

/// Dump help output of all commands and subcommands, for inclusion in
/// the top-level documentation.
fn generate_sq_usage_md(cmd: &clap::Command) -> Result<()> {
    let mut cmd = cmd.clone().term_width(80);
    cmd.build();
    let outdir: PathBuf =
        env::var_os("OUT_DIR").expect("OUT_DIR not set").into();
    assert!(outdir.is_dir());
    let path = outdir.join("sq-usage.md");

    let mut sink = fs::File::create(&path)
        .with_context(|| format!("trying to create {}", path.display()))?;

    dump_help_inner(&mut sink, &mut cmd, "##")
}

fn dump_help_inner(
    sink: &mut dyn Write,
    cmd: &mut clap::Command,
    heading: &str,
) -> Result<()> {
    writeln!(sink)?;

    let mut buffer = Vec::new();
    let _ = cmd.write_long_help(&mut buffer);
    let help = std::str::from_utf8(buffer.as_slice())?;

    let mut verbatim = false;
    for line in help.trim_end().split('\n').skip(1) {
        if ! verbatim && line.starts_with("Usage:") {
            writeln!(sink, "```text")?;
            verbatim = true;
        }

        if line.is_empty() {
            writeln!(sink)?;
        } else {
            writeln!(sink, "{}", line.trim_end())?;
        }
    }
    if verbatim {
        writeln!(sink, "```")?;
    }

    // Recurse.
    for subcommand in cmd
        .get_subcommands_mut()
        .filter(|sc| sc.get_name() != "help")
    {
        writeln!(sink)?;
        let heading_name = subcommand
            // cmd.build() in dump_help makes sure every subcommand has a display_name
            .get_display_name()
            .unwrap()
            .replace('-', " ");
        writeln!(sink, "{} Subcommand {}", heading, heading_name)?;

        dump_help_inner(sink, subcommand, &format!("{}#", heading))?;
    }

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

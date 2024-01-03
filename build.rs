use std::env;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use clap::ValueEnum;
use clap_complete::Shell;
use anyhow::{Context, Result};

pub mod cli {
    #![allow(unused_macros)]
    include!("src/macros.rs");
    include!("src/cli/mod.rs");
}

fn main() {
    println!("cargo:rerun-if-changed=build.rs");

    // Generate subplot tests.
    #[cfg(feature = "subplot")]
    subplot_build::codegen(Path::new("sq.subplot"))
        .expect("failed to generate code with Subplot");

    let mut sq = cli::build();

    // Dump help output of all commands and subcommands, for inclusion in docs
    dump_help(sq.clone()).unwrap();

    generate_shell_completions(&mut sq).unwrap();
    build_man_pages().unwrap();
}

/// Generates shell completions.
fn generate_shell_completions(sq: &mut clap::Command) -> Result<()> {
    let outdir: PathBuf =
        env::var_os("OUT_DIR").expect("OUT_DIR not set").into();
    assert!(outdir.is_dir());
    let path = outdir.join("shell-completions");
    fs::create_dir_all(&path)?;

    for shell in Shell::value_variants() {
        clap_complete::generate_to(*shell, sq, "sq", &path)?;
    };

    println!("cargo:warning=shell completions written to {}", path.display());
    Ok(())
}

fn dump_help(mut cmd: clap::Command) -> Result<()> {
    cmd = cmd.term_width(80);
    cmd.build();
    let path = PathBuf::from(env::var_os("OUT_DIR").unwrap())
        .join("sq-usage.md");
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


fn build_man_pages() -> Result<()> {
    // Man page support.
    let out_dir = std::path::PathBuf::from(
        std::env::var_os("OUT_DIR")
            .ok_or(std::io::Error::from(std::io::ErrorKind::NotFound))?);

    let man = clap_mangen::Man::new(cli::build());
    let mut buffer: Vec<u8> = Default::default();
    man.render(&mut buffer)?;

    let filename = out_dir.join("sq.1");
    // println!("cargo:warning=writing man page to {}", filename.display());
    std::fs::write(filename, buffer)?;

    fn doit(out_dir: &Path, prefix: &str, command: &clap::Command) -> Result<()> {
        let man = clap_mangen::Man::new(command.clone());
        let mut buffer: Vec<u8> = Default::default();
        man.render(&mut buffer)?;

        let filename = out_dir.join(format!("{}-{}.1", prefix, command.get_name()));
        // println!("cargo:warning=writing man page to {}", filename.display());
        std::fs::write(filename, buffer)?;

        for sc in command.get_subcommands() {
            doit(out_dir,
                 &format!("{}-{}", prefix, command.get_name()),
                 sc)?;
        }

        Ok(())
    }

    for sc in cli::build().get_subcommands() {
        doit(&out_dir, "sq", sc)?;
    }

    Ok(())
}

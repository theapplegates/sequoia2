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
    lint_help_texts(&sq).unwrap();
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

/// Lints the help texts.
fn lint_help_texts(sq: &clap::Command) -> Result<()> {
    let mut lints = Vec::new();

    walk(&mut Vec::new(), sq,
         &mut |path: &[&str], c: &clap::Command| {
             let top_level = path.len() == 1;
             let path = path.join(" ");
             lint_short_long(&mut lints, &path,
                             c.get_about(), c.get_long_about());

             for arg in c.get_arguments()
                 .filter(|a| a.get_id().as_str() != "help")
                 .filter(|a| ! a.is_global_set() || top_level)
             {
                 let slug = format!("{} {}", path,
                                    if let Some(l) = arg.get_long() {
                                        format!("--{}", l)
                                    } else if let Some(s) = arg.get_short() {
                                        format!("-{}", s)
                                    } else {
                                        arg.get_id().as_str().to_string()
                                    });
                 lint_short_long(&mut lints, &slug,
                                 arg.get_help(), arg.get_long_help());
             }

             Ok(())
         },
         &mut |_, _, _| Ok(()))?;

    if lints.is_empty() {
        Ok(())
    } else {
        println!("cargo:warning=Linting help texts found {} issues",
                 lints.len());
        println!("cargo:warning=");

        for lint in lints {
            println!("cargo:warning=lint: {}", lint);
        }

        Err(anyhow::anyhow!("linting help texts failed"))
    }
}

use clap::builder::StyledStr;

/// Lints short and long about and help texts.
fn lint_short_long(lints: &mut Vec<String>,
                   slug: &str,
                   short: Option<&StyledStr>,
                   long: Option<&StyledStr>)
{
    let short = if let Some(short) = short {
        short.to_string()
    } else {
        lints.push(format!("{}: no short help", slug));
        return;
    };

    if short.contains(". ") {
        lints.push(format!("{}: short contains more than one sentence", slug));
    }

    if short.ends_with(".") {
        lints.push(format!("{}: short ends in period", slug));
    }

    let long = if let Some(long) = long {
        long.to_string()
    } else {
        return;
    };

    if ! long.starts_with(&format!("{}\n\n", short)) {
        lints.push(format!("{}: long help doesn't start with subject (short help + \\n\\n)", slug));
    }

    if long.split("\n").count() == 1 {
        lints.push(format!("{}: long help consists of a single line", slug));
    }
}

fn walk<'sq, F, G, R>(path: &mut Vec<&'sq str>, c: &'sq clap::Command,
                      fun0: &mut F,
                      fun1: &mut G)
                      -> Result<R>
where
    F: FnMut(&[&str], &clap::Command) -> Result<()>,
    G: FnMut(&[&str], &clap::Command, &[R]) -> Result<R>,
{
    path.push(c.get_name());
    (fun0)(&path, c)?;

    let mut r = Vec::new();
    for s in c.get_subcommands().filter(|cmd| cmd.get_name() != "help") {
        r.push(walk(path, s, fun0, fun1)?);
    }

    let r = (fun1)(&path, c, &r)?;
    path.pop();
    Ok(r)
}


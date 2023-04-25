use sequoia_openpgp as openpgp;
use openpgp::Result;

use crate::Config;
use crate::sq_cli;

mod adopt;
use adopt::adopt;
mod attest_certifications;
use attest_certifications::attest_certifications;
mod extract_cert;
use extract_cert::extract_cert;
mod generate;
use generate::generate;
mod password;
use password::password;
mod subkey;
use subkey::subkey;
mod userid;
use userid::userid;

pub fn dispatch(config: Config, command: sq_cli::key::Command) -> Result<()> {
    use sq_cli::key::Subcommands::*;
    match command.subcommand {
        Generate(c) => generate(config, c)?,
        Password(c) => password(config, c)?,
        Userid(c) => userid(config, c)?,
        Subkey(c) => subkey(config, c)?,
        ExtractCert(c) => extract_cert(config, c)?,
        Adopt(c) => adopt(config, c)?,
        AttestCertifications(c) => attest_certifications(config, c)?,
    }
    Ok(())
}

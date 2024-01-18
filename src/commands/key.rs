use sequoia_openpgp as openpgp;
use openpgp::Result;

use crate::cli;
use crate::Config;

mod adopt;
use adopt::adopt;
mod attest_certifications;
use attest_certifications::attest_certifications;
mod expire;
mod extract_cert;
use extract_cert::extract_cert;
mod list;
use list::list;
mod generate;
use generate::generate;
mod password;
use password::password;
mod revoke;
use revoke::certificate_revoke;
mod subkey;
mod userid;

pub fn dispatch(config: Config, command: cli::key::Command) -> Result<()>
{
    use cli::key::Subcommands::*;
    match command.subcommand {
        List(c) => list(config, c)?,
        Generate(c) => generate(config, c)?,
        Password(c) => password(config, c)?,
        Expire(c) => expire::dispatch(config, c)?,
        Userid(c) => userid::dispatch(config, c)?,
        Revoke(c) => certificate_revoke(config, c)?,
        Subkey(c) => subkey::dispatch(config, c)?,
        ExtractCert(c) => extract_cert(config, c)?,
        Adopt(c) => adopt(config, c)?,
        AttestCertifications(c) => attest_certifications(config, c)?,
    }
    Ok(())
}

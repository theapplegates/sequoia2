//! Network services.

use anyhow::Context;

use sequoia_openpgp as openpgp;
use openpgp::{
    Result,
    KeyHandle,
    cert::{
        Cert,
        CertParser,
    },
    packet::{
        UserID,
    },
    parse::Parse,
    serialize::Serialize,
};
use sequoia_net as net;
use net::{
    KeyServer,
    wkd,
    dane,
};

use crate::{
    Config,
    Model,
    open_or_stdin,
    serialize_keyring,
    output::WkdUrlVariant,
};

use crate::sq_cli;

pub fn dispatch_keyserver(config: Config, c: sq_cli::keyserver::Command) -> Result<()> {
    let network_policy = c.network_policy.into();
    let mut ks = KeyServer::new(network_policy, &c.server)
        .context("Malformed keyserver URI")?;

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .enable_time()
        .build()?;

    use crate::sq_cli::keyserver::Subcommands::*;
    match c.subcommand {
         Get(c) => {
            let query = c.query;

            let handle = query.parse::<KeyHandle>();

            if let Ok(handle) = handle {
                let cert = rt.block_on(ks.get(handle))
                    .context("Failed to retrieve cert")?;

                let mut output =
                    config.create_or_stdout_safe(c.output.as_deref())?;
                if !c.binary {
                    cert.armored().serialize(&mut output)
                } else {
                    cert.serialize(&mut output)
                }.context("Failed to serialize cert")?;
            } else if let Ok(Some(addr)) = UserID::from(query.as_str()).email() {
                let certs = rt.block_on(ks.search(addr))
                    .context("Failed to retrieve certs")?;

                let mut output =
                    config.create_or_stdout_safe(c.output.as_deref())?;
                serialize_keyring(&mut output, &certs, c.binary)?;
            } else {
                return Err(anyhow::anyhow!(
                    "Query must be a fingerprint, a keyid, \
                     or an email address: {:?}", query));
            }
        },
        Send(c) => {
            let mut input = open_or_stdin(c.input.as_deref())?;
            let cert = Cert::from_reader(&mut input).
                context("Malformed key")?;

            rt.block_on(ks.send(&cert))
                .context("Failed to send key to server")?;
        },
    }

    Ok(())
}

pub fn dispatch_wkd(config: Config, c: sq_cli::wkd::Command) -> Result<()> {
    let network_policy: net::Policy = c.network_policy.into();

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .enable_time()
        .build()?;

    use crate::sq_cli::wkd::Subcommands::*;
    match c.subcommand {
        Url(c) => {
            let wkd_url = wkd::Url::from(&c.email_address)?;
            let advanced = wkd_url.to_url(None)?.to_string();
            let direct = wkd_url.to_url(wkd::Variant::Direct)?.to_string();
            let output = Model::wkd_url(config.output_version,
                                       WkdUrlVariant::Advanced, advanced, direct)?;
            output.write(config.output_format, &mut std::io::stdout())?;
        },
        DirectUrl(c) => {
            let wkd_url = wkd::Url::from(&c.email_address)?;
            let advanced = wkd_url.to_url(None)?.to_string();
            let direct = wkd_url.to_url(wkd::Variant::Direct)?.to_string();
            let output = Model::wkd_url(config.output_version,
                                       WkdUrlVariant::Direct, advanced, direct)?;
            output.write(config.output_format, &mut std::io::stdout())?;
        },
        Get(c) => {
            // Check that the policy allows https.
            network_policy.assert(net::Policy::Encrypted)?;

            let email_address = c.email_address;
            // XXX: EmailAddress could be created here to
            // check it's a valid email address, print the error to
            // stderr and exit.
            // Because it might be created a WkdServer struct, not
            // doing it for now.
            let certs = rt.block_on(wkd::get(&email_address))?;
            // ```text
            //     The HTTP GET method MUST return the binary representation of the
            //     OpenPGP key for the given mail address.
            // [draft-koch]: https://datatracker.ietf.org/doc/html/draft-koch-openpgp-webkey-service-07
            // ```
            // But to keep the parallelism with `store export` and `keyserver get`,
            // The output is armored if not `--binary` option is given.
            let mut output =
                config.create_or_stdout_safe(c.output.as_deref())?;
            serialize_keyring(&mut output, &certs, c.binary)?;
        },
        Generate(c) => {
            let domain = c.domain;
            let skip = c.skip;
            let f = open_or_stdin(c.input.as_deref())?;
            let base_path = c.base_directory;
            let variant = if c.direct_method {
                wkd::Variant::Direct
            } else {
                wkd::Variant::Advanced
            };
            let parser = CertParser::from_reader(f)?;
            let policy = &config.policy;
            let certs: Vec<Cert> = parser.filter_map(|cert| cert.ok())
                .collect();
            for cert in certs {
                let vc = match cert.with_policy(policy, None) {
                    Ok(vc) => vc,
                    e @ Err(_) if !skip => e?,
                    _ => continue,
                };
                if wkd::cert_contains_domain_userid(&domain, &vc) {
                    wkd::insert(&base_path, &domain, variant, &vc)
                        .context(format!("Failed to generate the WKD in \
                        {}.", base_path))?;
                } else if !skip {
                    return Err(openpgp::Error::InvalidArgument(
                        format!("Certificate {} does not contain User IDs in domain {}.",
                        vc.fingerprint(), domain)
                    ).into());
                }
            }
        },
    }

    Ok(())
}

pub fn dispatch_dane(config: Config, c: sq_cli::dane::Command) -> Result<()> {
    let network_policy: net::Policy = c.network_policy.into();

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .enable_time()
        .build()?;

    use crate::sq_cli::dane::Subcommands::*;
    match c.subcommand {
        Get(c) => {
            // Check that the policy allows https.
            network_policy.assert(net::Policy::Encrypted)?;

            let email_address = c.email_address;
            // XXX: EmailAddress could be created here to
            // check it's a valid email address, print the error to
            // stderr and exit.
            // Because it might be created a WkdServer struct, not
            // doing it for now.
            let certs = rt.block_on(dane::get(&email_address))?;
            let mut output =
                config.create_or_stdout_safe(c.output.as_deref())?;
            serialize_keyring(&mut output, &certs, c.binary)?;
        },
    }

    Ok(())
}

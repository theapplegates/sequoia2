use std::collections::HashSet;

use anyhow::Context;

use sequoia_openpgp as openpgp;
use openpgp::{
    armor,
    Result,
    serialize::Serialize,
};

use sequoia_cert_store as cert_store;
use cert_store::Store;
use cert_store::store::UserIDQueryParams;

use crate::cli::types::FileOrStdout;
use crate::{
    Config,
    print_error_chain,
    utils::cert_exportable,
};

use crate::cli::cert::export;

pub fn dispatch(config: Config, mut cmd: export::Command) -> Result<()> {
    let cert_store = config.cert_store_or_else()?;

    let mut userid_query = Vec::new();
    let mut die = false;

    for userid in cmd.userid.into_iter() {
        let q = UserIDQueryParams::new();
        userid_query.push((q, userid));
    }

    for pattern in cmd.grep.into_iter() {
        let mut q = UserIDQueryParams::new();
        q.set_anchor_start(false)
            .set_anchor_end(false)
            .set_ignore_case(true);
        userid_query.push((q, pattern));
    }

    for email in cmd.email.into_iter() {
        match UserIDQueryParams::is_email(&email) {
            Ok(email) => {
                let mut q = UserIDQueryParams::new();
                q.set_email(true);
                userid_query.push((q, email));
            }
            Err(err) => {
                let err = err.context(format!(
                    "Invalid value for --email: {:?}", email));
                print_error_chain(&err);
                die = true;
            }
        }
    }

    for domain in cmd.domain.into_iter() {
        match UserIDQueryParams::is_domain(&domain) {
            Ok(domain) => {
                let mut q = UserIDQueryParams::new();
                q.set_email(true)
                    .set_anchor_start(false);
                userid_query.push((q, format!("@{}", domain)));
            }
            Err(err) => {
                let err = err.context(format!(
                    "Invalid value for --domain: {:?}", domain));
                print_error_chain(&err);
                die = true;
            }
        }
    }

    if die {
        return Err(anyhow::anyhow!("Invalid arguments."));
    }

    for query in cmd.query {
        if let Ok(h) = query.parse() {
            cmd.key.push(h);
        } else if let Ok(email) = UserIDQueryParams::is_email(&query) {
            let mut q = UserIDQueryParams::new();
            q.set_email(true);
            userid_query.push((q, email));
        } else {
            let mut q = UserIDQueryParams::new();
            q.set_anchor_start(false)
                .set_anchor_end(false)
                .set_ignore_case(true);
            userid_query.push((q, query));
        }
    }

    if cmd.cert.is_empty() && cmd.key.is_empty() && userid_query.is_empty()
        && ! cmd.all
    {
        config.hint(format_args!(
            "Use --all to export all certs, or give a query."));
        return Err(anyhow::anyhow!("no query given"));
    }

    let output = FileOrStdout::default();
    let mut sink = output.create_pgp_safe(
        config.force,
        cmd.binary,
        armor::Kind::PublicKey,
    )?;

    let mut exported_something = false;

    if cmd.all {
        // Export everything.
        for cert in cert_store.certs()
            .filter(|c| c.to_cert().map(cert_exportable).unwrap_or(false))
        {
            // Turn parse errors into warnings: we want users to be
            // able to recover as much of their data as possible.
            let result = cert.to_cert()
                .with_context(|| {
                    format!("Parsing {} from certificate directory",
                            cert.fingerprint())
                });
            match result {
                Ok(cert) => cert.export(&mut sink)?,
                Err(err) => {
                    print_error_chain(&err);
                    continue;
                }
            }
        }

        // If we have nothing and we export nothing, that is fine.
        exported_something = true;
    } else {
        // There are two possible approaches when there are multiple
        // search criteria: we iterate overall the certificates and
        // check each one individually, or we execute each query and
        // merge the results.  The former makes more sense when most
        // of the certificates will be selected, but that is rarely
        // the case in practice.  Further, some backends, like the
        // KeyServer backend, don't support iteration.  So, we execute
        // each query and merge the results.

        let mut exported = HashSet::new();

        for kh in cmd.cert.iter() {
            if let Ok(certs) = cert_store.lookup_by_cert(kh) {
                for cert in certs.into_iter().filter(
                    |c| c.to_cert().map(cert_exportable).unwrap_or(false))
                {
                    if exported.insert(cert.fingerprint()) {
                        exported_something = true;
                        cert.export(&mut sink)?;
                    }
                }
            }
        }

        for kh in cmd.key.iter() {
            if let Ok(certs) = cert_store.lookup_by_cert_or_subkey(kh) {
                for cert in certs.into_iter().filter(
                        |c| c.to_cert().map(cert_exportable).unwrap_or(false))
                {
                    if exported.get(&cert.fingerprint()).is_some() {
                        // Already exported this one.
                        continue;
                    }

                    if cert.key_handle().aliases(kh) {
                        // When matching the primary key, we don't
                        // need a valid self signature.
                        exported_something = true;
                        cert.export(&mut sink)?;
                        exported.insert(cert.fingerprint());
                    } else {
                        // But, when matching a subkey, we do.
                        if let Ok(vc) = cert.with_policy(&config.policy, None) {
                            if vc.keys().subkeys().any(|ka| {
                                ka.key_handle().aliases(kh)
                            })
                            {
                                exported_something = true;
                                cert.export(&mut sink)?;
                                exported.insert(cert.fingerprint());
                            }
                        }
                    }
                }
            }
        }

        for (q, pattern) in userid_query.iter() {
            if let Ok(certs) = cert_store.select_userid(q, pattern) {
                for cert in certs.into_iter().filter(
                    |c| c.to_cert().map(cert_exportable).unwrap_or(false))
                {
                    if exported.get(&cert.fingerprint()).is_some() {
                        // Already exported this one.
                        continue;
                    }

                    // Matching User IDs need a valid self signature.
                    if let Ok(vc) = cert.with_policy(&config.policy, None) {
                        if vc.userids().any(|ua| {
                            q.check(ua.userid(), pattern)
                        }) {
                            exported_something = true;
                            cert.export(&mut sink)?;
                            exported.insert(cert.fingerprint());
                        }
                    }
                }
            }
        }
    }

    sink.finalize().context("Failed to export certificates")?;

    if exported_something {
        Ok(())
    } else {
        Err(anyhow::anyhow!("Search terms did not match any certificates"))
    }
}

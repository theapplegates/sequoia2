use chrono::DateTime;
use chrono::Utc;

use anyhow::Context;

use sequoia_openpgp as openpgp;
use openpgp::armor::Kind;
use openpgp::armor::Writer;
use openpgp::cert::CertBuilder;
use openpgp::serialize::Serialize;
use openpgp::types::KeyFlags;
use openpgp::Packet;
use openpgp::Result;

use crate::common::password;
use crate::common::userid::lint_userids;
use crate::Config;
use crate::cli::types::FileOrStdout;
use crate::cli;
use crate::ImportStatus;
use crate::commands::inspect::inspect;

pub fn generate(
    mut config: Config,
    command: cli::key::GenerateCommand,
) -> Result<()> {
    let mut builder = CertBuilder::new();

    // User ID
    if command.userid.is_empty() {
        wprintln!("No user ID given, using direct key signature");
    } else {
        // Make sure the user IDs are in canonical form.  If not, and
        // `--allow-non-canonical-userids` is not set, error out.
        if ! command.allow_non_canonical_userids {
            lint_userids(&command.userid)?;
        }

        for uid in command.userid {
            builder = builder.add_userid(uid);
        }
    }

    // Creation time.
    builder = builder.set_creation_time(config.time);

    // Expiration.
    builder = builder.set_validity_period(
        command
        .expiry
        .as_duration(DateTime::<Utc>::from(config.time))?
    );

    // Cipher Suite
    builder = builder.set_cipher_suite(
        command.cipher_suite.as_ciphersuite()
    );

    // Signing Capability
    match (command.can_sign, command.cannot_sign) {
        (false, false) | (true, false) => {
            builder = builder.add_signing_subkey();
        }
        (false, true) => { /* no signing subkey */ }
        (true, true) => {
            return Err(anyhow::anyhow!(
                "Conflicting arguments --can-sign and --cannot-sign"
            ));
        }
    }

    // Authentication Capability
    match (command.can_authenticate, command.cannot_authenticate) {
        (false, false) | (true, false) => {
            builder = builder.add_authentication_subkey()
        }
        (false, true) => { /* no authentication subkey */ }
        (true, true) => {
            return Err(anyhow::anyhow!(
                "Conflicting arguments --can-authenticate and\
                                --cannot-authenticate"
            ));
        }
    }

    // Encryption Capability
    use cli::types::EncryptPurpose::*;
    match (command.can_encrypt, command.cannot_encrypt) {
        (Some(Universal), false) | (None, false) => {
            builder = builder.add_subkey(
                KeyFlags::empty()
                    .set_transport_encryption()
                    .set_storage_encryption(),
                None,
                None,
            );
        }
        (Some(Storage), false) => {
            builder = builder.add_storage_encryption_subkey();
        }
        (Some(Transport), false) => {
            builder = builder.add_transport_encryption_subkey();
        }
        (None, true) => { /* no encryption subkey */ }
        (Some(_), true) => {
            return Err(anyhow::anyhow!(
                "Conflicting arguments --can-encrypt and \
                             --cannot-encrypt"
            ));
        }
    }

    if command.with_password {
        builder = builder.set_password(
            password::prompt_for_new("key")?);
    }

    let on_keystore = command.output.is_none();

    // Generate the key
    let gen = || {
        builder.generate()
    };

    let (cert, rev);

    let rev_path = if let Some(rev_cert) = command.rev_cert {
        (cert, rev) = gen()?;

        FileOrStdout::new(Some(rev_cert))
    } else if let Some(path) = command.output.as_ref().and_then(|o| o.path()) {
        (cert, rev) = gen()?;

        let mut path = path.clone();
        path.as_mut_os_string().push(".rev");
        FileOrStdout::from(path)
    } else if on_keystore {
        let dir = config.home.data_dir(sequoia_directories::Component::Other(
            "revocation-certificates".into()));
        std::fs::create_dir_all(&dir)
            .with_context(|| {
                format!("While creating {}", dir.display())
            })?;

        (cert, rev) = gen()?;
        FileOrStdout::new(
            Some(dir.join(format!("{}-revocation.pgp",
                                  cert.fingerprint()))))
    } else {
        return Err(anyhow::anyhow!(
            "Missing arguments: --rev-cert is mandatory if --output is '-' \
             or not provided."
        ));
    };

    let headers = cert.armor_headers();

    // write out rev cert
    {
        let mut headers: Vec<_> = headers
            .iter()
            .map(|value| ("Comment", value.as_str()))
            .collect();
        headers.insert(0, ("Comment", "Revocation certificate for"));

        let w = rev_path.create_safe(config.force)?;
        let mut w = Writer::with_headers(w, Kind::PublicKey, headers)?;
        Packet::from(cert.primary_key().key().clone()).serialize(&mut w)?;
        Packet::Signature(rev).serialize(&mut w)?;
        w.finalize()?;
    }

    // write out key
    {
        let headers: Vec<_> = headers
            .iter()
            .map(|value| ("Comment", value.as_str()))
            .collect();

        match command.output {
            Some(ref output_file) => {
                // Write the key to a file or to stdout.
                let w = output_file.clone().for_secrets()
                    .create_safe(config.force)?;
                let mut w = Writer::with_headers(w, Kind::SecretKey, headers)?;
                cert.as_tsk().serialize(&mut w)?;
                w.finalize()?;
            }
            None => {
                // write the key to the key store
                match config.import_key(cert.clone()) {
                    Ok(ImportStatus::New) => { /* success */ }
                    Ok(ImportStatus::Unchanged) => {
                        panic!(
                            "The new key is identical to an existing one; this \
                             should never happen");
                    }
                    Ok(ImportStatus::Updated) => {
                        panic!(
                            "The new key collides with an existing one; this \
                             should never happen")
                    }
                    Err(err) => {
                        return Err(anyhow::anyhow!(
                            "Failed saving to the store: {}", err))
                    }
                }
            }
        }
    }

    {
        let mut bytes = Vec::new();
        cert.as_tsk().serialize(&mut bytes)
            .expect("serializing to a vector is infallible");

        if let Err(err) = inspect(
            &mut config,
            buffered_reader::Memory::with_cookie(&bytes, Default::default()),
            command.output
                .as_ref()
                .and_then(|output| {
                    output.path().map(|p| p.display().to_string())
                })
                .as_deref(),
            &mut (Box::new(std::io::stderr()) as Box<dyn std::io::Write + Send + Sync>),
            false)
        {
            wprintln!("Failed to display key: {}", err);
            wprintln!("This is probably a bug in sq, please report it to \
                       https://gitlab.com/sequoia-pgp/sequoia-sq/-/issues/new .");
        }
    }

    if on_keystore {
        // Writing to key store.  Provide some guidance.
        wprintln!("If this is your key, you should mark it as a fully \
                   trusted introducer:");
        eprintln!();
        eprintln!("  $ sq pki link add --ca \\* {} --all",
                  cert.fingerprint());
        eprintln!();

        wprintln!("Otherwise, you should mark it as authenticated:");
        eprintln!();
        eprintln!("  $ sq pki link add {} --all",
                  cert.fingerprint());
        eprintln!();

        wprintln!("You can export your certificate as follows:");
        eprintln!();
        eprintln!("  $ sq cert export --cert {}",
                  cert.fingerprint());
        eprintln!();

        wprintln!("Once you are happy you can upload it to public directories \
                   using:");
        eprintln!();
        eprintln!("  $ sq network keyserver publish {}",
                  cert.fingerprint());
    } else {
        let mut shown = false;
        if let Some(ref output) = command.output {
            if let Some(output_path) = output.path() {
                wprintln!("You can extract the certificate from the \
                           generated key by running:");
                eprintln!();
                eprintln!("  $ sq toolbox extract-cert {}",
                          output_path.display());
                shown = true;
            }
        }

        if ! shown {
            wprintln!("You can extract the certificate from the \
                       generated key using `sq toolbox extract-cert`.");
        }
    }

    Ok(())
}

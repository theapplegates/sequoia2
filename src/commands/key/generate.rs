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
use openpgp::packet::UserID;
use openpgp::Result;

use crate::common::password;
use crate::common::userid::{lint_userids, lint_names, lint_emails};
use crate::Sq;
use crate::cli::types::FileOrStdout;
use crate::cli;
use crate::ImportStatus;
use crate::commands::inspect::inspect;

pub fn generate(
    mut sq: Sq,
    mut command: cli::key::GenerateCommand,
) -> Result<()> {
    let mut builder = CertBuilder::new();

    // Names, email addresses, and user IDs.
    lint_names(&command.names)?;
    for n in &command.names {
        command.userid.push(UserID::from(n.as_str()));
    }

    lint_emails(&command.emails)?;
    for n in &command.emails {
        command.userid.push(UserID::from_address(None, None, n)?);
    }

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
    builder = builder.set_creation_time(sq.time);

    // Expiration.
    builder = builder.set_validity_period(
        command
        .expiration
        .as_duration(DateTime::<Utc>::from(sq.time))?
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

    if ! command.without_password {
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
        let dir = sq.home.data_dir(sequoia_directories::Component::Other(
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

        let w = rev_path.create_safe(sq.force)?;
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
                    .create_safe(sq.force)?;
                let mut w = Writer::with_headers(w, Kind::SecretKey, headers)?;
                cert.as_tsk().serialize(&mut w)?;
                w.finalize()?;
            }
            None => {
                // write the key to the key store
                match sq.import_key(cert.clone()) {
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
            &mut sq,
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
        sq.hint(format_args!("If this is your key, you should mark it as a \
                              fully trusted introducer:"))
            .command(format_args!("sq pki link add --ca \\* {} --all",
                                  cert.fingerprint()));

        sq.hint(format_args!("Otherwise, you should mark it as authenticated:"))
            .command(format_args!("sq pki link add {} --all",
                                  cert.fingerprint()));

        sq.hint(format_args!("You can export your certificate as follows:"))
            .command(format_args!("sq cert export --cert {}",
                                  cert.fingerprint()));

        sq.hint(format_args!("Once you are happy you can upload it to public \
                              directories using:"))
            .command(format_args!("sq network keyserver publish --cert {}",
                                  cert.fingerprint()));
    } else {
        let mut shown = false;
        if let Some(ref output) = command.output {
            if let Some(output_path) = output.path() {
                sq.hint(format_args!("You can extract the certificate from the \
                                      generated key by running:"))
                    .command(format_args!("sq toolbox extract-cert {}",
                                          output_path.display()));
                shown = true;
            }
        }

        if ! shown {
            sq.hint(format_args!("You can extract the certificate from the \
                                  generated key using:"))
                .command(format_args!("sq toolbox extract-cert"));
        }
    }

    Ok(())
}

use std::convert::TryFrom;
use std::io::{self, Read};
use std::time::{Duration, SystemTime};

use anyhow::Context;

use buffered_reader::BufferedReader;

use sequoia_openpgp as openpgp;
use openpgp::{KeyHandle, Packet, Result};
use openpgp::armor::ReaderMode;
use openpgp::cert::prelude::*;
use openpgp::packet::{
    Signature,
    key::PublicParts,
};
use openpgp::parse::{Dearmor, Parse, PacketParserBuilder, PacketParserResult};
use openpgp::policy::{Policy, HashAlgoSecurity};
use openpgp::packet::key::SecretKeyMaterial;
use openpgp::types::{
    ReasonForRevocation,
    SignatureType,
};

use sequoia_cert_store as cert_store;
use cert_store::Store;

use crate::Convert;

use crate::best_effort_primary_uid_for;
use crate::Config;
use crate::one_line_error_chain;
use crate::SECONDS_IN_YEAR;
use crate::SECONDS_IN_DAY;

use crate::cli::inspect;
use crate::cli::types::FileOrStdout;

pub fn dispatch(mut config: Config, c: inspect::Command)
    -> Result<()>
{
    // sq inspect does not have --output, but commands::inspect does.
    // Work around this mismatch by always creating a stdout output.
    let output_type = FileOrStdout::default();
    let output = &mut output_type.create_unsafe(config.force)?;

    let print_certifications = c.certifications;

    let input = c.input;

    let mut bytes: Vec<u8> = Vec::new();
    if c.cert.is_empty() {
        if let Some(path) = input.inner() {
            if ! path.exists() &&
                format!("{}", input).parse::<KeyHandle>().is_ok() {
                wprintln!("The file {} does not exist, \
                           did you mean \"sq inspect --cert {}\"?",
                          input, input);
            }
        }

        inspect(&mut config, input.open()?,
                Some(&input.to_string()), output,
                print_certifications)
    } else {
        let cert_store = config.cert_store_or_else()?;
        for cert in c.cert.into_iter() {
            let certs = cert_store.lookup_by_cert_or_subkey(&cert)
                .with_context(|| format!("Looking up {}", cert))?;

            // Include non-exportable signatures, etc.
            for cert in certs.into_iter() {
                let b = cert.to_vec().context("Serializing certificate")?;
                bytes.extend(b);
            }
        }

        let br = buffered_reader::Memory::with_cookie(
            &bytes, sequoia_openpgp::parse::Cookie::default());
        inspect(&mut config, br, None, output,
                print_certifications)
    }
}

/// Inspects OpenPGP data.
///
/// The data is read from `input`.  `input_filename` is the name of
/// the file, if available.  This is only used for display purposes.
/// The output is written to `output`.
///
/// If `print_certifications` is set, also shows information about
/// certifications.
pub fn inspect<'a, R>(config: &mut Config,
                      input: R,
                      input_filename: Option<&str>,
                      output: &mut Box<dyn std::io::Write + Send + Sync>,
                      print_certifications: bool)
    -> Result<()>
where R: BufferedReader<sequoia_openpgp::parse::Cookie> + 'a,
{
    let time = Some(config.time);

    let mut ppr = openpgp::parse::PacketParser::from_buffered_reader(input)?;

  loop {
    if let Some(input_filename) = input_filename {
        write!(output, "{}: ", input_filename)?;
    }

    let mut type_called = false;  // Did we print the type yet?
    let mut encrypted = false;    // Is it an encrypted message?
    let mut packets = Vec::new(); // Accumulator for packets.
    let mut pkesks = Vec::new();  // Accumulator for PKESKs.
    let mut n_skesks = 0;         // Number of SKESKs.
    let mut sigs = Vec::new();    // Accumulator for signatures.
    let mut literal_prefix = Vec::new();

    while let PacketParserResult::Some(mut pp) = ppr {
        match pp.packet {
            Packet::PublicKey(_) | Packet::SecretKey(_) => {
                if pp.possible_cert().is_err()
                    && pp.possible_keyring().is_ok()
                {
                    if ! type_called {
                        writeln!(output, "OpenPGP Keyring.")?;
                        writeln!(output)?;
                        type_called = true;
                    }
                    let pp = openpgp::PacketPile::from(
                        std::mem::take(&mut packets));
                    let cert = openpgp::Cert::try_from(pp)?;
                    inspect_cert(
                        config,
                        config.policy,
                        time,
                        output,
                        &cert,
                        print_certifications,
                    )?;
                }
            },
            Packet::Literal(_) => {
                pp.by_ref().take(40).read_to_end(&mut literal_prefix)?;
            },
            Packet::SEIP(_) | Packet::AED(_) => {
                encrypted = true;
            },
            _ => (),
        }

        let possible_keyring = pp.possible_keyring().is_ok();
        let (packet, ppr_) = pp.recurse()?;
        ppr = ppr_;

        match packet {
            Packet::PKESK(p) => pkesks.push(p),
            Packet::SKESK(_) => n_skesks += 1,
            Packet::Signature(s) => if possible_keyring {
                packets.push(Packet::Signature(s))
            } else {
                sigs.push(s)
            },
            _ => packets.push(packet),
        }
    }

    if let PacketParserResult::EOF(eof) = ppr {
        let is_message = eof.is_message();
        let is_cert = eof.is_cert();
        let is_keyring = eof.is_keyring();

        // Now, the parser is exhausted, but we may find another
        // armored blob.  Note that this can only happen if the first
        // set of packets was also armored.
        let next_ppr =
            PacketParserBuilder::from_buffered_reader(eof.into_reader())
            .and_then(
                |builder| builder
                    .dearmor(Dearmor::Enabled(
                        ReaderMode::Tolerant(None)))
                    .build());

        if is_message.is_ok() {
            writeln!(output, "{}OpenPGP Message.",
                     match (encrypted, ! sigs.is_empty()) {
                         (false, false) => "",
                         (false, true) => "Signed ",
                         (true, false) => "Encrypted ",
                         (true, true) => "Encrypted and signed ",
                     })?;
            writeln!(output)?;
            if n_skesks > 0 {
                writeln!(output, "      Passwords: {}", n_skesks)?;
            }
            for pkesk in pkesks.iter() {
                writeln!(output, "      Recipient: {}", pkesk.recipient())?;
            }
            inspect_signatures(config, output, &sigs)?;
            if ! literal_prefix.is_empty() {
                writeln!(output, "           Data: {:?}{}",
                         String::from_utf8_lossy(&literal_prefix),
                         if literal_prefix.len() == 40 { "..." } else { "" })?;
            }

        } else if is_cert.is_ok() || is_keyring.is_ok() {
            let pp = openpgp::PacketPile::from(packets);
            let cert = openpgp::Cert::try_from(pp)?;
            inspect_cert(config, config.policy, time, output, &cert,
                         print_certifications)?;
        } else if packets.is_empty() && ! sigs.is_empty() {
            if sigs.iter().all(is_revocation_sig) {
                writeln!(output, "Revocation Certificate{}.",
                         if sigs.len() > 1 { "s" } else { "" })?;
                writeln!(output)?;
                for sig in sigs {
                    inspect_bare_revocation(config, output, &sig)?;
                }
                writeln!(output, "           Note: \
                                  Signatures have NOT been verified!")?;
            } else {
                writeln!(output, "Detached signature{}.",
                         if sigs.len() > 1 { "s" } else { "" })?;
                writeln!(output)?;
                inspect_signatures(config, output, &sigs)?;
            }
        } else if packets.is_empty() {
            writeln!(output, "No OpenPGP data.")?;
        } else {
            writeln!(output, "Unknown sequence of OpenPGP packets.")?;
            writeln!(output, "  Message: {}", is_message.as_ref().unwrap_err())?;
            writeln!(output, "  Cert: {}", is_cert.as_ref().unwrap_err())?;
            writeln!(output, "  Keyring: {}", is_keyring.as_ref().unwrap_err())?;
            writeln!(output)?;
            if let Some(filename) = input_filename {
                writeln!(output, "Hint: Try 'sq toolbox packet dump {}'",
                         filename)?;
            }
        }

        // See if there is another armor block.
        match next_ppr {
            Ok(ppr_) => {
                writeln!(output, "Note: There is another block of armored \
                                  OpenPGP data.")?;

                if is_message.is_ok() {
                    writeln!(output, "Note: Data concatenated to a message is \
                                      likely an error.")?;
                } else if is_cert.is_ok() || is_keyring.is_ok() {
                    writeln!(output, "Note: This is a non-standard extension \
                                      to OpenPGP.")?;
                }
                writeln!(output)?;

                ppr = ppr_;
                continue;
            },
            Err(_) => break,
        }
    } else {
        unreachable!()
    }
  }

    Ok(())
}

/// Returns true iff all signatures in the cert are revocation
/// signatures.
fn is_revocation_sig(s: &Signature) -> bool {
    [
        SignatureType::KeyRevocation,
        SignatureType::SubkeyRevocation,
        SignatureType::CertificationRevocation,
    ].contains(&s.typ())
}

/// Returns true iff all signatures in the cert are revocation
/// signatures.
fn is_revocation_cert(c: &Cert) -> bool {
    c.primary_key().signatures().all(|s| s.typ() == SignatureType::KeyRevocation)
        && c.keys().subkeys().all(|skb| skb.signatures().all(
            |s| s.typ() == SignatureType::SubkeyRevocation))
        && c.userids().all(|uidb| uidb.signatures().all(
            |s| s.typ() == SignatureType::CertificationRevocation))
}

fn inspect_cert(
    config: &mut Config,
    policy: &dyn Policy,
    time: Option<SystemTime>,
    output: &mut dyn io::Write,
    cert: &openpgp::Cert,
    print_certifications: bool,
) -> Result<()> {
    if cert.is_tsk() {
        writeln!(output, "Transferable Secret Key.")?;
    } else if is_revocation_cert(&cert) {
        writeln!(output, "Revocation Certificate.")?;
    } else {
        writeln!(output, "OpenPGP Certificate.")?;
    }
    writeln!(output)?;
    writeln!(output, "    Fingerprint: {}", cert.fingerprint())?;
    inspect_revocation(output, "", cert.revocation_status(policy, None))?;
    inspect_key(
        config,
        policy,
        time,
        output,
        "",
        cert.keys().next().unwrap(),
        print_certifications,
    )?;
    writeln!(output)?;

    for skb in cert.keys().subkeys() {
        writeln!(output, "         Subkey: {}", skb.key().fingerprint())?;
        inspect_revocation(output, "", skb.revocation_status(policy, None))?;
        match skb.binding_signature(policy, None) {
            Ok(sig) => {
                if let Err(e) = sig.signature_alive(None, Duration::new(0, 0)) {
                    print_error_chain(output, &e)?;
                }
            }
            Err(e) => print_error_chain(output, &e)?,
        }
        inspect_key(
            config,
            policy,
            time,
            output,
            "",
            skb.into(),
            print_certifications,
        )?;
        writeln!(output)?;
    }

    fn print_error_chain(output: &mut dyn io::Write, err: &anyhow::Error)
                         -> Result<()> {
        writeln!(output, "                 Invalid: {}", err)?;
        for cause in err.chain().skip(1) {
            writeln!(output, "                 because: {}", cause)?;
        }
        Ok(())
    }

    for uidb in cert.userids() {
        writeln!(output, "         UserID: {}", uidb.userid())?;
        inspect_revocation(output, "", uidb.revocation_status(policy, None))?;
        match uidb.binding_signature(policy, None) {
            Ok(sig) => {
                if let Err(e) = sig.signature_alive(None, Duration::new(0, 0)) {
                    print_error_chain(output, &e)?;
                }
            }
            Err(e) => print_error_chain(output, &e)?,
        }
        inspect_certifications(config, output, policy,
                               uidb.certifications(),
                               print_certifications)?;
        writeln!(output)?;
    }

    for uab in cert.user_attributes() {
        writeln!(output, "         User attribute: {:?}",
                 uab.user_attribute())?;
        inspect_revocation(output, "", uab.revocation_status(policy, None))?;
        match uab.binding_signature(policy, None) {
            Ok(sig) => {
                if let Err(e) = sig.signature_alive(None, Duration::new(0, 0)) {
                    print_error_chain(output, &e)?;
                }
            }
            Err(e) => print_error_chain(output, &e)?,
        }
        inspect_certifications(config, output, policy,
                               uab.certifications(),
                               print_certifications)?;
        writeln!(output)?;
    }

    for ub in cert.unknowns() {
        writeln!(output, "         Unknown component: {:?}", ub.unknown())?;
        match ub.binding_signature(policy, None) {
            Ok(sig) => {
                if let Err(e) = sig.signature_alive(None, Duration::new(0, 0)) {
                    print_error_chain(output, &e)?;
                }
            }
            Err(e) => print_error_chain(output, &e)?,
        }
        inspect_certifications(config, output, policy,
                               ub.certifications(),
                               print_certifications)?;
        writeln!(output)?;
    }

    for bad in cert.bad_signatures() {
        writeln!(output, "             Bad Signature: {:?}", bad)?;
    }

    Ok(())
}

fn inspect_key(
    config: &mut Config,
    policy: &dyn Policy,
    time: Option<SystemTime>,
    output: &mut dyn io::Write,
    indent: &str,
    ka: ErasedKeyAmalgamation<PublicParts>,
    print_certifications: bool,
) -> Result<()> {
    let key = ka.key();
    let bundle = ka.bundle();
    let vka = match ka.with_policy(policy, time) {
        Ok(vka) => {
            if let Err(e) = vka.alive() {
                writeln!(output, "{}                 Invalid: {}",
                         indent,
                         one_line_error_chain(&e))?;
            }
            Some(vka)
        },
        Err(e) => {
            writeln!(output, "{}                 Invalid: {}",
                     indent,
                     one_line_error_chain(&e))?;
            None
        },
    };

    writeln!(output, "{}Public-key algo: {}", indent, key.pk_algo())?;
    if let Some(bits) = key.mpis().bits() {
        writeln!(output, "{}Public-key size: {} bits", indent, bits)?;
    }
    if let Some(secret) = key.optional_secret() {
        writeln!(output, "{}     Secret key: {}",
                 indent,
                 if let SecretKeyMaterial::Unencrypted(_) = secret {
                     "Unencrypted"
                 } else {
                     "Encrypted"
                 })?;
    }
    writeln!(output, "{}  Creation time: {}", indent,
             key.creation_time().convert())?;
    if let Some(vka) = vka {
        if let Some(expires) = vka.key_validity_period() {
            let expiration_time = key.creation_time() + expires;
            writeln!(output, "{}Expiration time: {} (creation time + {})",
                     indent,
                     expiration_time.convert(),
                     expires.convert())?;
        }

        if let Some(flags) = vka.key_flags().and_then(inspect_key_flags) {
            writeln!(output, "{}      Key flags: {}", indent, flags)?;
        }
    }
    inspect_certifications(config, output, policy,
                           bundle.certifications().iter(),
                           print_certifications)?;

    Ok(())
}

/// Prints the revocation reasons.
fn print_reasons(output: &mut dyn io::Write, indent: &str,
                 third_party: bool, sigs: &[&Signature])
                 -> Result<()> {
    for sig in sigs {
        let (reason, message) = sig.reason_for_revocation()
            .map(|(r, m)| (r, Some(m)))
            .unwrap_or((ReasonForRevocation::Unspecified, None));

        writeln!(output, "{}                  - {}", indent, reason)?;
        writeln!(output, "{}                    On: {}",
                 indent, sig.signature_creation_time()
                 .expect("valid sigs have one").convert())?;
        if third_party {
            writeln!(output, "{}                    Issued by {}",
                     indent,
                     if let Some(issuer)
                     = sig.get_issuers().into_iter().next()
                     {
                         issuer.to_string()
                     } else {
                         "an unknown certificate".into()
                     })?;
        }
        if let Some(msg) = message {
            writeln!(output, "{}                    Message: {:?}",
                     indent, String::from_utf8_lossy(msg))?;
        }
    }
    Ok(())
}

fn inspect_revocation(output: &mut dyn io::Write,
                      indent: &str,
                      revoked: openpgp::types::RevocationStatus)
                      -> Result<()> {
    use openpgp::types::RevocationStatus::*;
    match revoked {
        Revoked(sigs) => {
            writeln!(output, "{}                 Revoked:", indent)?;
            print_reasons(output, indent, false, &sigs)?;
        },
        CouldBe(sigs) => {
            writeln!(output, "{}                 Possibly revoked:", indent)?;
            print_reasons(output, indent, true, &sigs)?;
        },
        NotAsFarAsWeKnow => (),
    }

    Ok(())
}

fn inspect_bare_revocation(config: &mut Config,
                           output: &mut dyn io::Write, sig: &Signature)
                           -> Result<()> {
    let indent = "";
    inspect_issuers(config, output, &sig)?;
    writeln!(output, "{}                 Possible revocation:", indent)?;
    print_reasons(output, indent, false, &[sig])?;
    writeln!(output)?;
    Ok(())
}

fn inspect_key_flags(flags: openpgp::types::KeyFlags) -> Option<String> {
    let mut capabilities = Vec::new();
    if flags.for_certification() {
        capabilities.push("certification")
    }
    if flags.for_signing() {
        capabilities.push("signing")
    }
    if flags.for_authentication() {
        capabilities.push("authentication")
    }
    if flags.for_transport_encryption() {
        capabilities.push("transport encryption")
    }
    if flags.for_storage_encryption() {
        capabilities.push("data-at-rest encryption")
    }
    if flags.is_group_key() {
        capabilities.push("group key")
    }
    if flags.is_split_key() {
        capabilities.push("split key")
    }

    if !capabilities.is_empty() {
        Some(capabilities.join(", "))
    } else {
        None
    }
}

fn inspect_signatures(config: &mut Config,
                      output: &mut dyn io::Write,
                      sigs: &[openpgp::packet::Signature]) -> Result<()> {
    use openpgp::types::SignatureType::*;
    for sig in sigs {
        match sig.typ() {
            Binary | Text => (),
            signature_type =>
                writeln!(output, "           Kind: {}", signature_type)?,
        }

        inspect_issuers(config, output, &sig)?;
    }
    if ! sigs.is_empty() {
        writeln!(output, "           Note: \
                          Signatures have NOT been verified!")?;
    }

    Ok(())
}

fn inspect_issuers(config: &mut Config,
                   output: &mut dyn io::Write,
                   sig: &Signature) -> Result<()> {
    let mut fps: Vec<_> = sig.issuer_fingerprints().collect();
    fps.sort();
    fps.dedup();
    let khs: Vec<KeyHandle> = fps.into_iter().map(|fp| fp.into()).collect();
    for kh in khs.iter() {
        writeln!(output, " Alleged signer: {}, {}",
                 kh,
                 best_effort_primary_uid_for(
                     Some(config), kh, config.policy, config.time))?;
    }

    let mut keyids: Vec<_> = sig.issuers().collect();
    keyids.sort();
    keyids.dedup();
    for keyid in keyids {
        if ! khs.iter().any(|kh| kh.aliases(&keyid.into())) {
            writeln!(output, " Alleged signer: {}, {}",
                     keyid,
                     best_effort_primary_uid_for(
                         Some(config), &KeyHandle::from(keyid),
                         config.policy, config.time))?;
        }
    }

    Ok(())
}

fn inspect_certifications<'a, A>(config: &mut Config,
                                 output: &mut dyn io::Write,
                                 policy: &dyn Policy,
                                 certs: A,
                                 print_certifications: bool)
    -> Result<()>
    where A: std::iter::Iterator<Item=&'a openpgp::packet::Signature>
{
    if print_certifications {
        let mut emit_warning = false;
        for sig in certs {
            let time = if let Some(time) = sig.signature_creation_time() {
                chrono::DateTime::<chrono::offset::Utc>::from(time)
            } else {
                // A signature must have a signature creation time
                // subpacket to be valid.  This signature is not
                // valid, so skip it.
                continue;
            };

            emit_warning = true;

            writeln!(output, "  Certification: Creation time: {}", time)?;

            let indent = "                 ";

            if let Some(e) = sig.signature_expiration_time() {
                let e = chrono::DateTime::<chrono::offset::Utc>::from(e);
                let diff = e - time;
                let years = diff.num_seconds() / (SECONDS_IN_YEAR as i64);
                let rest = diff.num_seconds() - years * (SECONDS_IN_YEAR as i64);
                let days = rest / (SECONDS_IN_DAY as i64);
                let rest = rest - days * (SECONDS_IN_DAY as i64);

                writeln!(output, "{}Expiration time: {} (after {}{}{}{}{})",
                         indent,
                         e,
                         match years {
                             0 => "".into(),
                             1 => format!("{} year", years),
                             _ => format!("{} years", years),
                         },
                         if years != 0 && days != 0 { ", " } else { "" },
                         match days {
                             0 => "".into(),
                             1 => format!("{} day", days),
                             _ => format!("{} days", days),
                         },
                         if years == 0 && days != 0 && rest != 0 { ", " } else { "" },
                         if years == 0 {
                             match rest {
                                 0 => "".into(),
                                 1 => format!("{} second", rest),
                                 _ => format!("{} seconds", rest),
                             }
                         } else {
                             "".into()
                         })?;
            }

            if let Some((depth, amount)) = sig.trust_signature() {
                writeln!(output, "{}Trust depth: {}", indent,
                         depth)?;
                writeln!(output, "{}Trust amount: {}", indent,
                         amount)?;
            }
            for re in sig.regular_expressions() {
                if let Ok(re) = String::from_utf8(re.to_vec()) {
                    writeln!(output, "{}Regular expression: {:?}", indent,
                             re)?;
                } else {
                    writeln!(output,
                             "{}Regular expression (invalid UTF-8): {:?}",
                             indent,
                             String::from_utf8_lossy(re))?;
                }
            }

            let mut fps: Vec<_> = sig.issuer_fingerprints().collect();
            fps.sort();
            fps.dedup();
            let khs: Vec<KeyHandle> = fps.into_iter().map(|fp| fp.into()).collect();
            for kh in khs.iter() {
                writeln!(output, "{}Alleged certifier: {}, {}",
                         indent, kh,
                         best_effort_primary_uid_for(
                             Some(config), kh,
                             config.policy, config.time))?;
            }
            let mut keyids: Vec<_> = sig.issuers().collect();
            keyids.sort();
            keyids.dedup();
            for keyid in keyids {
                if ! khs.iter().any(|kh| kh.aliases(&keyid.into())) {
                    writeln!(output, "{}Alleged certifier: {}, {}", indent,
                             keyid,
                             best_effort_primary_uid_for(
                                 Some(config), &KeyHandle::from(keyid),
                                 config.policy, config.time))?;
                }
            }

            writeln!(output, "{}Hash algorithm: {}",
                     indent, sig.hash_algo())?;
            if let Err(err) = policy.signature(
                sig, HashAlgoSecurity::CollisionResistance)
            {
                writeln!(output,
                         "{}Certification is not valid according to \
                          the current policy:\n\
                          {}  {}",
                         indent, indent,
                         one_line_error_chain(&err))?;
            }
        }
        if emit_warning {
            writeln!(output, "           Note: \
                              Certifications have NOT been verified!")?;
        }
    } else {
        let count = certs.count();
        if count > 0 {
            writeln!(output, " Certifications: {}, \
                              use --certifications to list", count)?;
        }
    }

    Ok(())
}

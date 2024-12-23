use std::collections::BTreeSet;

use typenum::Unsigned;

use sequoia_openpgp as openpgp;
use openpgp::Cert;
use openpgp::Fingerprint;
use openpgp::KeyHandle;
use openpgp::Result;
use openpgp::types::RevocationStatus;
use openpgp::packet::UserID;

use sequoia_cert_store as cert_store;
use cert_store::store::UserIDQueryParams;
use cert_store::Store as _;

use sequoia_wot as wot;
use wot::store::Backend;
use wot::store::Store;

use crate::cli;
use cli::types::CertDesignators;
use cli::types::TrustAmount;
use cli::types::UserIDDesignators;
use cli::types::cert_designator;
use cli::types::userid_designator;

use super::output::ConciseHumanReadableOutputNetwork;
use super::output::OutputType;

use crate::{
    Sq,
    common::ui,
};

const TRACE: bool = false;

/// The different kinds of queries that we support.
pub enum QueryKind {
    Cert(KeyHandle),
    UserID(String),
    Email(String),
    UserIDBinding(KeyHandle, String),
    EmailBinding(KeyHandle, String),
    Domain(String),
    Pattern(String),
    All,
}

impl QueryKind {
    /// Returns the queried key handle, if any.
    fn key_handle(&self) -> Option<KeyHandle> {
        use QueryKind::*;

        match self {
            Cert(kh) | UserIDBinding(kh, _) | EmailBinding(kh, _) => {
                Some(kh.clone())
            }
            _ => None
        }
    }

    /// Returns the queried user ID, if any.
    fn userid(&self) -> Option<&str> {
        use QueryKind::*;

        match self {
            UserID(userid) | UserIDBinding(_, userid) => {
                Some(&userid[..])
            }
            _ => None
        }
    }

    /// Returns the queried email address, if any.
    fn email(&self) -> Option<&str> {
        use QueryKind::*;

        match self {
            Email(email) | EmailBinding(_, email) => {
                Some(&email[..])
            }
            _ => None
        }
    }
}

pub struct Query {
    /// The user-supplied command-line argument, e.g., `--cert
    /// FINGERPRINT`.
    pub argument: Option<String>,
    pub kind: QueryKind,
}

impl Query {
    /// Returns a `Query` that matches all bindings.
    pub fn all() -> Self {
        Query {
            argument: None,
            kind: QueryKind::All,
        }
    }

    /// Returns a `Query` for a key handle.
    ///
    /// `argument` is the user-supplied command-line argument, e.g.,
    /// `--cert FINGERPRINT`.
    pub fn for_key_handle(argument: Option<String>, kh: KeyHandle)
        -> Query
    {
        Query {
            argument,
            kind: QueryKind::Cert(kh),
        }
    }

    /// Converts a set of certificate designators to a set of queries.
    pub fn for_cert_designators<Arguments, Prefix, Options, Doc>(
        designators: CertDesignators<Arguments, Prefix, Options, Doc>)
        -> Vec<Query>
    where
        Arguments: typenum::Unsigned,
        Prefix: cert_designator::ArgumentPrefix,
    {
        let arguments = Arguments::to_usize();
        let file_arg = (arguments & cert_designator::FileArg::to_usize()) > 0;
        let special_arg = (arguments & cert_designator::SpecialArg::to_usize()) > 0;
        let self_arg = (arguments & cert_designator::SelfArg::to_usize()) > 0;

        assert!(! file_arg);
        assert!(! special_arg);
        assert!(! self_arg);

        designators.iter()
            .map(|designator| {
                use cert_designator::CertDesignator::*;
                let kind = match designator {
                    Stdin | File(_) | Special(_) | Self_ => {
                        unreachable!("Not allowed in this context");
                    }
                    Cert(kh) => {
                        QueryKind::Cert(kh.clone())
                    }
                    UserID(userid) => QueryKind::UserID(userid.clone()),
                    Email(email) => QueryKind::Email(email.clone()),
                    Domain(domain) => QueryKind::Domain(domain.clone()),
                    Grep(pattern) => QueryKind::Pattern(pattern.clone()),
                };

                Query {
                    argument: Some(designator.argument::<Prefix>()),
                    kind,
                }
            })
            .collect()
    }

    /// Creates a query for a binding consisting of a certificate
    /// designator and a user ID designator.
    pub fn for_binding<CertPrefix, CertOptions, CertDoc,
                       UserIDArguments, UserIDOptions, UserIDDocumentation>
        (cert: CertDesignators<cert_designator::CertArg,
                               CertPrefix, CertOptions, CertDoc>,
         userid: UserIDDesignators<UserIDArguments,
                                   UserIDOptions, UserIDDocumentation>)
        -> Vec<Query>
    where
        CertOptions: typenum::Unsigned,
        CertPrefix: cert_designator::ArgumentPrefix,
        UserIDArguments: typenum::Unsigned,
        UserIDOptions: typenum::Unsigned,
    {
        // One required value.
        let cert_options = CertOptions::to_usize();
        let cert_one_value
            = (cert_options & cert_designator::OneValue::to_usize()) > 0;
        let cert_optional_value
            = (cert_options & cert_designator::OptionalValue::to_usize()) > 0;
        assert!(cert_one_value);
        assert!(! cert_optional_value);

        // One required value.
        let userid_options = UserIDOptions::to_usize();
        let userid_one_value
            = (userid_options & userid_designator::OneValue::to_usize()) > 0;
        let userid_optional_value
            = (userid_options & userid_designator::OptionalValue::to_usize()) > 0;
        assert!(userid_one_value);
        assert!(! userid_optional_value);

        assert_eq!(cert.len(), 1);
        let cert = cert.iter().next().unwrap();
        let kh = if let cert_designator::CertDesignator::Cert(kh) = cert {
            kh
        } else {
            unreachable!("Only CertArg");
        };

        assert_eq!(userid.len(), 1);
        let userid = userid.iter().next().unwrap();
        let kind = match userid {
            userid_designator::UserIDDesignator::UserID(_, userid) => {
                QueryKind::UserIDBinding(kh.clone(), userid.clone())
            }
            userid_designator::UserIDDesignator::Email(_, email) => {
                QueryKind::EmailBinding(kh.clone(), email.clone())
            }
            userid_designator::UserIDDesignator::Name(_, _name) => {
                unreachable!("--name is disabled")
            }
        };

        vec![
            Query {
                argument: Some(format!("{} {}",
                                       cert.argument::<CertPrefix>(),
                                       userid.argument::<UserIDArguments>())),
                kind,
            }
        ]
    }
}

impl<Arguments, Prefix, Options, Doc>
    From<CertDesignators<Arguments, Prefix, Options, Doc>> for Vec<Query>
where
    Arguments: typenum::Unsigned,
    Prefix: cert_designator::ArgumentPrefix,
{
    fn from(designators: CertDesignators<Arguments, Prefix, Options, Doc>)
        -> Vec<Query>
    {
        Query::for_cert_designators(designators)
    }
}

impl<Arguments, Options, Documentation>
    From<UserIDDesignators<Arguments, Options, Documentation>> for Vec<Query>
where
    Arguments: typenum::Unsigned,
{
    fn from(designators: UserIDDesignators<Arguments, Options, Documentation>)
        -> Vec<Query>
    {
        designators.iter()
            .map(|designator| {
                use userid_designator::UserIDDesignator::*;
                let kind = match designator {
                    UserID(_, userid) => QueryKind::UserID(userid.clone()),
                    Email(_, email) => QueryKind::Email(email.clone()),
                    Name(_, _name) => {
                        unreachable!("--name is disabled");
                    }
                };

                Query {
                    argument: Some(designator.argument::<Arguments>()),
                    kind,
                }
            })
            .collect()
    }
}

pub fn required_trust_amount(trust_amount: Option<TrustAmount<usize>>,
                             certification_network: bool)
    -> Result<usize>
{
    let amount = if let Some(v) = &trust_amount {
        v.amount()
    } else {
        if certification_network {
            // Look for multiple paths.  Specifically, try to find 10
            // paths.
            10 * wot::FULLY_TRUSTED
        } else {
            wot::FULLY_TRUSTED
        }
    };

    Ok(amount)
}

// Returns whether there is a matching self-signed User ID.
fn have_self_signed_userid(cert: &Cert,
                           pattern: &UserID, email: bool)
    -> bool
{
    if email {
        if let Ok(Some(pattern)) = pattern.email_normalized() {
            // userid contains a valid email address.
            cert.userids().any(|u| {
                if let Ok(Some(userid)) = u.userid().email_normalized() {
                    pattern == userid
                } else {
                    false
                }
            })
        } else {
            false
        }
    } else {
        cert.userids().any(|u| u.userid() == pattern)
    }
}

/// Authenticate bindings defined by a Query on a Network
///
/// If `gossip` is specified, paths that are not rooted are still
/// shown (with a trust amount of 0, of course).
pub fn authenticate<'store, 'rstore, Q>(
    o: &mut dyn std::io::Write,
    sq: &Sq<'store, 'rstore>,
    queries: Vec<Q>,
    gossip: bool,
    certification_network: bool,
    trust_amount: Option<TrustAmount<usize>>,
    show_paths: bool,
) -> Result<()>
where 'store: 'rstore,
      Q: Into<Query>
{
    tracer!(TRACE, "authenticate");

    let mut queries: Vec<Query>
        = queries.into_iter().map(|q| q.into()).collect();
    if queries.is_empty() {
        queries.push(Query::all());
    };

    let return_all = queries.iter().any(|q| matches!(q.kind, QueryKind::All));

    // Build the network.
    let cert_store = sq.cert_store_or_else()?;
    if return_all {
        cert_store.precompute();
    }

    let mut n = wot::NetworkBuilder::rooted(cert_store, &*sq.trust_roots());
    if certification_network {
        n = n.certification_network();
    }
    let n = n.build();

    let required_amount =
        required_trust_amount(trust_amount, certification_network)?;
    t!("required amount: {} (gossip: {})", required_amount, gossip);

    // Map a key handle to the named certificates.
    let resolve_key_handle = |kh: &KeyHandle| -> Vec<Fingerprint> {
        match kh {
            KeyHandle::Fingerprint(fpr) => vec![ fpr.clone() ],
            KeyHandle::KeyID(_) => {
                if let Ok(certs) = cert_store.lookup_by_cert(&kh) {
                    certs.into_iter().map(|c| c.fingerprint()).collect()
                } else {
                    // We don't error out here: at the end of this
                    // function we check that all queries matched at
                    // least one certificate.
                    vec![]
                }
            }
        }
    };

    // Get the candidates.
    //
    // The `bool` means: always show the certificate, even if it can't
    // be authenticated.  The `Vec<usize>` are the queries that
    // resolve to that binding.
    let mut bindings: Vec<(Fingerprint, Option<UserID>, bool, Vec<usize>)>
        = Vec::new();

    // Whether query #index matched something.
    let mut queries_satisfied = vec![false; queries.len()];

    for (i, query) in queries.iter().enumerate() {
        match &query.kind {
            QueryKind::Cert(kh) => {
                t!("Authenticating {}", kh);

                for fpr in resolve_key_handle(kh) {
                    let count = bindings.len();
                    bindings.extend(
                        n.certified_userids_of(&fpr)
                            .into_iter()
                            .map(|userid| {
                                (fpr.clone(), Some(userid),
                                 true, vec![ i ])
                            }));

                    if bindings.len() == count {
                        // No user IDs.  Add the certificate.
                        bindings.push((fpr.clone(), None,
                                       true, vec![ i ]));
                    }
                }
            }
            QueryKind::UserID(userid) => {
                t!("Authenticating user ID: {:?}", userid);

                bindings.extend(
                    n.lookup_synopses_by_userid(UserID::from(&userid[..]))
                        .into_iter()
                        .map(|fpr| {
                            (fpr, Some(UserID::from(&userid[..])),
                             false, vec![ i ])
                        }));
            }
            QueryKind::EmailBinding(_, email) | QueryKind::Email(email) =>
            {
                let kh = if let QueryKind::EmailBinding(kh, _) = &query.kind {
                    t!("Authenticating binding: {}, {:?}", kh, email);
                    Some(kh)
                } else {
                    t!("Authenticating email: {:?}", email);
                    None
                };

                let userid_check = UserID::from(format!("<{}>", email));
                if let Ok(Some(email_check)) = userid_check.email2() {
                    if email != email_check {
                        return Err(anyhow::anyhow!(
                            "{:?} does not appear to be an email address",
                            email));
                    }
                } else {
                    return Err(anyhow::anyhow!(
                        "{:?} does not appear to be an email address",
                        email));
                }

                // Now, iterate over all of the certifications of the target,
                // and select the bindings where the User ID matches the email
                // address.
                let b = if let Some(kh) = kh.as_ref() {
                    let fprs = resolve_key_handle(kh);
                    fprs.into_iter().flat_map(|fpr| {
                        n.certified_userids_of(&fpr)
                            .into_iter()
                            .map(|userid| (fpr.clone(), Some(userid)))
                            .collect::<Vec<_>>()
                            .into_iter()
                    }).collect::<Vec<_>>()
                } else {
                    n.lookup_synopses_by_email(&email)
                        .into_iter()
                        .map(|(fp, userid)| (fp, Some(userid)))
                        .collect()
                };

                let email_normalized = userid_check.email_normalized()
                    .expect("checked").expect("checked");
                bindings.extend(
                    b.into_iter().filter_map(|(fingerprint, userid_other)| {
                        if let Some(email_other_normalized)
                            = userid_other.as_ref()
                            .and_then(|u| u.email_normalized().ok())
                            .flatten()
                        {
                            if email_normalized == email_other_normalized {
                                Some((fingerprint, userid_other.clone(),
                                      false, vec![ i ]))
                            } else {
                                None
                            }
                        } else {
                            None
                        }
                    }));
            }
            QueryKind::UserIDBinding(kh, userid) => {
                t!("Authenticating {}, {:?}", kh, userid);
                for fpr in resolve_key_handle(kh) {
                    bindings.push((fpr, Some(UserID::from(&userid[..])),
                                   false, vec![ i ]));
                }
            }
            QueryKind::Domain(pattern) | QueryKind::Pattern(pattern) => {
                let pattern_;
                let (query_params, pattern)
                    = if let QueryKind::Domain(_) = query.kind
                {
                    t!("Authenticating domain {}", pattern);

                    let domain = UserIDQueryParams::is_domain(pattern)?;
                    let mut query_params = UserIDQueryParams::new();
                    query_params.set_email(true)
                        .set_anchor_start(false);
                    pattern_ = format!("@{}", domain);

                    (query_params, &pattern_)
                } else {
                    if pattern.is_empty() {
                        t!("Authenticating everything");
                    } else {
                        t!("Authenticating user IDs matching {:?}", pattern);
                    }

                    let mut query_params = UserIDQueryParams::new();
                    query_params
                        .set_email(false)
                        .set_anchor_start(false)
                        .set_anchor_end(false)
                        .set_ignore_case(true);

                    (query_params, pattern)
                };

                if ! pattern.is_empty() {
                    // If the pattern doesn't match anything, don't
                    // abort yet.  There might be other queries.
                    if let Ok(matches)
                        = cert_store.select_userid(&query_params, pattern)
                    {
                        bindings.extend(
                            matches
                            .into_iter()
                            .flat_map(|cert| {
                                cert.userids()
                                    .filter(|userid| {
                                        t!("Checking {}, {}",
                                           cert.fingerprint(),
                                           String::from_utf8_lossy(userid.value()));

                                        query_params.check(&userid, pattern)
                                    })
                                    .map(|userid| {
                                        (cert.fingerprint(), Some(userid),
                                         false, vec![ i ])
                                    })
                                    .collect::<Vec<_>>()
                                    .into_iter()
                            }));
                    }
                } else {
                    bindings.extend(
                        n.certified_userids()
                            .into_iter()
                            .map(|(fp, userid)| {
                                (fp, Some(userid), false, vec![ i ])
                            }));
                }
            }
            QueryKind::All => {
                // --all is always satisfied.
                queries_satisfied[i] = true;

                let mut certs = BTreeSet::new();
                bindings.extend(
                    n.certified_userids()
                        .into_iter()
                        .map(|(fp, userid)| {
                            certs.insert(fp.clone());

                            (fp, Some(userid), false, vec![ i ])
                        }));

                // Add certificates without user IDs.
                let all_certs: BTreeSet<_> = n.iter_fingerprints().collect();
                bindings.extend(
                    all_certs.difference(&certs).map(|fp| {
                        (fp.clone(), None, false, vec![ i ])
                    }));
            }
        }
    }

    // There may be multiple certifications of the same
    // User ID.  Dedup.
    bindings.sort_by(
        |(a_fpr, a_userid, _, _), (b_fpr, b_userid, _, _)|
        {
            a_fpr.cmp(b_fpr)
                .then(a_userid.cmp(b_userid))
        });
    bindings.dedup_by(
        |(a_fpr, a_userid, a_show, a_idx), (b_fpr, b_userid, b_show, b_idx)|
        {
            if a_fpr == b_fpr && a_userid == b_userid {
                // debup removes a, so we merge into b.
                b_idx.extend_from_slice(&a_idx[..]);
                *b_show |= *a_show;
                true
            } else {
                false
            }
        });
    t!("Checking {} bindings", bindings.len());

    // The number of matching bindings that we showed.  Note: this may
    // be more than the number of bindings we really authenticated,
    // because when a certificate is addressed by fingerprint, we
    // always show it.
    let mut bindings_shown = 0;

    let mut output = ConciseHumanReadableOutputNetwork::new(
        o, &sq, required_amount, show_paths);

    for (fingerprint, userid, always_show, i) in bindings.iter() {
        let authenticated = if let Some(userid) = userid {
            let paths = if gossip {
                n.gossip(fingerprint.clone(), userid.clone())
            } else {
                n.authenticate(
                    userid.clone(), fingerprint.clone(), required_amount)
            };

            let aggregated_amount = paths.amount();
            t!("{}, {:?}: {}", fingerprint, userid, aggregated_amount);
            let authenticated = if aggregated_amount >= required_amount {
                // We authenticated the binding!
                true
            } else if gossip {
                // We're in gossip mode, show everything.
                true
            } else if *always_show {
                // We're authenticating a certificate, which was specified
                // explicitly.  We don't consider it authenticated, but we
                // do want to show it.
                false
            } else {
                // Don't show it.
                t!("Failed to sufficiently authenticate the binding");
                continue;
            };

            let paths = paths.into_iter().collect::<Vec<(wot::Path, usize)>>();

            output.add_cert(fingerprint)?;
            output.add_paths(paths, fingerprint, userid, aggregated_amount)?;

            authenticated
        } else {
            // A cert without bindings.
            output.add_cert(fingerprint)?;

            true
        };

        bindings_shown += 1;

        if authenticated {
            for i in i.into_iter() {
                queries_satisfied[*i] = true;
            }
        }
    }

    output.finalize()?;

    let mut unsatisfied = 0;
    for (i, satisfied) in queries_satisfied.into_iter().enumerate() {
        if satisfied {
            continue;
        }
        unsatisfied += 1;

        // We didn't show anything.  Try to figure out what was wrong.
        let query = &queries[i];

        if gossip {
            weprintln!("No bindings match {}.",
                       query.argument.as_deref().unwrap_or("the query"));
        } else {
            weprintln!("No bindings matching {} could be authenticated.",
                       query.argument.as_deref().unwrap_or("the query"));
        }

        if let Some(kh) = query.kind.key_handle() { 'lint_cert: {
            // See if the target certificate exists.
            let certs_;
            let cert = match cert_store.lookup_by_cert_or_subkey(&kh) {
                Ok(certs) => {
                    assert!(certs.len() > 0);

                    certs_ = certs;
                    if let Some(cert) = certs_.iter().find(|c| c.key_handle() == kh) {
                        match cert.to_cert() {
                            Ok(cert) => cert,
                            Err(err) => {
                                weprintln!("{} is invalid: {}",
                                           cert.fingerprint(), err);
                                break 'lint_cert;
                            }
                        }
                    } else {
                        weprintln!("{} is a subkey of {}",
                                   kh,
                                   certs_.iter()
                                       .map(|c| {
                                           c.fingerprint().to_string()
                                       })
                                       .collect::<Vec<_>>()
                                       .join(", "));
                        break 'lint_cert;
                    }
                }
                Err(err) => {
                    weprintln!("Looking up {}: {}", kh, err);
                    break 'lint_cert;
                }
            };

            // Check that it is valid.
            match cert.with_policy(sq.policy, sq.time) {
                Ok(vc) => {
                    // The certificate is valid under the current
                    // policy.

                    // Check if the certificate has expired.
                    if let Err(err) = vc.alive() {
                        weprintln!("Warning: {} is not live: {}.",
                                   cert.fingerprint(), err);
                    }
                }
                Err(err) => {
                    weprintln!("Warning: {} is not valid according to \
                                the current policy: {}.",
                               cert.fingerprint(),
                               crate::one_line_error_chain(err));
                }
            };

            // Check if the certificate was revoked.
            if let RevocationStatus::Revoked(sigs)
                = cert.revocation_status(sq.policy, sq.time)
            {
                if let Some((reason, message))
                    = sigs[0].reason_for_revocation()
                {
                    weprintln!("Warning: {} is revoked: {}{}.",
                               cert.fingerprint(),
                               reason,
                               ui::Safe(message));
                } else {
                    weprintln!("Warning: {} is revoked: unspecified reason.",
                               cert.fingerprint());
                }
            }

            // See if there is a matching self-signed User ID.
            if let Some(userid) = query.kind.userid() {
                if ! have_self_signed_userid(cert, &UserID::from(userid), false) {
                    weprintln!("Warning: {} is not a \
                                self-signed User ID for {}.",
                               userid, cert.fingerprint());
                }
            } else if let Some(email) = query.kind.email() {
                if ! have_self_signed_userid(cert, &UserID::from(email), true) {
                    weprintln!("Warning: {} does not appear in \
                                self-signed User ID for {}.",
                               email, cert.fingerprint());
                }
            }

            // See if there are any certifications made on
            // this certificate.
            if let Ok(cs) = n.certifications_of(&cert.fingerprint(), 0.into()) {
                if cs.iter().all(|cs| {
                    cs.certifications()
                        .all(|(_userid, certifications)| {
                            certifications.is_empty()
                        })
                })
                {
                    weprintln!("Warning: {} was never certified.",
                               cert.fingerprint());
                }
            }
        }}
    }

    // See if the trust roots exist.
    if unsatisfied > 0 && ! gossip {
        if n.roots().iter().all(|r| {
            let fpr = r.fingerprint();
            if let Err(err) = n.lookup_synopsis_by_fpr(&fpr) {
                weprintln!("Looking up trust root ({}): {}.",
                           fpr, err);
                true
            } else {
                false
            }
        })
        {
            weprintln!("Warning: No trust roots found.");
        }
    }

    if bindings.is_empty() {
        // There are no matching bindings.

        weprintln!("No bindings match.");

        if queries.len() == 1 {
            if let QueryKind::Pattern(pattern) = &queries[0].kind {
                // Tell the user about `sq network fetch`.
                sq.hint(format_args!(
                    "Try searching public directories:"))
                    .sq().arg("network").arg("search")
                    .arg(pattern)
                    .done();
            }
        } else if n.iter_fingerprints().next().is_none() {
            weprintln!("Warning: The certificate store does not contain any \
                        certificates.");

            if return_all {
                sq.hint(format_args!(
                    "Consider creating a key for yourself:"))
                    .sq().arg("key").arg("generate")
                    .arg_value("--name", "your-name")
                    .arg_value("--email", "your-email-address")
                    .arg("--own-key")
                    .done();

                sq.hint(format_args!(
                    "Consider importing other peoples' certificates:"))
                    .sq().arg("cert").arg("import")
                    .arg("a-cert-file.pgp")
                    .done();

                sq.hint(format_args!(
                    "Try searching public directories for other peoples' \
                     certificates:"))
                    .sq().arg("network").arg("search")
                    .arg("some-mail-address")
                    .done();
            }
        }
    } else if gossip {
        // We are in gossip mode.  Mention `sq pki link` as a way to
        // mark bindings as authenticated.
        if ! bindings.is_empty() {
            weprintln!("After checking that a user ID really belongs to \
                        a certificate, use `sq pki link add` to mark \
                        the binding as authenticated, or use \
                        `sq network search FINGERPRINT|EMAIL` to look for \
                        new certifications.");
        }
    } else if bindings.len() - bindings_shown > 0 {
        // Some of the matching bindings were not shown.  Tell the
        // user about the `--gossip` option.
        let bindings = bindings.len();
        assert!(bindings > 0);
        let bindings_not_shown = bindings - bindings_shown;

        if bindings == 1 {
            weprintln!("1 binding found.");
        } else {
            weprintln!("{} bindings found.", bindings);
        }

        if bindings_not_shown == 1 {
            weprintln!("Skipped 1 binding, which could not be authenticated.");
            weprintln!("Pass `--gossip` to see the unauthenticated binding.");
        } else {
            weprintln!("Skipped {} bindings, which could not be authenticated.",
                      bindings_not_shown);
            weprintln!("Pass `--gossip` to see the unauthenticated bindings.");
        }
    }

    if unsatisfied == 1 {
        if gossip {
            Err(anyhow::anyhow!("No bindings match the query."))
        } else {
            Err(anyhow::anyhow!(
                "No bindings matching the query could be authenticated."))
        }
    } else if unsatisfied > 1 {
        if gossip {
            Err(anyhow::anyhow!("No bindings match {} of the queries.",
                                unsatisfied))
        } else {
            Err(anyhow::anyhow!(
                "No bindings matching {} of the queries could be authenticated.",
                unsatisfied))
        }
    } else {
        Ok(())
    }
}

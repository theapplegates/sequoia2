use super::common::Sq;

#[test]
fn sq_pki_authorize_then_authenticate() {
    let mut sq = Sq::new();

    let otto_somewhere_com = "<otto@somewhere.com>";
    let (otto, otto_pgp, _otto_rev)
        = sq.key_generate(&[], &[otto_somewhere_com]);
    sq.key_import(&otto_pgp);

    let ca_example_org = "<ca@example.org>";
    let (ca, ca_pgp, _ca_rev)
        = sq.key_generate(&[], &[ca_example_org]);
    sq.key_import(&ca_pgp);

    let alice_example_org = "<alice@example.org>";
    let (alice, alice_pgp, _alice_rev)
        = sq.key_generate(&[], &[alice_example_org]);
    sq.key_import(&alice_pgp);

    let bob_example_org = "<bob@example.org>";
    let bob_other_org = "<bob@other.org>";
    let (bob, bob_pgp, _bob_rev)
        = sq.key_generate(&[], &[bob_example_org, bob_other_org]);
    sq.key_import(&bob_pgp);

    sq.tick(1);

    // The ca certifies alice's and bob's certificates for each of
    // their user IDs.
    let certification = sq.scratch_file(None);
    sq.pki_certify(&[],
                   ca.key_handle(), alice.key_handle(),
                   &[ alice_example_org ],
                   certification.as_path());
    sq.cert_import(&certification);

    let certification = sq.scratch_file(None);
    sq.pki_certify(&[],
                   ca.key_handle(), bob.key_handle(),
                   &[ bob_example_org, bob_other_org ],
                   certification.as_path());
    sq.cert_import(certification);

    // Check whether we can authenticate alice's and bob's
    // certificates for their user ID using otto as the trust root.
    let check = |sq: &Sq,
                 can_authenticate_alice,
                 can_authenticate_bob1,
                 can_authenticate_bob2|
    {
        for (cert, userid, can_authenticate) in &[
            (&alice, alice_example_org, can_authenticate_alice),
            (&bob, bob_example_org, can_authenticate_bob1),
            (&bob, bob_other_org, can_authenticate_bob2),
        ]
        {
            let r = sq.pki_authenticate(
                &["--trust-root", &otto.fingerprint().to_string() ],
                &cert.fingerprint().to_string(),
                userid);

            match (can_authenticate, r.is_ok()) {
                (true, false) => {
                    panic!("Expected to authenticated {}, but didn't.",
                           userid);
                }
                (false, true) => {
                    panic!("Expected to NOT authenticated {}, but did.",
                           userid);
                }
                _ => (),
            }
        }
    };

    // No delegation yet.
    println!("CA: not authorized");
    check(
        &sq,
        false, // Alice.
        false, // bob@example.org
        false);// bob@other.org

    // Otto authorizes completely to the CA.
    let certification = sq.scratch_file(None);
    sq.tick(1);
    sq.pki_authorize(&["--unconstrained"],
                     otto.key_handle(), ca.key_handle(),
                     &[],
                     certification.as_path());
    sq.cert_import(certification);

    println!("CA: authorized, and unconstrained");
    check(
        &sq,
        true, // alice@example.org
        true, // bob@example.org
        true);// bob@other.org

    // Otto authorizes to the CA with the regex contraint "example".
    let certification = sq.scratch_file(None);
    sq.tick(1);
    sq.pki_authorize(&["--regex", "example"],
                     otto.key_handle(), ca.key_handle(),
                     &[],
                     certification.as_path());
    sq.cert_import(certification);

    println!("CA: authorized for \"example\"");
    check(
        &sq,
        true,  // alice@example.org
        true,  // bob@example.org
        false);// bob@other.org

    // Otto authorizes to the CA with the domain contraint "example.org".
    let certification = sq.scratch_file(None);
    sq.tick(1);
    sq.pki_authorize(&["--domain", "example.org"],
                     otto.key_handle(), ca.key_handle(),
                     &[],
                     certification.as_path());
    sq.cert_import(certification);

    println!("CA: authorized for \"example.org\"");
    check(
        &sq,
        true,  // alice@example.org
        true,  // bob@example.org
        false);// bob@other.org

    // Otto authorizes to the CA with the regex contraint "other".
    let certification = sq.scratch_file(None);
    sq.tick(1);
    sq.pki_authorize(&["--regex", "other"],
                     otto.key_handle(), ca.key_handle(),
                     &[],
                     certification.as_path());
    sq.cert_import(certification);

    println!("CA: authorized for \"other\"");
    check(
        &sq,
        false, // alice@example.org
        false, // bob@example.org
        true); // bob@other.org

    // Otto authorizes to the CA with the regex contraint "bob".
    let certification = sq.scratch_file(None);
    sq.tick(1);
    sq.pki_authorize(&["--regex", "bob"],
                     otto.key_handle(), ca.key_handle(),
                     &[],
                     certification.as_path());
    sq.cert_import(certification);

    println!("CA: authorized for \"bob\"");
    check(
        &sq,
        false, // alice@example.org
        true,  // bob@example.org
        true); // bob@other.org

    // Otto authorizes to the CA with the regex contraint "bob" or "alice".
    let certification = sq.scratch_file(None);
    sq.tick(1);
    sq.pki_authorize(&["--regex", "bob", "--regex", "alice"],
                     otto.key_handle(), ca.key_handle(),
                     &[],
                     certification.as_path());
    sq.cert_import(certification);

    println!("CA: authorized for \"bob\" or \"alice\"");
    check(
        &sq,
        true, // alice@example.org
        true, // bob@example.org
        true);// bob@other.org


    // Otto authorizes to the CA for the domains example.org and other.org.
    let certification = sq.scratch_file(None);
    sq.tick(1);
    sq.pki_authorize(&["--domain", "example.org", "--domain", "other.org"],
                     otto.key_handle(), ca.key_handle(),
                     &[],
                     certification.as_path());
    sq.cert_import(certification);

    println!("CA: authorized for the domains example.org and other.org");
    check(
        &sq,
        true, // alice@example.org
        true, // bob@example.org
        true);// bob@other.org


    // Otto authorizes to the CA for the domain example.com and the regex alice.
    let certification = sq.scratch_file(None);
    sq.tick(1);
    sq.pki_authorize(&["--domain", "other.org", "--regex", "alice"],
                     otto.key_handle(), ca.key_handle(),
                     &[],
                     certification.as_path());
    sq.cert_import(certification);

    println!("CA: authorized for the domains example.org and other.org");
    check(
        &sq,
        true,  // alice@example.org
        false, // bob@example.org
        true); // bob@other.org


    // Otto authorizes to the CA with the regex contraint "zoo".
    let certification = sq.scratch_file(None);
    sq.tick(1);
    sq.pki_authorize(&["--regex", "zoo"],
                     otto.key_handle(), ca.key_handle(),
                     &[],
                     certification.as_path());
    sq.cert_import(certification);

    println!("CA: authorized for \"zoo\"");
    check(
        &sq,
        false, // alice@example.org
        false, // bob@example.org
        false);// bob@other.org

    // Otto authorizes to the CA with the domain contraint "example".
    let certification = sq.scratch_file(None);
    sq.tick(1);
    sq.pki_authorize(&["--domain", "example"],
                     otto.key_handle(), ca.key_handle(),
                     &[],
                     certification.as_path());
    sq.cert_import(certification);

    println!("CA: authorized for \"zoo\"");
    check(
        &sq,
        false, // alice@example.org
        false, // bob@example.org
        false);// bob@other.org
}

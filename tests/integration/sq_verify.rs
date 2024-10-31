use std::fs::File;
use std::io::Seek;
use std::io::Write;
use std::io;

use sequoia_openpgp as openpgp;
use openpgp::Result;

use super::common::Sq;

// Make sure verifying bad data fails, and removes the intermediate
// file.
#[test]
fn sq_verify_bad() -> Result<()> {
    let sq = Sq::new();

    // The signer.
    let (_cert, cert_file, _rev_file) = sq.key_generate(&[], &["alice"]);

    // Create a big file.  When verifying, we buffer the first ~25 MB
    // of verified data so that we can at least withhold some data if
    // we can't verify the message.
    let data_file = sq.scratch_file("data");
    let size = {
        let mut file = File::create(&data_file)?;
        let data = vec![42; 1024 * 1024];
        let mut size = 0;
        for _ in 0..100 {
            file.write_all(&data).expect("can write");
            size += data.len();
        }

        size as u64
    };
    assert_eq!(std::fs::metadata(&data_file).expect("can stat").len(),
               size);

    // Sign the message.
    let sig_file = sq.scratch_file("sig");
    sq.sign(&cert_file, None, &data_file, sig_file.as_path());

    // Verify the signed message.
    let output = sq.scratch_file("output");
    std::fs::write(&output, "xxx").expect("can write to scratch file");
    sq.verify(
        &["--overwrite",
          "--signer-file", &cert_file.display().to_string()],
        &sig_file,
        output.as_path());
    assert!(output.exists());
    assert_eq!(std::fs::metadata(&output).expect("can stat").len(),
               size);

    // Modify the data, and make sure verification now fails.
    let mut f = File::options().write(true).open(&sig_file)?;
    f.seek(io::SeekFrom::Start(size / 2)).expect("can seek");
    f.write_all(b"xxx").expect("can write");
    drop(f);

    let output2 = sq.scratch_file("output2");
    std::fs::write(&output2, "xxx").expect("can write to scratch file");
    assert!(
        sq.verify_maybe(
            &["--overwrite",
              "--signer-file", &cert_file.display().to_string()],
            &sig_file,
            output2.as_path())
            .is_err());
    // Since we failed to verify the message, we should have deleted
    // the output file.
    assert!(! output2.exists());

    Ok(())
}

use sequoia_openpgp as openpgp;
use openpgp::KeyHandle;

use sequoia_keystore as keystore;
use keystore::Protection;

use crate::best_effort_primary_uid;
use crate::cli;
use crate::Sq;
use crate::Result;

pub fn list(sq: Sq, _command: cli::key::ListCommand) -> Result<()> {
    // Start and connect to the keystore.
    let ks = if let Some(ks) = sq.key_store()? {
        ks
    } else {
        // The key store is disabled.  Don't fail, just return
        // nothing.
        return Ok(());
    };
    let mut ks = ks.lock().unwrap();

    let mut backends = ks.backends()?;
    for backend in &mut backends {
        let devices = backend.list()?;
        if devices.len() == 0 {
            println!(" - Backend {} has no devices.", backend.id()?);
        } else {
            println!(" - {}", backend.id()?);
        }

        for mut device in devices {
            let keys = device.list()?;
            if keys.len() == 0 {
                println!("   - Device {} has no keys.", device.id()?);
            } else {
                println!("   - {}", device.id()?);
            }

            for mut key in keys.into_iter() {
                let fpr = KeyHandle::from(key.fingerprint());

                let sanitized_userid = if let Ok(cert)
                    = sq.lookup_one(&fpr, None, true)
                {
                    best_effort_primary_uid(
                        Some(&sq), &cert, sq.policy, None)
                } else {
                    crate::PreferredUserID::unknown()
                };

                let signing_capable = key.signing_capable().unwrap_or(false);
                let decryption_capable = key.decryption_capable().unwrap_or(false);
                println!("     - {} {} ({}, {}, {})",
                         fpr, sanitized_userid,
                         if key.available().unwrap_or(false) {
                             "available"
                         } else {
                             "not available"
                         },
                         match key.locked() {
                             Ok(Protection::Unlocked) => "unlocked",
                             Ok(_) => "locked",
                             Err(_) => "unknown protection",
                         },
                         match (signing_capable, decryption_capable) {
                             (true, true) => {
                                 "for signing and decryption"
                             }
                             (true, false) => {
                                 "for signing"
                             }
                             (false, true) => {
                                 "for decryption"
                             }
                             (false, false) => {
                                 "unusable"
                             }
                         });
            }
        }
    }

    Ok(())
}

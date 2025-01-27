use sequoia_openpgp as openpgp;
use openpgp::packet::Signature;

use crate::Result;
use crate::common::ui;

/// `link` is whether "link" should be used to talk about the
/// certification or "certification".
pub fn summarize_certification(o: &mut dyn std::io::Write,
                               indent: &str,
                               certification: &Signature,
                               link: bool)
    -> Result<()>
{
    let (link, linked) = if link {
        ("link", "linked")
    } else {
        ("certification", "certified")
    };

    let indent = &format!("{} - ", indent)[..];

    if let Some(t) = certification.signature_creation_time() {
        wwriteln!(stream=o, initial_indent=indent,
                  "created at {}",
                  chrono::DateTime::<chrono::Utc>::from(t)
                  .format("%Y‑%m‑%d %H:%M:%S"));
    } else {
        wwriteln!(stream=o, initial_indent=indent,
                  "creation time missing");
    }

    let (depth, amount) = certification.trust_signature()
        .unwrap_or((0, sequoia_wot::FULLY_TRUSTED as u8));

    if amount == 0 {
        wwriteln!(stream=o, initial_indent=indent,
                  "{} was retracted", link);
    } else {
        let mut regex: Vec<_> = certification.regular_expressions()
            .map(|re| ui::Safe(re).to_string())
            .collect();
        regex.sort();
        regex.dedup();

        if depth > 0 {
            if amount == sequoia_wot::FULLY_TRUSTED as u8
                && regex.is_empty()
            {
                wwriteln!(stream=o, initial_indent=indent,
                          "{} as a fully trusted CA", linked);
            } else {
                wwriteln!(stream=o, initial_indent=indent,
                          "{} as a partially trusted CA", linked);
            }
        }

        if let Some(e) = certification.signature_expiration_time() {
            wwriteln!(stream=o, initial_indent=indent,
                      "expiration: {}",
                      chrono::DateTime::<chrono::Utc>::from(e)
                      .format("%Y‑%m‑%d"));
        }

        if depth != 0 && depth != 255 {
            wwriteln!(stream=o, initial_indent=indent,
                      "trust depth: {}", depth);
        }

        if amount != sequoia_wot::FULLY_TRUSTED as u8 {
            wwriteln!(stream=o, initial_indent=indent,
                      "trust amount: {}", amount);
        }

        if ! regex.is_empty() {
            wwriteln!(stream=o, initial_indent=indent,
                      "regular expressions: {}", regex.join("; "));
        }
    }

    Ok(())
}

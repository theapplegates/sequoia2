use terminal_size::terminal_size;

use sequoia_openpgp as openpgp;
use openpgp::armor;

use crate::Config;
use crate::Result;
use crate::commands;
use crate::load_keys;
use crate::sq_cli;

pub fn dispatch(config: Config, command: sq_cli::packet::Command)
    -> Result<()>
{
    tracer!(TRACE, "packet::dispatch");
    match command.subcommand {
        sq_cli::packet::Subcommands::Dump(command) => {
            let mut input = command.input.open()?;
            let output_type = command.output;
            let mut output = output_type.create_unsafe(config.force)?;

            let session_key = command.session_key;
            let width = if let Some((width, _)) = terminal_size() {
                Some(width.0.into())
            } else {
                None
            };
            commands::dump(&mut input, &mut output,
                           command.mpis, command.hex,
                           session_key.as_ref(), width)?;
        },

        sq_cli::packet::Subcommands::Decrypt(command) => {
            let mut input = command.input.open()?;
            let mut output = command.output.create_pgp_safe(
                config.force,
                command.binary,
                armor::Kind::Message,
            )?;

            let secrets =
                load_keys(command.secret_key_file.iter().map(|s| s.as_ref()))?;
            let session_keys = command.session_key;
            commands::decrypt::decrypt_unwrap(
                config,
                &mut input, &mut output,
                secrets,
                session_keys,
                command.dump_session_key)?;
            output.finalize()?;
        },

        sq_cli::packet::Subcommands::Split(command) => {
            let mut input = command.input.open()?;
            let prefix =
            // The prefix is either specified explicitly...
                command.prefix.unwrap_or(
                    // ... or we derive it from the input file...
                    command.input.and_then(|x| {
                        // (but only use the filename)
                        x.file_name().map(|f|
                                          String::from(f.to_string_lossy())
                        )
                    })
                    // ... or we use a generic prefix...
                        .unwrap_or_else(|| String::from("output"))
                    // ... finally, add a hyphen to the derived prefix.
                        + "-");
            commands::split(&mut input, &prefix)?;
        },
        sq_cli::packet::Subcommands::Join(command) => {
            commands::join(config, command)?;
        }
    }

    Ok(())
}

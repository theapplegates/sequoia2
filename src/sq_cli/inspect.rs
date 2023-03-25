use clap::Parser;

#[derive(Parser, Debug)]
#[clap(
    name = "inspect",
    about = "Inspects data, like file(1)",
    long_about =
"Inspects data, like file(1)

It is often difficult to tell from cursory inspection using cat(1) or
file(1) what kind of OpenPGP one is looking at.  This subcommand
inspects the data and provides a meaningful human-readable description
of it.

\"sq inspect\" respects the reference time set by the top-level
\"--time\" argument.  It uses the reference time when determining what
binding signatures are active.
",
    after_help =
"EXAMPLES:

# Inspects a certificate
$ sq inspect juliet.pgp

# Inspects a certificate ring
$ sq inspect certs.pgp

# Inspects a message
$ sq inspect message.pgp

# Inspects a detached signature
$ sq inspect message.sig

# Show the certificate as it looked on July 21, 2013
$ sq inspect --time 20130721 cert.pgp
",
)]
pub struct Command {
    #[clap(
        value_name = "FILE",
        help = "Reads from FILE or stdin if omitted",
    )]
    pub input: Option<String>,
    #[clap(
        long = "certifications",
        help = "Prints third-party certifications",
    )]
    pub certifications: bool,
}

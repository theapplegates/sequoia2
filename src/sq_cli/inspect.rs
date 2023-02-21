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
    #[clap(
        long = "time",
        value_name = "TIME",
        help = "Sets the certification time to TIME (as ISO 8601)",
        long_help = "\
Sets the certification time to TIME.  TIME is interpreted as an ISO 8601 \
timestamp.  To set the certification time to July 21, 2013 at midnight UTC, \
you can do:

$ sq inspect --time 20130721 cert.pgp

To include a time, add a T, the time and optionally the timezone (the \
default timezone is UTC):

$ sq inspect --time 20130721T0550+0200 cert.pgp
"
    )]
    pub time: Option<String>,
}

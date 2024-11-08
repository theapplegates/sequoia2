use crate::integration::common::Sq;

/// Check that invalid syntax is caught.
#[test]
fn version() {
    let sq = Sq::new();

    let version = format!(
        "{}.{}.{}",
        env!("CARGO_PKG_VERSION_MAJOR"),
        env!("CARGO_PKG_VERSION_MINOR"),
        env!("CARGO_PKG_VERSION_PATCH"));

    // Make sure "--cli-version" works.
    let cmd = sq.command_args(&[
        "--cli-version", &version,
        "version"
    ][..]);
    sq.run(cmd, true);

    // Unsupported versions should be rejected.
    let cmd = sq.command_args(&[
        "--cli-version", "0.0.0",
        "version"
    ]);
    sq.run(cmd, false);

    // --cli-version must be the first argument.
    let cmd = sq.command_args(&[
        "version",
        "--cli-version", &version
    ]);
    sq.run(cmd, false);

    // Invalid versions should be rejected.
    let cmd = sq.command_args(&[
        "--cli-version", &version[1..],
        "version"
    ]);
    sq.run(cmd, false);

}

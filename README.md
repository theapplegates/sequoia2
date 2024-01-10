# sq, the Sequoia-PGP command line tool

[Sequoia-PGP][] is an implementation of OpenPGP in Rust. It includes a
suite of library crates, which are meant to be used from applications.
This crate provides the `sq` command line application. `sq` is aimed
at command line users as a way to use OpenPGP conveniently from the
command line.

See the [sq user guide][] for instructions. The program also has built-in
help, using the `--help` option and `help` subcommand:

~~~sh
$ sq help
...
~~~

You can also browse the [manual pages][], look at our [acceptance
criteria][], and browse the [rustdoc output][] if you want to learn about
the implementation.

[Sequoia-PGP]: https://sequoia-pgp.org/
[sq user guide]: https://sequoia-pgp.gitlab.io/sq-user-guide/
[manual pages]: https://sequoia-pgp.gitlab.io/sequoia-sq/man/
[acceptance criteria]: https://sequoia-pgp.gitlab.io/sequoia-sq/subplot/
[rustdoc output]: https://sequoia-pgp.gitlab.io/sequoia-sq/impl/

## Building

This crate can be built using the standard `cargo` toolchain:

```sh
cargo build
```

The above creates the `sq` executable, the manual pages, and its shell
completions.  By default, the manual pages and shell completions are
put into the `cargo` target directory, but the exact location is
unpredictable.  To write the assets to a predictable location, set the
environment variable `ASSET_OUT_DIR` to a suitable location.

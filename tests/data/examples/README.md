# Introduction

This directory contains data for the examples.

The test suite executes each subcommand's examples.  Each subcommand
has its own context (temporary directory), which is set to the current
working directory.  The contents of this directory are copied into
that directory.  If a subcommand has multiple examples, they are
execute after each other in the same context.

By using static data, we can use known fingerprints in the examples.

# Contents

- alice-secret.pgp: A general-purpose certificate for Alice
  <alice@example.org>.

    - Imported into the cert store.

- bob-secret.pgp: A general-purpose certificate for Bob
  <bob@example.org>.

    - Imported into the cert store.
    - Certified by Alice.

- juliet.pgp: A general-purpose certificate for Juliet Capulet
  <juliet@example.org>.

    - NOT imported into the cert store.

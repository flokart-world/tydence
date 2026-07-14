# tydence

RFC 3161 trusted timestamps for git-managed data.

tydence lets you prove that the contents of a git repository existed
at a certain point in time. It generates a manifest over the
repository state, obtains RFC 3161 timestamp tokens from one or more
Time Stamping Authorities, and stores both inside the repository
itself so that the evidence travels with the data.

The proof is carried by the manifests and tokens; git provides
transport and organization. Git's object hashes are never part of
the evidential chain, so the proof is equally strong in SHA-1 and
SHA-256 repositories and does not rest on git's own integrity.

## How it works

A **stamp** is a commit whose tree carries the evidence for its own
snapshot:

- `.tydence/manifest` — a canonical listing of every tracked file
  under SHA-256 + SHA3-256 double hashes; the message imprint sent
  to each TSA is a hash of these bytes
- `.tydence/tokens/<site>.tsr` — one RFC 3161 token per site of the
  chosen profile, fully verified before anything is sealed
- `.tydence/ltv/` — TSA certificate chains and CRL snapshots, kept
  in the repository so tokens remain verifiable long after the TSA
  or its certificates are gone

Every manifest also binds the nearest earlier stamps by hash (the
**renewal chain**), so one fresh stamp simultaneously re-stamps the
current content and renews all earlier evidence. Verification is
fail-closed: a stamp passes or fails, and anything undecidable
fails.

## Quick start

Install the command (Rust 1.95 or later):

```console
$ cargo install --locked tydence-cli
```

Define sites and profiles in `.tydence/config` and commit it — the
stamping policy is ordinary tracked content:

```
Site freetsa
    URL https://freetsa.org/tsr
    Imprint sha512

Profile default
    UseSite freetsa
```

Name the TSA root certificates you have decided to trust. Anchors
are machine-local by design — a repository must not certify itself —
and are obtained out of band (a TSA publishes its root):

```console
$ git config --add tydence.anchor ~/trust/freetsa-root.pem
```

Stamp the current branch tip and judge the result:

```console
$ tydence stamp --profile default
sealed 5b1f0f4a... on refs/heads/master
$ tydence verify
PASS 5b1f0f4a... (freetsa at 2026-07-14T09:00:00+00:00)
```

## Commands

| Command | Purpose |
|---------|---------|
| `tydence stamp` | Seal a stamp commit over the current branch |
| `tydence verify` | Judge the stamps that carry a commit |
| `tydence precommit` | Refuse a commit that would carry staged stamp artifacts |
| `tydence drop` | Declare the next commit ordinary: drop staged stamp artifacts |

Every command takes `-C <path>` to run as if started there, as in
git. `tydence help <command>` documents each command in detail.

## Documentation

- [Command manual](docs/user_manuals/commands.md) — invocation,
  trust anchor management, hook installation, daily operation
- [Configuration manual](docs/user_manuals/config.md) — the
  `.tydence/config` format: sites, profiles, failure behavior
- [Stamping specification](docs/stamping.md) — the evidential model
  and data formats: manifest, renewal chain, verification, epoch
  rollover

## Crates

- `tydence` — the library: stamping, verification and repository
  audit as a Rust API
- `tydence-cli` — the thin `tydence` binary over it
- `tydence-ucd` — internal proc-macro crate generating the frozen
  Unicode tables the manifest path encoding pins per format version

## Etymology

The name is a coinage of *time* and *evidence*.

## Status

0.1.0 is the first public release. The stamping flow, fail-closed
verification and the command line are implemented and exercised
end-to-end against a live TSA.

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or
  <http://www.apache.org/licenses/LICENSE-2.0>)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or
  <http://opensource.org/licenses/MIT>)

at your option.

`tydence-ucd` redistributes Unicode Character Database files, which
additionally carry the [Unicode License v3](crates/tydence-ucd/data/UNICODE-LICENSE.txt).

### Contribution

Unless you explicitly state otherwise, any contribution intentionally
submitted for inclusion in the work by you, as defined in the Apache-2.0
license, shall be dual licensed as above, without any additional terms or
conditions.

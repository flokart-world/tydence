# tydence

RFC 3161 trusted timestamps for git-managed data.

tydence lets you prove that the contents of a git repository existed at a
certain point in time. It generates a manifest over the repository state,
obtains RFC 3161 timestamp tokens from one or more Time Stamping Authorities,
and stores both inside the repository itself so that the evidence travels
with the data.

The proof is carried by the manifests and tokens; git provides transport
and organization.

## Status

Under initial development. Not yet functional.

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or
  <http://www.apache.org/licenses/LICENSE-2.0>)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or
  <http://opensource.org/licenses/MIT>)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally
submitted for inclusion in the work by you, as defined in the Apache-2.0
license, shall be dual licensed as above, without any additional terms or
conditions.

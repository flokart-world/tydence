# Changelog

## [0.1.0] - 2026-07-15

### Added
- Stamping: `tydence stamp` seals a commit whose tree carries a
  canonical double-hash (SHA-256 + SHA3-256) manifest of every
  tracked file and one RFC 3161 token per site of the chosen
  profile. Every token is fully verified before anything is sealed;
  an invalid token never enters the repository.
- Verification: `tydence verify` judges the stamps that carry a
  commit with a binary, fail-closed verdict — manifest/tree
  agreement in both directions, full token verification including
  revocation against the CRL snapshots sealed in the repository,
  and renewal-chain linkage back to the bound earlier stamps.
- Renewal chain: each stamp binds the nearest earlier stamp on
  every line of history by hash, so a single zero-content-change
  stamp re-stamps the current content and renews all earlier
  evidence at once. The same stamp form retroactively introduces
  tydence into an existing repository.
- Multi-TSA profiles: sites and profiles are declared in
  `.tydence/config`, committed to the repository so the stamping
  policy itself is preserved as evidence. A site failure aborts the
  stamp unless the profile marks it `ContinueOnError`.
- Long-term validation: TSA certificate chains and CRL snapshots
  are stored under `.tydence/ltv/` and refreshed at each stamp, so
  tokens remain verifiable after a TSA disappears. Material first
  learned from a fresh token is deposited and queued for the next
  commit; `stamp` and `verify` report unsealed deposits until they
  are sealed.
- Trust anchors come from outside the repository — the
  `tydence.anchor` git configuration key or `--anchor` — never from
  the repository itself.
- Commit hygiene: `tydence precommit` (for the pre-commit hook)
  refuses an ordinary commit that would carry resurrected stamp
  artifacts, and `tydence drop` clears them.
- `tydence stamp --amend` replaces an unshared branch tip instead
  of adding a new commit.
- Stamp commits receive `Tydence-Stamp` trailers carrying the
  manifest's double hash, for reading `git log` — no verification
  reads them.
- Works identically in SHA-1 and SHA-256 repositories: the evidence
  never rests on git object hashes.
- Documentation: [stamping specification](docs/stamping.md),
  [configuration manual](docs/user_manuals/config.md) and
  [command manual](docs/user_manuals/commands.md).

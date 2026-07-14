# tydence stamping specification

This document specifies the stamping model and data formats: what a
stamp is, what it covers, and how it is verified.

## 1. Purpose and doctrine

tydence attaches RFC 3161 trusted timestamps to data managed in a git
repository, making it provable to a third party that the data existed
at a certain point in time and has not been altered since.

The design rests on one principle:

> **The proof is carried by manifests and timestamp tokens; git
> provides transport and organization.**

A proof-of-existence hash chain must still be sound decades later, at
the time a dispute is examined — not merely at the time of stamping.
Git's internal object hashes (as of 2026, SHA-1 is already broken
and SHA-256 is unproven over multi-decade spans) are therefore never
part of the evidential chain. The evidence layer consists solely of:

```
RFC 3161 token → manifest → actual file contents
```

where every link uses strong, algorithm-agile hashes. Git commit
hashes and topology are recorded in the manifest only as *position
annotations* — they locate the stamp within the repository and add
transport-level rigidity, but no legal claim rests on them.

| Layer | Responsibility | Components | Hashes relied upon |
|-------|----------------|------------|--------------------|
| Evidence | Proof of existence, sealing, renewal chain | Manifest, RFC 3161 tokens, LTV data | SHA-256 + SHA3-256 (agile) |
| Transport | Versioning, distribution, day-to-day tamper detection | Git history | Git object hashes (not relied upon) |

Consequences:

- Only **stamped commits** carry TSA-grade proof of existence.
  Unstamped commits between stamps are supported by transport-layer
  integrity alone. Stamping frequency is an operational choice.
- The proof is independent of the repository's git object format
  (SHA-1 or SHA-256): evidential strength is identical in both.
- An examiner can be handed nothing but the sequence of manifests and
  tokens; verification never requires explaining git internals.

## 2. Concepts

- **Stamp commit**: a commit whose tree carries `.tydence/manifest`
  and `.tydence/tokens/`. Whether a commit is stamped is decidable
  from a checkout alone (self-evidencing). Note that the *presence*
  of tokens is a claim, not a proof — verification (§7) establishes
  validity.
- **Manifest**: the canonical text enumerating the full stamped
  snapshot with double hashes (§4). The message imprint sent to the
  TSA is a hash of the manifest bytes.
- **Token**: an RFC 3161 `TimeStampToken` (CMS `SignedData`, raw DER)
  received from a TSA for the manifest imprint.
- **LTV data** (long-term validation): TSA certificate chains and CRL
  snapshots preserved in the repository so that tokens remain
  verifiable after the TSA disappears or its certificates expire.
- **Renewal chain**: each manifest embeds strong hashes of earlier
  stamps' manifests and tokens — at minimum the immediately preceding
  stamp, optionally older ones (§4.1) — so a new stamp re-covers all
  earlier evidence (RFC 3161 §4 recommendation; hash-tree renewal in
  the sense of RFC 4998).
- **Site**: a named (TSA, imprint algorithm) pair. A stamp requests
  one token per selected site; the means of selection is outside
  this specification. The site name identifies the token file (§3)
  and appears in `past-token` lines (§4.1).

## 3. Repository layout

```
.tydence/
  manifest            # present only in stamp commits
  tokens/
    <site>.tsr        # one per site used in the stamp; raw DER,
                      # verifiable with standard tools (openssl ts).
                      # Present only in stamp commits.
  ltv/
    certs/<issuer_hash>.cer   # TSA certificate chains (PEM); permanent
    crls/<issuer_hash>.crl    # CRL snapshots (PEM); permanent
```

- `manifest` and `tokens/` belong to stamp commits only. Their
  presence is what identifies a commit as claiming to be stamped;
  verification (§7) decides whether the claim holds. A commit
  carrying artifacts that do not match its own tree — for example,
  stale ones inherited from an earlier stamp commit — fails check 2
  as a manifest/tree mismatch.
- `ltv/` is permanent and accumulating. The working tree holds only
  the latest data per issuer, so its size is bounded by the number of
  TSAs and CAs. Historical CRL snapshots accumulate in git history
  and are never pruned: past revocation information is itself
  evidence.

## 4. Manifest format (v1)

The manifest is line-oriented plain text: UTF-8, LF line endings,
terminated by a final newline. It must be printable on paper and
verifiable by eye; whitespace is therefore unambiguous by
construction — no leading or trailing whitespace on any line, tokens
separated by exactly one space.

Each line after the header is a record: a record name, the record's
named fields in flag form (`--name value`), a `--` separator, and
the record's payload. The grammar borrows Unix command-line
conventions for familiarity, but none of their flexibility: for
every record type this specification fixes which fields appear and
in what order, every field is mandatory, and unknown record or field
names are rejected (fail closed). Any snapshot and binding set
therefore has exactly one canonical manifest.

```
tydence-manifest/v1
parents -- <commit-hash> [<commit-hash> ...]
predecessor --commit <commit-hash> -- <origin>
past-manifest --commit <commit-hash> -- sha256:<hex> sha3-256:<hex>
past-token --commit <commit-hash> --spec rfc3161 --site <site> -- sha256:<hex> sha3-256:<hex>
entry --path <path> --mode <mode> --size <size> -- sha256:<hex> sha3-256:<hex>
...
```

### 4.1 Lines

- **Header** (first line): the literal format identifier
  `tydence-manifest/v1`. Verifiers must reject unknown versions
  (fail closed). Any change to the canonical form bumps the version.
- **`parents`** — *position annotation*. The direct parent commit
  hashes of the stamp commit (all parents on a merge), in the order
  git records them. Omitted for a root commit.
- **`predecessor`** — *position annotation*. Declares that the stamp
  named by `--commit` lives in another repository — the predecessor
  of an epoch rollover (§8) — so its binding group cannot resolve in
  this one. The payload is a free-form designation of that
  repository (a name, URL or archive locator), encoded as in §4.3.
  The record is a member of the binding group it announces: it opens
  the group, immediately preceding the group's `past-manifest` line,
  and carries the same `--commit`. One per bound stamp living
  outside this repository, and none for the others. A manifest may
  freely mix cross-repository and local groups — for example, a
  stamp after a rollover binding its local predecessor while also
  re-binding the final stamp of the previous epoch.
- **`past-manifest`** — *evidential binding*. The payload is the
  double hash of a bound earlier stamp's manifest bytes; `--commit`
  is a position annotation locating that stamp. Every stamp except the
  very first binds at least its nearest preceding stamp on every
  line of history — a merge whose sides each carry stamps
  contributes one per side, so no line of evidence is left dangling.
  Additional, older stamps may also be bound, so that the chain
  between them survives the loss of intermediate stamps and can be
  verified and presented without them (§6). Absent on the first
  stamp, unless the chain continues from another repository (epoch
  rollover, §8).
- **`past-token`** — *evidential binding*. One line per token of a
  bound stamp; the payload is the double hash of the raw DER bytes.
  `--commit` carries the same annotation as that stamp's
  `past-manifest` line. `--spec` names the anchor specification the
  token follows (`rfc3161` today; future anchor implementations
  introduce new labels without a format change). `--site` names the
  token file the line covers (§3).
- **`entry`** — one line per tracked file in the stamped snapshot.

Position annotations use git's hex hashes and inherit git's object
format; evidential bindings never do.

Each bound stamp forms one group: its `predecessor` record if the
stamp lives outside this repository, the `past-manifest` line, then
that stamp's `past-token` lines. The canonical group order is
defined declaratively: among all orderings in which every group
precedes the groups whose stamps its own manifest transitively
binds, the canonical one is the ordering whose sequence of
`past-manifest` sha256 payloads is smallest in byte-wise
lexicographic order. The binding relation is acyclic and the
payloads are distinct, so this minimum exists and is unique: a
stamp still precedes the stamps it binds (nearest-first), groups
the relation leaves unrelated — the two sides of a merge, for
example — fall back to payload byte order, and any chosen binding
set has exactly one canonical writing.

Record types appear in exactly the order listed in the grammar,
with `predecessor` placed inside its group; within a binding group
`past-token` lines are sorted by `--spec`, then `--site`; `entry`
lines are sorted by plain byte
order of the whole line, which — with `--path` as the first field,
and the separating space sorting below every byte an encoded path
can contain — coincides with the byte order of the encoded path.
This makes the manifest a pure function of the snapshot and the
chosen binding set.

### 4.2 Entries

- **Coverage**: the full tracked content of the commit tree,
  following git semantics. `.tydence/manifest` itself and
  `.tydence/tokens/` are excluded — tokens are received only after
  the manifest is fixed (acyclicity). `.tydence/ltv/` is **included**:
  CRL snapshots for the chains already on record are refreshed
  before the token request (§5), so the covering stamp proves "this
  revocation data existed at the same genTime". Material first
  learned from a freshly received token cannot enter the already
  fixed manifest; it is deposited in the working tree and sealed by
  the following stamp (§5).
- **`--path`** (first field, so that whole-line byte order and path
  order coincide): the byte string git stores (no normalization),
  encoded as in §4.3.
- **`--mode`**: the git mode (`100644`, `100755`, `120000`). Symbolic
  links are hashed over their target string. Empty directories are
  not tracked, as in git.
- **Submodules** are enumerated recursively, their paths prefixed
  with the submodule path. A gitlink's commit hash is a git hash and
  therefore never an evidential binding.
- **`--size`**: the content size in bytes, decimal.
- **Payload hashes** are computed over the actual file contents —
  never git blob ids — and written as lowercase hex.

### 4.3 Path encoding

All paths undergo one uniform, RFC 3986-style transformation of the
byte string git stores. Escaped bytes are written as `%XX` with
uppercase hex; a multi-byte character is escaped as the sequence of
its UTF-8 bytes.

- the escape character `%` itself is escaped
- bytes that are not part of a valid UTF-8 sequence are escaped
- characters in the Unicode general categories C* (control, format,
  surrogate, private use, unassigned) and Z* (separators) are
  escaped — this covers ASCII controls and space, zero-width and
  joining characters (ZWSP, ZWNJ, ZWJ), bidirectional controls,
  non-ASCII spaces such as U+3000, and line/paragraph separators
- everything else — visibly rendered UTF-8: letters, digits,
  combining marks, punctuation and symbols, non-ASCII included — is
  kept as-is (`+` has no special meaning and stays literal)

The escaping targets exactly the characters that are invisible or
layout-altering in print, so the printed manifest is reconstructible
byte-for-byte by eye, needs no quoting mechanism, keeps whitespace
out of the path field entirely, and round-trips any pathological
byte sequence. Visible but confusable spellings (homoglyphs,
alternative combining orders) are deliberately left untouched: the
path stays the byte string git stores, and certainty comes from the
payload hashes, never from the printout.

The Unicode character tables are pinned per format version (v1:
Unicode 17.0). Later Unicode versions reassign the Cn (unassigned)
category, so following them silently would make the encoding depend
on the implementation; adopting newer tables bumps the format
version instead.

### 4.4 Message imprint

The imprint sent to a TSA is a hash of the manifest bytes, using the
site's imprint algorithm (§2). Compromise of an imprint algorithm is
healed by the renewal chain; compromise of a manifest hash family is
healed by the double hash: the surviving family keeps the binding
intact while a third family is added and re-stamped (hash-tree
renewal, RFC 4998).

Which imprint algorithms are usable is a property of the site, not
of this format. As of 2026, every TSA surveyed for this design —
Japanese accredited services and freeTSA — accepts only SHA-2 family
digests (SHA-256/384/512) and none accepts SHA-3; manifest-side
double hashing provides the cross-family insurance regardless.

## 5. Stamping flow

All materials that a token covers are fixed *before* the commit is
created, so the stamp commit itself carries its tokens — no auxiliary
timestamp commits, no dedicated branches, no interleaved history.

1. Fix the content to stamp (index / working tree)
2. Refresh the CRLs in `.tydence/ltv/` for every TSA certificate
   chain already on record there
3. Generate the manifest into `.tydence/manifest` (covering
   everything, including `ltv/`)
4. Request one token per selected site (nonce and certReq set,
   HTTPS)
5. Fully verify each received token (§7 check 3) — an invalid token
   is never sealed in. For a chain not yet on record, the CRLs this
   check needs are fetched now, guided by the certificates the
   token carries
6. Write tokens into `.tydence/tokens/`; deposit the chains and
   CRLs first fetched in step 5 into the working tree's `ltv/`
7. Create the commit with all of the above in its tree

Step 6's deposit lands in the working tree only: the manifest was
fixed in step 3, so this stamp cannot cover the deposit, and the
following stamp seals it. The deferral costs no verifiability —
check 3 accepts a CRL snapshot sealed later (§7) — and it only
concerns a site's first token: from the second use on, step 2 seals
a fresh CRL for the site's chain before the token exists, keeping
each stamp's evidence self-contained. A repository whose newest
stamp first used a site can seal that deposit promptly with one
zero-content-change stamp (§6).

The stamp commit may replace an existing branch tip (certifying the
current state of accumulated work) or be a new commit with zero
content change (§6); either way the resulting commit satisfies this
section.

## 6. Renewal chain and retroactive introduction

A **zero-content-change stamp commit** serves both purposes:

- **Renewal**: because the manifest covers the entire current
  snapshot plus the bound manifests and token hashes, one stamp
  simultaneously re-stamps all content, renews the old tokens, and
  seals in fresh CRL snapshots for them. When to renew is an
  operational choice, bounded by the verifiable lifetime of the
  existing tokens (their TSA certificates).
- **Retroactive introduction**: adopting tydence in an existing
  repository is one zero-change stamp commit on the current HEAD.
  History before that point has transport-layer integrity only — a
  proof of existence cannot be created for the past.

Only stamp points are guaranteed. Editing the history of unstamped
spans (rebase and the like) is outside the model: it affects position
annotations at most, and those take no part in the verification
verdict (§7). A stamped commit's evidence survives history editing
as long as its tree is preserved — the binding does not depend on
git.

Stamps need not all use the same sites: the bindings are hash-based
and TSA-independent, so a later compromise of one stamp's TSA merely
widens that stamp's time uncertainty to the neighboring unaffected
stamps (graceful degradation).

Additional bindings (§4.1) let a stamp bind an earlier stamp
directly, on top of the mandatory immediate predecessor — for
example, stamps using stronger TSAs binding the previous such stamp.
Those stamps then form a chain of their own: it can be verified and
presented to an examiner without any of the intermediate stamps, and
it survives the loss of their artifacts.

## 7. Verification

Verification examines every stamp commit in history:

1. Manifest syntax and format version
2. **Bidirectional** agreement between manifest and tree contents:
   every entry's hashes recompute identically, and no file outside
   the exclusions exists without an entry
3. Full token verification: messageImprint equals the manifest hash;
   CMS signature; certificate chain to a trust anchor; ExtendedKeyUsage
   `id-kp-timeStamping` (critical); ESSCertID / ESSCertIDv2
   consistency (RFC 5816 — both must be supported); validity against
   a historical CRL snapshot sealed in the repository — by the stamp
   itself for a chain already on record, by a following stamp for a
   chain's first token (§5) — including revocation reason codes (a
   token may remain acceptable after certificate expiry only if
   revocation status and reason permit)
4. Renewal chain linkage: for each binding group, recomputing the
   double hash of the bound stamp's own `.tydence/manifest` bytes,
   and of each named token file's bytes, reproduces the group's
   `past-manifest` / `past-token` payloads. The `--commit`
   annotation merely locates the candidate bytes; the hash match is
   what identifies them as the bound artifacts, so the bytes may
   equally be supplied from outside the repository (for example,
   from an epoch predecessor, §8)

A stamp commit with multiple tokens is valid if at least one of its
tokens is valid.

**The verdict is binary and fail-closed**: a stamp commit passes or
fails, and anything undecidable fails. The verifier's correctness is
the lifeline of the whole design.

Position annotations take no part in the verdict. Whether they agree
with the surrounding git topology is a transport-layer consistency
question, outside this specification.

## 8. Epoch rollover

If LTV accumulation ever grows to operational nuisance, the escape
hatch is starting a fresh repository whose first manifest carries
`past-manifest` / `past-token` bindings to the final stamp of the old
repository. The chain is hash-based and independent of repository
identity, so the evidence chain continues across repositories.

The genesis manifest declares the crossing explicitly with a
`predecessor` record (§4.1): the binding group's `--commit` names a
commit of the predecessor repository and will not resolve locally,
and the record says so and points at where the predecessor lives.
The dangling annotation is harmless — position annotations are
locators, not evidence, and verification (§7 check 4) accepts the
bound artifacts from outside the repository. Two consequences do
follow, though. The successor
carries only the hashes of the predecessor's final artifacts, never
the bytes, so the predecessor repository — or at least its stamp
artifacts — must be retained for the chain across the rollover to
remain verifiable. And each stamp's proof of its own snapshot stays
self-contained in the successor; only walking the chain into the
predecessor's past needs the retained artifacts.

## 9. Standards

- RFC 2634 / RFC 5035 — Enhanced Security Services (ESSCertID/v2)
- RFC 3161 — Time-Stamp Protocol (TSP)
- RFC 4998 — Evidence Record Syntax (conceptual basis for the two
  kinds of renewal; the ERS record format itself is not produced)
- RFC 5280 — X.509 certificates and CRLs
- RFC 5652 — Cryptographic Message Syntax (CMS)
- RFC 5816 — ESSCertIDv2 update for RFC 3161

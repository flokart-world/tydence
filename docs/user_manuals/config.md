# tydence configuration manual

This document is the user manual for the tydence configuration file:
where it lives, what it controls, and the exact syntax it accepts.
The stamping model and data formats it drives are specified in
[stamping.md](../stamping.md).

## 1. Role and placement

The stamping specification defines what a stamp is but deliberately
leaves the choice of sites outside its scope (stamping.md §2). The
configuration file is that mechanism: it defines the sites a
repository stamps with and groups them into named profiles for
stamping to choose from.

The file lives at `.tydence/config`, committed to the repository. It
is ordinary tracked content, so every stamp covers it and the
stamping policy itself is preserved as evidence. Consequently the
file may hold only what is true for every clone of the repository;
anything machine-local stays out (§6).

Verification never reads the configuration: a verifier judges tokens
against trust material supplied from outside the repository, so the
verdict on sealed stamps is independent of it.

## 2. Lexical rules

The format borrows its shape from OpenSSH's `ssh_config`: one
directive per line, a directive being a name followed by
whitespace-separated arguments, and block-opening directives making
the member directives that follow theirs.

- The file is UTF-8 text. Lines end with LF; a trailing CR is
  tolerated so checkouts that rewrite line endings still parse.
- Blank lines are ignored. A line whose first non-whitespace
  character is `#` is a comment. `#` does not open a comment
  mid-line: an argument starting with `#` is an error, while a `#`
  inside an argument (a URL fragment, say) is just a character.
- Leading whitespace is insignificant. Indenting member directives
  is convention, not syntax.
- Arguments are separated by runs of spaces or tabs. There is no
  quoting mechanism and no line continuation; no value can contain
  whitespace.
- Directive names are CamelCase, following `ssh_config`'s
  documented spellings (`HostName`, `IdentityFile`), with acronyms
  fully uppercase as OpenSSH writes them (`TCPKeepAlive`) — hence
  `URL`. Unlike `ssh_config`, whose parser accepts keywords in any
  case, the spelling is exact: flexibility in how the same thing
  can be written buys nothing and widens what a reader must
  recognize.

Parsing fails closed. Unknown directives, unknown modifiers,
misplaced or duplicated directives, malformed values, and dangling
references are all errors; a configuration that parses is fully
understood.

The format carries no version marker. The configuration is read only
by the contemporary tool — verification never reads it — so no old
file ever meets a new parser across decades the way manifests do.
Should a breaking revision ever be needed, it will introduce a
mandatory `Version` directive: today's parser rejects that as an
unknown directive, and the revised parser can read its absence as
this format.

## 3. Structure

Directives group into blocks:

```
Site <name>
    URL <https URL>
    Imprint <sha256|sha384|sha512>

Profile <name>
    UseSite <name> [ContinueOnError]
```

Blocks may appear in any order and interleave freely: a `UseSite`
line may name a site defined anywhere in the file, after it as well
as before. References are by name and duplicate names are errors
(§2), so ordering carries no meaning; whether definitions or uses
come first is the author's taste, and the format does not take
sides. The selection keyword is distinct from `Site` because
indentation is only convention (§2): the keyword alone, not the
layout around it, must tell a definition from a selection.

A configuration may be empty, or hold sites without profiles, while
a repository's policy is still being set up — stamping, not parsing,
requires a usable profile.

### 3.1 Site

`Site <name>` opens the definition of one site — a named (TSA,
imprint algorithm) pair (stamping.md §2). The name is the site's
identity everywhere it appears: the token file `tokens/<name>.tsr`
(stamping.md §3), the `--site` field of `past-token` lines
(stamping.md §4.1), and the selections in profiles. Naming
constraints are in §4.

Each site block carries exactly these member directives, each
exactly once:

- `URL` — the TSA's RFC 3161 endpoint. HTTPS only: the stamping
  flow requests tokens over HTTPS (stamping.md §5), and rejecting
  other schemes at parse time keeps a misconfigured endpoint from
  surfacing only when a stamp is attempted.
- `Imprint` — the digest family for the message imprint sent to
  this TSA: `sha256`, `sha384` or `sha512`. Only the SHA-2 family
  appears because no surveyed TSA accepts SHA-3 imprints;
  cross-family insurance lives in the manifest's double hashes, not
  in the imprint (stamping.md §4.4).

### 3.2 Profile

`Profile <name>` opens a named selection of sites. A stamp uses
exactly one profile — named explicitly at stamping time; there is no
implicit default — and requests one token per selected site. Profile
names follow the same constraints as site names (§4).

A profile holds one or more `UseSite <name>` lines, each naming a
defined site (§3), each site at most once. A line may carry the
single modifier `ContinueOnError`; its effect is defined in §5.

Profiles let the cost and strength of stamping vary by occasion —
a free-TSA-only profile for frequent stamps, a stronger one for
renewal-chain stamps — without touching the site definitions.

## 4. Site and profile names

A name is 1 to 64 characters of ASCII letters, digits, `-` and `_`,
beginning and ending with a letter or digit. Names are
case-sensitive: `FreeTSA` and `freetsa` are distinct.

The constraint exists because a site name becomes the token filename
`tokens/<name>.tsr` inside the repository and a bare field in
manifest lines; the allowed set keeps both trivially safe.

The length bound, unlike the character set, is not derived: the
nearest hard limit — 255 bytes for a `<name>.tsr` filename on common
filesystems — lies far above any name that still reads as a name.
64 is a conventional cap chosen well inside that margin; moving it
adjusts a convention, not a constraint.

Two hazards are deliberately left to the author, matching git's own
stance on tracked filenames: names differing only by case collide as
token files on case-insensitive filesystems, and Windows reserves
certain device names (`con`, `nul`, `prn`, ...). Choose names that
avoid both wherever those platforms matter.

## 5. Failure behavior when stamping

A stamp requests one token per site selected by the profile and
fully verifies each received token before sealing (stamping.md §5).
For each site, acquisition or pre-seal verification can fail.

- Without a modifier, a site's failure aborts the stamp: nothing is
  written, no commit is created.
- With `ContinueOnError`, the site's failure is reported as a
  warning and the stamp proceeds with the remaining tokens.

Regardless of modifiers, a stamp that would seal zero valid tokens
is aborted: a stamp commit's claim is carried by its tokens, and an
empty claim is not a weaker stamp but no stamp at all.

## 6. What the configuration never contains

- **Trust anchors.** What a verifier trusts axiomatically is the
  verifier's decision, supplied from outside the repository; a
  repository that named its own trust anchors would be certifying
  itself. The `ltv/` tree holds companion certificates and CRL
  snapshots — material a verifier examines, never axioms.
- **Credentials.** TSA authentication material is machine-local by
  nature and must never be committed. How credentials are supplied
  will be defined together with the first authenticated TSA
  integration.

## 7. Example

```
# Free development TSA; best-effort by nature.
Site freetsa-sha512
    URL https://freetsa.org/tsr
    Imprint sha512

# Accredited TSA under contract.
Site accredited-sha384
    URL https://tsa.example.jp/tsr
    Imprint sha384

# Frequent, zero-cost stamping.
Profile light
    UseSite freetsa-sha512

# Annual renewal-chain stamps: the accredited token is the point,
# the free one is a bonus.
Profile annual
    UseSite accredited-sha384
    UseSite freetsa-sha512 ContinueOnError
```

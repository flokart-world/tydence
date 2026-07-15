# tydence command manual

This document is the user manual for the `tydence` command line: how
invocation works, what each command does, and how the commands fit
into daily operation. The evidential model and data formats it
drives are specified in [stamping.md](../stamping.md); the
`.tydence/config` file has a [manual of its own](config.md). Each
command also documents itself — `tydence help <command>` carries the
same material in condensed form, so the terminal alone suffices in
the field.

## 1. Invocation

```
tydence [-C <path>] <command> [options]
```

`-C <path>` (long form `--directory`) runs the command as if started
in that directory, as in git. The repository is discovered from
there upward, so any directory inside a worktree works.

Exit status follows one convention across all commands:

- **0** — success; for `verify`, every judged stamp passed.
- **1** — a check or verdict failed: a failing stamp, nothing
  proven, or stamp artifacts found in the index.
- **2** — an operational error: the command could not do its job at
  all (no repository, unreadable anchors, a TSA unreachable without
  `ContinueOnError`, usage errors).

Operational errors are reported to stderr as a cause chain:

```
tydence: <error>
  caused by: <underlying cause>
```

## 2. Trust anchors

Stamping and verification both judge tokens against **trust anchor
certificates**: the roots of the TSA certificate chains you have
decided to trust. Anchors are obtained out of band — a TSA publishes
its root; an accredited CA publishes its certificates — and are
machine-local by design: a repository that named its own trust
anchors would be certifying itself, so anchors never come from
repository content (config.md §6).

Anchors are named through git's own configuration namespace:

```console
$ git config --add tydence.anchor <PEM_FILE>
```

`tydence.anchor` is multi-valued and follows the usual configuration
precedence: values set with `--local` are this repository's trust,
values in the global or system configuration apply to every
repository that has no better knowledge — all values accumulate. A
leading `~/` in a value expands to the home directory.

On top of the configured values, `--anchor <PEM_FILE>` adds more for
one invocation of `stamp` or `verify`; the option may repeat. A PEM
file may hold several concatenated certificates. A command that ends
up with no anchors at all fails rather than judging against nothing.

## 3. tydence stamp

```
tydence stamp --profile <NAME> [--anchor <PEM_FILE>]...
              [--amend] [--message <TEXT>]
```

Seals one stamp commit over the branch HEAD points at, following the
stamping flow of stamping.md §5: refreshes the CRL snapshots under
`.tydence/ltv/`, fixes the manifest over the tree being stamped —
binding the nearest earlier stamp on every line of history —
requests one token per site of the profile over HTTPS, fully
verifies each token, and only then writes the stamp commit and moves
the branch to it.

- `--profile <NAME>` names the configuration profile whose sites to
  stamp with (config.md §3.2). There is no implicit default. A
  site's failure aborts the stamp unless its selection carries
  `ContinueOnError`, in which case the failure is reported as a
  warning and the stamp proceeds; a stamp that would seal zero
  valid tokens is aborted regardless.
- `--amend` replaces the branch tip instead of adding a new commit:
  the stamp takes over the tip's parents and, unless `--message`
  says otherwise, the tip's message, as with `git commit --amend`.
  This rewrites history and is only safe while the tip has not been
  shared. Without it, the stamp becomes a new commit with HEAD as
  its parent, certifying the same content — the zero-content-change
  form that also serves as renewal (§7).
- `--message <TEXT>` sets the commit message; without it an
  amending stamp keeps the tip's message and a plain stamp uses
  `Stamp with profile <NAME>`. Either way the message receives
  `Tydence-Stamp` trailers carrying the manifest's double hash —
  joined into a trailer block the message already ends with, and
  replacing any `Tydence-Stamp` lines of a stamp this one amends —
  a convenience for reading `git log`; no verification reads them.

The commit is written directly, and the index and working tree are
then brought to match it: a fresh stamp reads clean, artifacts in
place. Resuming ordinary work is the explicit `tydence drop` (§6),
and a forgotten drop is caught by the pre-commit guard (§5). When a
site's certificate chain is seen for the first time, the trust
material learned from its fresh token cannot enter the already
fixed manifest; it is deposited under `.tydence/ltv/` in the
working tree and queued in the index, and the command names the
deposits and asks for them to be sealed. Seal them promptly with a
follow-up stamp or an ordinary commit (§7).

## 4. tydence verify

```
tydence verify [--anchor <PEM_FILE>]... [--commit <REVISION>]
```

Judges the stamps that carry a commit. From the starting commit —
HEAD, or `--commit <REVISION>` in the usual git revision syntax —
every line of history is followed back to its nearest
stamp claim, and each claim receives the full fail-closed verdict of
stamping.md §7: manifest syntax, bidirectional manifest/tree
agreement, full token verification including revocation against the
sealed CRL snapshots, and renewal-chain linkage to the bound earlier
artifacts. Verifying the nearest claims is verifying the whole line
of evidence in front: earlier stamps are covered through the renewal
chain.

One line per judged stamp reports the verdict:

```
PASS <commit> (<site> at <genTime>, ...)
  manifest sha256:<hex> sha3-256:<hex>
FAIL <commit>: <cause>
```

Under each passing stamp's line, the sealed manifest's double hash
is printed exactly as the manifest grammar spells it. This is the
value to transcribe into an anchor outside the repository — a dated
notarial declaration, say — and it appears only on a passed
verdict, so a printed digest is always a verified one. A stamp with
several tokens stands as long as one token stands; every rejected
token is still reported as a note under its stamp's line.

When the starting commit is not itself a stamp, the command says
so: content since the judged stamps rests on git integrity alone.
Unsealed working-tree deposits (§3) are used as CRL sources where
they apply, then reported so they can be sealed.

The command exits 0 only when at least one stamp was judged and
every judged stamp passed; a passing repository with nothing proven
does not exist.

## 5. tydence precommit

```
tydence precommit
```

Refuses a commit that would carry stamp artifacts. After every
stamp, `.tydence/manifest` and `.tydence/tokens/` sit in the index
in agreement with HEAD (§3), and a reset or checkout can resurrect
them too; either way the ordinary commit about to be made would
merely inherit a stamp's artifacts, and its claim would fail
verification forever after. The command exits 1 in that situation
and names the paths — `tydence drop` is the way out. The LTV
deposits and records also staged by `stamp` are exactly what it
lets through.

Intended to be called from the repository's pre-commit hook:

```sh
#!/bin/sh
tydence precommit || exit 1
```

installed as `.git/hooks/pre-commit` (executable), or added to the
hooks a `core.hooksPath` directory already runs.

## 6. tydence drop

```
tydence drop
```

Declares the next commit ordinary: removes `.tydence/manifest` and
`.tydence/tokens/` from the index and the working tree — the state
every stamp leaves behind (§3), and the state `precommit` refuses.
Everything else stays: the configuration and the `.tydence/ltv/`
records are tracked content, not stamp artifacts. Sealed stamps are
untouched; their artifacts live in their commits.

## 7. Operation

**Adopting tydence in an existing repository.** Commit a
`.tydence/config` (config.md), configure anchors (§2), and stamp:
the first stamp is one zero-content-change commit on the current
HEAD. History before that point keeps transport-layer integrity
only — a proof of existence cannot be created for the past
(stamping.md §6).

**Renewal.** A plain `tydence stamp` on an unchanged tree re-stamps
all content, renews every earlier token through the chain, and
seals fresh CRL snapshots. When to renew is an operational choice,
bounded by the verifiable lifetime of the existing tokens' TSA
certificates. Profiles let the strength vary by occasion — a free
TSA for frequent stamps, an accredited one for the annual renewal
(config.md §7).

**Sealing first-use deposits.** After a stamp that first used a
site, `stamp` and `verify` keep reporting the queued `ltv/` deposits
until a commit seals them. The cheapest seal is one follow-up
zero-content-change stamp; an ordinary commit works too. From the
site's second use on, each stamp's evidence is self-contained.

**Sharing amended stamps.** `--amend` moves the branch tip;
publishing the result follows git's usual force-push rules. The
evidence itself does not depend on git topology, but collaborators'
clones do.

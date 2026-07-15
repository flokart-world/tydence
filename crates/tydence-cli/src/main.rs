//! The tydence command line: a thin shell over the tydence library.
//! The commands are documented by their own help text (`tydence help
//! <command>`), which stands in for a specification by design — the
//! evidential model and data formats live in the library's
//! documentation, not here.

use clap::{Args, Parser, Subcommand};
use std::path::PathBuf;
use std::process::ExitCode;

use tydence::gix;

type FailureCause = Box<dyn std::error::Error>;

const ABOUT: &str = "RFC 3161 trusted timestamps for git-managed data";

// The long help texts are the CLI's documentation of record — help
// text stands in for a specification by design — and live as plain
// text files beside the code, where prose is edited as prose.
const LONG_ABOUT: &str = include_str!("help/long_about.txt");
const STAMP_HELP: &str = include_str!("help/stamp.txt");
const VERIFY_HELP: &str = include_str!("help/verify.txt");
const PRECOMMIT_HELP: &str = include_str!("help/precommit.txt");
const DROP_HELP: &str = include_str!("help/drop.txt");

#[derive(Args)]
struct AnchorArgs {
    /// Trust anchor PEM file, on top of the tydence.anchor
    /// configuration values
    #[arg(long = "anchor", value_name = "PEM_FILE")]
    anchor_files: Vec<PathBuf>,
}

#[derive(Args)]
struct StampArgs {
    /// Configuration profile naming the sites to stamp with
    #[arg(long, value_name = "NAME")]
    profile: String,
    #[command(flatten)]
    anchors: AnchorArgs,
    /// Replace the branch tip instead of adding a new commit
    #[arg(long)]
    amend: bool,
    /// Commit message (defaults to the tip's message with --amend,
    /// to "Stamp with profile <NAME>" otherwise)
    #[arg(long, value_name = "TEXT")]
    message: Option<String>,
}

#[derive(Args)]
struct VerifyArgs {
    #[command(flatten)]
    anchors: AnchorArgs,
    /// Commit to judge from (HEAD if omitted)
    #[arg(long, value_name = "REVISION")]
    commit: Option<String>,
}

#[derive(Subcommand)]
enum Command {
    /// Seal a stamp commit over the current branch
    #[command(after_long_help = STAMP_HELP)]
    Stamp(StampArgs),
    /// Judge the stamps that carry a commit
    #[command(after_long_help = VERIFY_HELP)]
    Verify(VerifyArgs),
    /// Refuse a commit that would carry staged stamp artifacts
    #[command(after_long_help = PRECOMMIT_HELP)]
    Precommit,
    /// Declare the next commit ordinary: drop staged stamp artifacts
    #[command(after_long_help = DROP_HELP)]
    Drop,
}

#[derive(Parser)]
#[command(name = "tydence", version, about = ABOUT, long_about = LONG_ABOUT)]
struct Cli {
    /// Run as if started in this directory, as in git -C
    #[arg(
        short = 'C',
        long = "directory",
        value_name = "PATH",
        default_value = ".",
        global = true
    )]
    directory: PathBuf,
    #[command(subcommand)]
    command: Command,
}

fn report(error: &dyn std::error::Error) {
    eprintln!("tydence: {error}");
    let mut maybe_cause = error.source();
    while let Some(cause) = maybe_cause {
        eprintln!("  caused by: {cause}");
        maybe_cause = cause.source();
    }
}

// Only the leading ~/ form is expanded: it is what people actually
// write in configuration values, and any other tilde form is left to
// mean the literal path it spells.
fn expand_home(path_text: &str) -> PathBuf {
    match (path_text.strip_prefix("~/"), std::env::var_os("HOME")) {
        (Some(below_home), Some(home)) => PathBuf::from(home).join(below_home),
        _ => PathBuf::from(path_text),
    }
}

/// The anchor PEM paths the `tydence.anchor` configuration key names,
/// across every configuration scope (git-config(1) sanctions
/// third-party variables; multi-valued keys accumulate).
fn configured_anchor_paths(repository: &gix::Repository) -> Vec<PathBuf> {
    repository
        .config_snapshot()
        .plumbing()
        .strings("tydence.anchor")
        .unwrap_or_default()
        .iter()
        .map(|value| expand_home(&value.to_string()))
        .collect()
}

fn load_anchors(
    repository: &gix::Repository,
    args: &AnchorArgs,
) -> Result<Vec<Vec<u8>>, FailureCause> {
    let mut anchors = Vec::new();
    for path in configured_anchor_paths(repository) {
        anchors.extend(tydence::load_anchor_file(&path)?);
    }
    for path in &args.anchor_files {
        anchors.extend(tydence::load_anchor_file(path)?);
    }
    if anchors.is_empty() {
        return Err("no trust anchors supplied: name PEM files with \
                    `git config --add tydence.anchor <path>` or pass \
                    --anchor"
            .into());
    }
    Ok(anchors)
}

fn signature_of(
    maybe_identity: Option<
        Result<gix::actor::SignatureRef<'_>, gix::config::time::Error>,
    >,
    role: &str,
) -> Result<gix::actor::Signature, FailureCause> {
    let identity = maybe_identity
        .ok_or_else(|| {
            format!("no {role} identity; configure user.name and user.email")
        })??
        .to_owned()?;
    Ok(identity)
}

/// Decodes the tip's message for inheritance by an amending stamp.
/// Stamp messages are otherwise new text; only here does existing
/// commit content flow in, so only here can non-UTF-8 bytes appear.
fn decode_tip_message(raw_message: &[u8]) -> Result<String, FailureCause> {
    match std::str::from_utf8(raw_message) {
        Ok(text) => Ok(text.to_string()),
        Err(_) => {
            Err("the tip's message is not UTF-8 text; pass --message".into())
        }
    }
}

/// The parents of the stamp being made: a plain stamp becomes HEAD's
/// child, an amending stamp replaces HEAD by taking over its parents.
fn stamp_parent_ids(
    amend: bool,
    head_id: gix::ObjectId,
    head_parent_ids: Vec<gix::ObjectId>,
) -> Vec<gix::ObjectId> {
    match amend {
        true => head_parent_ids,
        false => vec![head_id],
    }
}

fn format_moment(moment: std::time::SystemTime) -> String {
    // RFC 3161 genTime is a GeneralizedTime and can, in theory,
    // predate the epoch; the moment is display-only either way.
    match moment.duration_since(std::time::UNIX_EPOCH) {
        Ok(elapsed) => gix::date::Time::new(elapsed.as_secs() as i64, 0)
            .format(gix::date::time::format::ISO8601_STRICT)
            .unwrap_or_else(|_| format!("{moment:?}")),
        Err(_) => "before 1970-01-01T00:00:00+00:00".to_string(),
    }
}

/// Converges the checkout to the freshly sealed stamp: the index and
/// working tree come to agree with HEAD, and the worktree LTV
/// deposits HEAD does not cover are queued. Returns what was queued.
fn converge_checkout(
    repository: &gix::Repository,
) -> Result<Vec<String>, FailureCause> {
    tydence::sync_artifacts(repository)?;
    Ok(tydence::stage_deposits(repository)?)
}

fn stamp(
    repository: &gix::Repository,
    args: &StampArgs,
) -> Result<ExitCode, FailureCause> {
    let anchor_certificates = load_anchors(repository, &args.anchors)?;
    let head_reference = repository.head_ref()?.ok_or(
        "HEAD is detached; stamping moves a branch, check one out first",
    )?;
    let reference_name = head_reference.name().as_bstr().to_string();
    let head_id = repository.head_id()?.detach();
    let head_commit = repository.find_commit(head_id)?;
    let base_tree_id = head_commit.tree_id()?.detach();
    // A plain stamp certifies HEAD's content as a new commit; --amend
    // replaces the tip instead, taking over its parents.
    let head_parent_ids: Vec<gix::ObjectId> = head_commit
        .parent_ids()
        .map(|parent| parent.detach())
        .collect();
    let parent_ids = stamp_parent_ids(args.amend, head_id, head_parent_ids);
    let author = signature_of(repository.author(), "author")?;
    let committer = signature_of(repository.committer(), "committer")?;
    let message = match (&args.message, args.amend) {
        (Some(text), _) => text.clone(),
        // An amending stamp inherits the message of the tip it
        // replaces, as git commit --amend does.
        (None, true) => {
            decode_tip_message(head_commit.message_raw()?.as_ref())?
        }
        (None, false) => format!("Stamp with profile {}", args.profile),
    };
    let created = tydence::create_stamp(
        repository,
        &tydence::CreateInputs {
            base_tree_id,
            profile_name: &args.profile,
            anchor_certificates: &anchor_certificates,
            parent_ids: &parent_ids,
            message: &message,
            author: &author,
            committer: &committer,
            reference_name: &reference_name,
            expected: gix::refs::transaction::PreviousValue::MustExistAndMatch(
                gix::refs::Target::Object(head_id),
            ),
        },
        |_site_name, site| tydence::live_anchor(site),
    )?;
    for warning in &created.warnings {
        eprintln!(
            "tydence: warning: site {} skipped: {}",
            warning.site_name, warning.cause
        );
    }
    println!("sealed {} on {}", created.commit_id, reference_name);
    // The seal is already history at this point, so a failure below
    // must not read as a failed stamp: say the seal stands and how
    // to converge — the sync derives everything from HEAD, so
    // repeating it is safe.
    let queued = match converge_checkout(repository) {
        Ok(queued) => queued,
        Err(cause) => {
            report(cause.as_ref());
            eprintln!(
                "tydence: the stamp is sealed; only the checkout did not \
                 converge to it — fix the cause, then run `git restore \
                 --source=HEAD --staged --worktree -- .tydence`"
            );
            // The operational 2, not the verdict 1: nothing was
            // judged and no evidence failed — the bookkeeping did.
            return Ok(ExitCode::from(2));
        }
    };
    if !queued.is_empty() {
        println!("queued LTV deposits the manifest could not yet cover:");
        for path in &queued {
            println!("  {path}");
        }
        println!(
            "seal them promptly with a follow-up stamp or an ordinary commit"
        );
    }
    Ok(ExitCode::SUCCESS)
}

fn verify(
    repository: &gix::Repository,
    args: &VerifyArgs,
) -> Result<ExitCode, FailureCause> {
    let anchor_certificates = load_anchors(repository, &args.anchors)?;
    let start_id = match &args.commit {
        Some(revision) => {
            repository
                .rev_parse_single(revision.as_str())?
                .object()?
                .peel_to_kind(gix::object::Kind::Commit)?
                .id
        }
        None => repository.head_id()?.detach(),
    };
    let audit = tydence::audit_repository(
        repository,
        &tydence::AuditInputs {
            start_id,
            anchor_certificates: &anchor_certificates,
            worktree: repository.workdir(),
        },
    )?;
    if audit.verdicts.is_empty() {
        println!("no stamp claim behind {start_id}: nothing is proven");
        return Ok(ExitCode::from(1));
    }
    if !audit.start_is_claiming {
        println!(
            "{start_id} is not itself a stamp; judging the nearest stamps \
             behind it (content since then rests on git integrity alone)"
        );
    }
    let mut all_pass = true;
    for verdict in &audit.verdicts {
        match &verdict.outcome {
            Ok(summary) => {
                let accepted: Vec<String> = summary
                    .accepted
                    .iter()
                    .map(|token| {
                        format!(
                            "{} at {}",
                            token.site,
                            format_moment(token.summary.gen_time)
                        )
                    })
                    .collect();
                println!(
                    "PASS {} ({})",
                    verdict.commit_id,
                    accepted.join(", ")
                );
                println!("  manifest {}", summary.manifest_hashes);
                for rejection in &summary.rejected {
                    println!(
                        "  note: token {} rejected: {}",
                        rejection.site, rejection.cause
                    );
                }
            }
            Err(failure) => {
                all_pass = false;
                println!("FAIL {}: {failure}", verdict.commit_id);
            }
        }
    }
    for path in &audit.unsealed_deposits {
        println!("note: unsealed LTV deposit: {path}");
    }
    if !audit.unsealed_deposits.is_empty() {
        println!(
            "note: seal the deposits with a follow-up stamp or an ordinary \
             commit"
        );
    }
    match all_pass {
        true => Ok(ExitCode::SUCCESS),
        false => Ok(ExitCode::from(1)),
    }
}

fn precommit(repository: &gix::Repository) -> Result<ExitCode, FailureCause> {
    let staged = tydence::staged_artifacts(repository)?;
    if staged.is_empty() {
        return Ok(ExitCode::SUCCESS);
    }
    eprintln!("tydence: the index holds stamp artifacts:");
    for path in &staged {
        eprintln!("  {path}");
    }
    eprintln!(
        "tydence: only `tydence stamp` seals stamp commits; run \
         `tydence drop` to make the next commit an ordinary one"
    );
    Ok(ExitCode::from(1))
}

fn drop_artifacts(
    repository: &gix::Repository,
) -> Result<ExitCode, FailureCause> {
    let dropped = tydence::drop_artifacts(repository)?;
    match dropped.is_empty() {
        true => println!("nothing to drop"),
        false => {
            println!("dropped stamp artifacts:");
            for path in &dropped {
                println!("  {path}");
            }
        }
    }
    Ok(ExitCode::SUCCESS)
}

fn run() -> Result<ExitCode, FailureCause> {
    let cli = Cli::parse();
    let repository = gix::discover(&cli.directory)?;
    match &cli.command {
        Command::Stamp(args) => stamp(&repository, args),
        Command::Verify(args) => verify(&repository, args),
        Command::Precommit => precommit(&repository),
        Command::Drop => drop_artifacts(&repository),
    }
}

fn main() -> ExitCode {
    match run() {
        Ok(code) => code,
        Err(error) => {
            report(error.as_ref());
            ExitCode::from(2)
        }
    }
}

#[cfg(test)]
mod tests {
    use clap::CommandFactory;
    use std::time::{Duration, UNIX_EPOCH};

    use super::*;

    #[test]
    fn the_command_line_definition_is_coherent() {
        Cli::command().debug_assert();
    }

    #[test]
    fn a_plain_stamp_becomes_the_child_of_head() {
        let head = gix::ObjectId::empty_tree(gix::hash::Kind::Sha1);
        let parent = gix::ObjectId::empty_blob(gix::hash::Kind::Sha1);
        let parents = stamp_parent_ids(false, head, vec![parent]);
        assert_eq!(parents, vec![head]);
    }

    #[test]
    fn an_amending_stamp_takes_over_the_tips_parents() {
        let head = gix::ObjectId::empty_tree(gix::hash::Kind::Sha1);
        let parent = gix::ObjectId::empty_blob(gix::hash::Kind::Sha1);
        let parents = stamp_parent_ids(true, head, vec![parent]);
        assert_eq!(parents, vec![parent]);
    }

    #[test]
    fn a_utf8_tip_message_is_inherited_as_spelled() {
        assert_eq!(
            decode_tip_message(b"wip: fix\n").expect("the message decodes"),
            "wip: fix\n"
        );
    }

    #[test]
    fn a_non_utf8_tip_message_asks_for_an_explicit_one() {
        assert!(decode_tip_message(&[0xff, 0xfe]).is_err());
    }

    #[test]
    fn amending_a_root_stamp_stays_a_root() {
        let head = gix::ObjectId::empty_tree(gix::hash::Kind::Sha1);
        let parents = stamp_parent_ids(true, head, vec![]);
        assert!(parents.is_empty());
    }

    #[test]
    fn a_home_relative_anchor_path_expands() {
        let home =
            std::env::var_os("HOME").expect("the test environment has HOME");
        assert_eq!(
            expand_home("~/anchors/root.pem"),
            PathBuf::from(home).join("anchors/root.pem")
        );
    }

    #[test]
    fn other_paths_stay_as_spelled() {
        assert_eq!(
            expand_home("/etc/tydence/root.pem"),
            PathBuf::from("/etc/tydence/root.pem")
        );
        assert_eq!(
            expand_home("~user/root.pem"),
            PathBuf::from("~user/root.pem")
        );
    }

    #[test]
    fn a_moment_formats_as_iso8601_utc() {
        let moment = UNIX_EPOCH + Duration::from_secs(1_800_000_000);
        assert_eq!(format_moment(moment), "2027-01-15T08:00:00+00:00");
    }

    #[test]
    fn a_pre_epoch_moment_prints_the_fixed_marker() {
        let moment = UNIX_EPOCH - Duration::from_secs(1);
        assert_eq!(format_moment(moment), "before 1970-01-01T00:00:00+00:00");
    }
}

//! Token acquisition for one stamp (stamping specification §5 steps
//! 4–5): walks the chosen profile's selections, obtains one token
//! per site through its anchor, and fully verifies each token before
//! it may be sealed. The failure policy is the configuration
//! manual's §5: an unmodified site's failure aborts the stamp, a
//! `ContinueOnError` site's failure is reported and tolerated, and a
//! stamp that would seal zero valid tokens is always aborted.

use std::fmt;

use super::config::{Config, Site, UseSite};
use super::tsp::TimestampAnchor;
use super::verify::{TrustData, VerificationBasis, verify_token};

// Single spelling of the boxed cause type, as in the tsp module.
type FailureCause = Box<dyn std::error::Error + Send + Sync>;

/// One token that passed pre-seal verification, keyed by the site
/// that issued it.
#[derive(Debug)]
pub struct AcquiredToken {
    pub site_name: String,
    pub bytes: Vec<u8>,
}

/// One selected site that failed to yield a sealable token, during
/// acquisition or during pre-seal verification.
#[derive(Debug)]
pub struct SiteFailure {
    pub site_name: String,
    pub cause: FailureCause,
}

impl fmt::Display for SiteFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "site {:?} yielded no sealable token: {}",
            self.site_name, self.cause
        )
    }
}

/// The outcome of a completed acquisition: the tokens to seal, in
/// selection order, and the failures the profile tolerated.
#[derive(Debug)]
pub struct Acquisition {
    pub tokens: Vec<AcquiredToken>,
    /// Failures of `ContinueOnError` selections. They do not stop
    /// the stamp, but they are always reported.
    pub warnings: Vec<SiteFailure>,
}

#[derive(Debug)]
pub enum Error {
    /// The named profile is not defined in the configuration.
    UnknownProfile { profile_name: String },
    /// A selection names a site the configuration does not define.
    /// The parser guarantees resolution for parsed configurations,
    /// but the model is open to programmatic construction, so the
    /// guarantee is re-checked fail-closed at the point of use.
    UnknownSite { site_name: String },
    /// A site is selected more than once. Re-checked here for the
    /// same reason as `UnknownSite`: acquiring twice would spend a
    /// second token only for the seal to collide on one token file.
    DuplicateSelection { site_name: String },
    /// A selection without `ContinueOnError` failed, aborting the
    /// stamp before any further site is contacted.
    SiteFailed(SiteFailure),
    /// Every selection failed. Zero valid tokens never seal: an
    /// empty claim is not a weaker stamp but no stamp at all.
    NoValidTokens { failures: Vec<SiteFailure> },
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownProfile { profile_name } => write!(
                formatter,
                "profile {profile_name:?} is not defined in the \
                 configuration"
            ),
            Self::UnknownSite { site_name } => write!(
                formatter,
                "the selected site {site_name:?} is not defined in the \
                 configuration"
            ),
            Self::DuplicateSelection { site_name } => write!(
                formatter,
                "the site {site_name:?} is selected more than once"
            ),
            Self::SiteFailed(failure) => {
                write!(formatter, "the stamp is aborted: {failure}")
            }
            Self::NoValidTokens { failures } => {
                write!(formatter, "no selected site yielded a valid token")?;
                for failure in failures {
                    write!(formatter, " [{failure}]")?;
                }
                Ok(())
            }
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::SiteFailed(failure) => Some(failure.cause.as_ref()),
            Self::UnknownProfile { .. }
            | Self::UnknownSite { .. }
            | Self::DuplicateSelection { .. }
            | Self::NoValidTokens { .. } => None,
        }
    }
}

/// Everything one token acquisition consumes: the stamping policy,
/// the already fixed manifest bytes the tokens must cover, and the
/// trust material pre-seal verification judges against.
#[derive(Clone, Copy, Debug)]
pub struct AcquireInputs<'a> {
    pub config: &'a Config,
    /// The profile to stamp with, always named explicitly; there is
    /// no implicit default (configuration manual §3.2).
    pub profile_name: &'a str,
    /// The exact bytes of `.tydence/manifest`.
    pub manifest_bytes: &'a [u8],
    pub trust: TrustData<'a>,
}

/// Acquires one fully verified token per site the chosen profile
/// selects. `make_anchor` turns a selected site into the anchor its
/// token is drawn from, so live HTTPS acquisition and test doubles
/// pass through the same entry point. Every selection is resolved
/// before any anchor is built: an unresolvable selection aborts
/// while no token has been spent yet.
///
/// `supplement_trust` runs between a site's acquisition and its
/// pre-seal verification, handing back additional CRL snapshots
/// (DER) for the received token's chain: a chain first learned from
/// the token itself has its CRLs fetched only at this point (§5
/// step 5). Its failure is the site's failure, under the same
/// `ContinueOnError` policy as everything else about the site.
pub fn run<MakeAnchor, Anchor, SupplementTrust>(
    inputs: &AcquireInputs<'_>,
    mut make_anchor: MakeAnchor,
    mut supplement_trust: SupplementTrust,
) -> Result<Acquisition, Error>
where
    MakeAnchor: FnMut(&str, &Site) -> Anchor,
    Anchor: TimestampAnchor,
    Anchor::Error: Send + Sync + 'static,
    SupplementTrust: FnMut(&str, &[u8]) -> Result<Vec<Vec<u8>>, FailureCause>,
{
    let Some(profile) = inputs.config.profiles.get(inputs.profile_name) else {
        return Err(Error::UnknownProfile {
            profile_name: inputs.profile_name.to_string(),
        });
    };
    let mut selections: Vec<(&UseSite, &Site)> =
        Vec::with_capacity(profile.selections.len());
    for selection in &profile.selections {
        let Some(site) = inputs.config.sites.get(&selection.site_name) else {
            return Err(Error::UnknownSite {
                site_name: selection.site_name.clone(),
            });
        };
        let is_repeated = selections
            .iter()
            .any(|(prior, _)| prior.site_name == selection.site_name);
        if is_repeated {
            return Err(Error::DuplicateSelection {
                site_name: selection.site_name.clone(),
            });
        }
        selections.push((selection, site));
    }
    let mut tokens = Vec::new();
    let mut warnings = Vec::new();
    for (selection, site) in selections {
        let site_name = selection.site_name.as_str();
        let mut anchor = make_anchor(site_name, site);
        // An invalid token is never sealed in (§5 step 5): a token
        // becomes sealable only by passing the verifier's full
        // check 3, judged against the base trust material plus
        // whatever the supplement fetched for this very token.
        let sealable_token = (|| -> Result<Vec<u8>, FailureCause> {
            let bytes = anchor.acquire_token(inputs.manifest_bytes).map_err(
                |acquire_error| Box::new(acquire_error) as FailureCause,
            )?;
            let supplemented_crls = supplement_trust(site_name, &bytes)?;
            let mut crls = inputs.trust.crls.to_vec();
            crls.extend(supplemented_crls);
            let basis = VerificationBasis {
                manifest_bytes: inputs.manifest_bytes,
                trust: TrustData {
                    crls: &crls,
                    ..inputs.trust
                },
            };
            verify_token(&bytes, &basis).map_err(|verify_error| {
                Box::new(verify_error) as FailureCause
            })?;
            Ok(bytes)
        })();
        match sealable_token {
            Ok(bytes) => tokens.push(AcquiredToken {
                site_name: selection.site_name.clone(),
                bytes,
            }),
            Err(cause) => {
                let failure = SiteFailure {
                    site_name: selection.site_name.clone(),
                    cause,
                };
                if !selection.continues_on_error {
                    return Err(Error::SiteFailed(failure));
                }
                warnings.push(failure);
            }
        }
    }
    if tokens.is_empty() {
        return Err(Error::NoValidTokens { failures: warnings });
    }
    Ok(Acquisition { tokens, warnings })
}

#[cfg(test)]
use super::{config, test_pki, tsp};

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::collections::HashMap;

    use super::config::{Profile, parse};
    use super::tsp::ImprintAlgorithm;

    use super::*;

    const MANIFEST: &[u8] = b"tydence-manifest/v1\n";

    const TWO_SITES: &str = "Site alpha\n\
                             \tURL https://alpha.example/tsr\n\
                             \tImprint sha256\n\
                             Site beta\n\
                             \tURL https://beta.example/tsr\n\
                             \tImprint sha256\n";

    #[derive(Clone, Copy)]
    enum ScriptedAnchor<'a> {
        Minting(&'a test_pki::Authority),
        Garbage,
        Broken,
    }

    impl TimestampAnchor for ScriptedAnchor<'_> {
        type Error = std::io::Error;

        fn acquire_token(
            &mut self,
            payload: &[u8],
        ) -> Result<Vec<u8>, std::io::Error> {
            match self {
                Self::Minting(authority) => Ok(test_pki::encode_token(
                    &test_pki::standard_token_parts(payload, authority),
                    &authority.tsa_key,
                )),
                Self::Garbage => Ok(b"not a token".to_vec()),
                Self::Broken => {
                    Err(std::io::Error::other("the wire went dark"))
                }
            }
        }
    }

    struct Trust {
        authority: test_pki::Authority,
        bundle: test_pki::TrustDers,
    }

    fn standard_trust() -> Trust {
        let authority = test_pki::standard_authority();
        let bundle = test_pki::standard_trust_ders(&authority);
        Trust { authority, bundle }
    }

    impl Trust {
        fn data(&self) -> TrustData<'_> {
            TrustData {
                anchor_certificates: &self.bundle.anchors,
                companion_certificates: &self.bundle.companions,
                crls: &self.bundle.crls,
            }
        }
    }

    /// Builds the factory the tests hand to `run`: each call is
    /// recorded in `contacted`, then dispatched by site name against
    /// the scripted behaviors.
    fn scripted_factory<'a>(
        behaviors: &'a [(&'a str, ScriptedAnchor<'a>)],
        contacted: &'a RefCell<Vec<String>>,
    ) -> impl FnMut(&str, &Site) -> ScriptedAnchor<'a> {
        move |site_name, _site| {
            contacted.borrow_mut().push(site_name.to_string());
            behaviors
                .iter()
                .find(|(scripted_name, _)| *scripted_name == site_name)
                .unwrap_or_else(|| panic!("unscripted site {site_name:?}"))
                .1
        }
    }

    fn no_factory(site_name: &str, _site: &Site) -> ScriptedAnchor<'static> {
        panic!("no anchor may be built for {site_name:?}")
    }

    fn no_supplement(
        _site_name: &str,
        _token_bytes: &[u8],
    ) -> Result<Vec<Vec<u8>>, FailureCause> {
        Ok(Vec::new())
    }

    fn broken_supplement(
        _site_name: &str,
        _token_bytes: &[u8],
    ) -> Result<Vec<Vec<u8>>, FailureCause> {
        Err("the distribution point went dark".into())
    }

    fn inputs_of<'a>(
        config: &'a Config,
        profile_name: &'a str,
        trust: &'a Trust,
    ) -> AcquireInputs<'a> {
        AcquireInputs {
            config,
            profile_name,
            manifest_bytes: MANIFEST,
            trust: trust.data(),
        }
    }

    fn acquired_site_names(acquisition: &Acquisition) -> Vec<&str> {
        acquisition
            .tokens
            .iter()
            .map(|token| token.site_name.as_str())
            .collect()
    }

    #[test]
    fn a_profile_seals_one_verified_token_per_selected_site() {
        let trust = standard_trust();
        let config_text = format!(
            "{TWO_SITES}Profile plain\n\tUseSite alpha\n\tUseSite beta\n"
        );
        let config = parse(&config_text).expect("the fixture parses");
        let behaviors = [
            ("alpha", ScriptedAnchor::Minting(&trust.authority)),
            ("beta", ScriptedAnchor::Minting(&trust.authority)),
        ];
        let contacted = RefCell::new(Vec::new());
        let acquisition = run(
            &inputs_of(&config, "plain", &trust),
            scripted_factory(&behaviors, &contacted),
            no_supplement,
        )
        .expect("two healthy sites seal two tokens");
        assert_eq!(acquired_site_names(&acquisition), ["alpha", "beta"]);
        assert!(acquisition.warnings.is_empty());
        assert_eq!(*contacted.borrow(), ["alpha", "beta"]);
    }

    #[test]
    fn an_unknown_profile_aborts_the_stamp() {
        let trust = standard_trust();
        let config_text =
            format!("{TWO_SITES}Profile plain\n\tUseSite alpha\n");
        let config = parse(&config_text).expect("the fixture parses");
        let verdict = run(
            &inputs_of(&config, "ghost", &trust),
            no_factory,
            no_supplement,
        );
        assert!(matches!(
            verdict,
            Err(Error::UnknownProfile { profile_name }) if profile_name == "ghost"
        ));
    }

    #[test]
    fn an_unresolvable_selection_aborts_before_any_site_is_contacted() {
        let trust = standard_trust();
        // The parser rejects a dangling selection, so the hole is
        // reproduced the way it can actually arise: a configuration
        // assembled programmatically.
        let config = Config {
            sites: HashMap::from([(
                "alpha".to_string(),
                Site {
                    url: "https://alpha.example/tsr".to_string(),
                    imprint_algorithm: ImprintAlgorithm::Sha256,
                },
            )]),
            profiles: HashMap::from([(
                "holed".to_string(),
                Profile {
                    selections: vec![
                        UseSite {
                            site_name: "alpha".to_string(),
                            continues_on_error: false,
                        },
                        UseSite {
                            site_name: "ghost".to_string(),
                            continues_on_error: false,
                        },
                    ],
                },
            )]),
        };
        // The resolvable selection precedes the dangling one, so a
        // resolve-as-you-go implementation would already have
        // contacted a site; no_factory pins that none was.
        let verdict = run(
            &inputs_of(&config, "holed", &trust),
            no_factory,
            no_supplement,
        );
        assert!(matches!(
            verdict,
            Err(Error::UnknownSite { site_name }) if site_name == "ghost"
        ));
    }

    #[test]
    fn a_repeated_selection_aborts_before_any_site_is_contacted() {
        let trust = standard_trust();
        // The parser rejects a repeated selection, so the repetition
        // is assembled programmatically, as it can actually arise.
        let config = Config {
            sites: HashMap::from([(
                "alpha".to_string(),
                Site {
                    url: "https://alpha.example/tsr".to_string(),
                    imprint_algorithm: ImprintAlgorithm::Sha256,
                },
            )]),
            profiles: HashMap::from([(
                "echoed".to_string(),
                Profile {
                    selections: vec![
                        UseSite {
                            site_name: "alpha".to_string(),
                            continues_on_error: false,
                        },
                        UseSite {
                            site_name: "alpha".to_string(),
                            continues_on_error: false,
                        },
                    ],
                },
            )]),
        };
        let verdict = run(
            &inputs_of(&config, "echoed", &trust),
            no_factory,
            no_supplement,
        );
        assert!(matches!(
            verdict,
            Err(Error::DuplicateSelection { site_name }) if site_name == "alpha"
        ));
    }

    #[test]
    fn an_unmodified_site_failure_aborts_the_stamp() {
        let trust = standard_trust();
        let config_text =
            format!("{TWO_SITES}Profile plain\n\tUseSite alpha\n");
        let config = parse(&config_text).expect("the fixture parses");
        let behaviors = [("alpha", ScriptedAnchor::Broken)];
        let contacted = RefCell::new(Vec::new());
        let verdict = run(
            &inputs_of(&config, "plain", &trust),
            scripted_factory(&behaviors, &contacted),
            no_supplement,
        );
        assert!(matches!(
            verdict,
            Err(Error::SiteFailed(failure)) if failure.site_name == "alpha"
        ));
    }

    #[test]
    fn an_aborting_failure_contacts_no_further_site() {
        let trust = standard_trust();
        let config_text = format!(
            "{TWO_SITES}Profile plain\n\tUseSite alpha\n\tUseSite beta\n"
        );
        let config = parse(&config_text).expect("the fixture parses");
        let behaviors = [
            ("alpha", ScriptedAnchor::Broken),
            ("beta", ScriptedAnchor::Minting(&trust.authority)),
        ];
        let contacted = RefCell::new(Vec::new());
        let verdict = run(
            &inputs_of(&config, "plain", &trust),
            scripted_factory(&behaviors, &contacted),
            no_supplement,
        );
        assert!(matches!(verdict, Err(Error::SiteFailed(_))));
        assert_eq!(*contacted.borrow(), ["alpha"]);
    }

    #[test]
    fn a_tolerated_failure_is_reported_and_the_stamp_proceeds() {
        let trust = standard_trust();
        let config_text = format!(
            "{TWO_SITES}Profile mixed\n\
             \tUseSite alpha ContinueOnError\n\
             \tUseSite beta\n"
        );
        let config = parse(&config_text).expect("the fixture parses");
        let behaviors = [
            ("alpha", ScriptedAnchor::Broken),
            ("beta", ScriptedAnchor::Minting(&trust.authority)),
        ];
        let contacted = RefCell::new(Vec::new());
        let acquisition = run(
            &inputs_of(&config, "mixed", &trust),
            scripted_factory(&behaviors, &contacted),
            no_supplement,
        )
        .expect("the surviving site carries the stamp");
        assert_eq!(acquired_site_names(&acquisition), ["beta"]);
        assert_eq!(acquisition.warnings.len(), 1);
        assert_eq!(acquisition.warnings[0].site_name, "alpha");
    }

    #[test]
    fn zero_valid_tokens_abort_even_when_every_failure_is_tolerated() {
        let trust = standard_trust();
        let config_text = format!(
            "{TWO_SITES}Profile tolerant\n\
             \tUseSite alpha ContinueOnError\n\
             \tUseSite beta ContinueOnError\n"
        );
        let config = parse(&config_text).expect("the fixture parses");
        let behaviors = [
            ("alpha", ScriptedAnchor::Broken),
            ("beta", ScriptedAnchor::Broken),
        ];
        let contacted = RefCell::new(Vec::new());
        let verdict = run(
            &inputs_of(&config, "tolerant", &trust),
            scripted_factory(&behaviors, &contacted),
            no_supplement,
        );
        let Err(Error::NoValidTokens { failures }) = verdict else {
            panic!("expected NoValidTokens, got {verdict:?}");
        };
        assert_eq!(failures.len(), 2);
        assert_eq!(failures[0].site_name, "alpha");
        assert_eq!(failures[1].site_name, "beta");
    }

    #[test]
    fn a_token_failing_pre_seal_verification_is_a_site_failure() {
        let trust = standard_trust();
        let config_text =
            format!("{TWO_SITES}Profile plain\n\tUseSite alpha\n");
        let config = parse(&config_text).expect("the fixture parses");
        let behaviors = [("alpha", ScriptedAnchor::Garbage)];
        let contacted = RefCell::new(Vec::new());
        let verdict = run(
            &inputs_of(&config, "plain", &trust),
            scripted_factory(&behaviors, &contacted),
            no_supplement,
        );
        assert!(matches!(
            verdict,
            Err(Error::SiteFailed(failure)) if failure.site_name == "alpha"
        ));
    }

    #[test]
    fn a_supplement_failure_is_a_site_failure() {
        let trust = standard_trust();
        let config_text =
            format!("{TWO_SITES}Profile plain\n\tUseSite alpha\n");
        let config = parse(&config_text).expect("the fixture parses");
        let behaviors = [("alpha", ScriptedAnchor::Minting(&trust.authority))];
        let contacted = RefCell::new(Vec::new());
        let verdict = run(
            &inputs_of(&config, "plain", &trust),
            scripted_factory(&behaviors, &contacted),
            broken_supplement,
        );
        assert!(matches!(
            verdict,
            Err(Error::SiteFailed(failure)) if failure.site_name == "alpha"
        ));
    }

    #[test]
    fn a_supplemented_crl_joins_the_verification_basis() {
        let mut trust = standard_trust();
        // The base trust is stripped of its CRLs, so verification
        // can only succeed through the supplemented snapshot.
        let supplemented_crl = trust.bundle.crls.remove(0);
        assert!(trust.bundle.crls.is_empty());
        let config_text =
            format!("{TWO_SITES}Profile plain\n\tUseSite alpha\n");
        let config = parse(&config_text).expect("the fixture parses");
        let behaviors = [("alpha", ScriptedAnchor::Minting(&trust.authority))];
        let contacted = RefCell::new(Vec::new());
        let acquisition = run(
            &inputs_of(&config, "plain", &trust),
            scripted_factory(&behaviors, &contacted),
            |_site_name: &str,
             _token_bytes: &[u8]|
             -> Result<Vec<Vec<u8>>, FailureCause> {
                Ok(vec![supplemented_crl.clone()])
            },
        )
        .expect("the supplemented CRL carries verification");
        assert_eq!(acquired_site_names(&acquisition), ["alpha"]);
    }

    #[test]
    fn a_selection_less_profile_aborts_with_no_valid_tokens() {
        let trust = standard_trust();
        // Unreachable through the parser (a profile holds one or
        // more selections), so assembled programmatically.
        let config = Config {
            sites: HashMap::new(),
            profiles: HashMap::from([(
                "hollow".to_string(),
                Profile { selections: vec![] },
            )]),
        };
        let verdict = run(
            &inputs_of(&config, "hollow", &trust),
            no_factory,
            no_supplement,
        );
        let Err(Error::NoValidTokens { failures }) = verdict else {
            panic!("expected NoValidTokens, got {verdict:?}");
        };
        assert!(failures.is_empty());
    }
}

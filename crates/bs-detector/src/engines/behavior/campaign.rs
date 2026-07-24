/*
 * Copyright 2026, The KyzoDB Authors.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
 * If a copy of the MPL was not distributed with this file,
 * You can obtain one at https://mozilla.org/MPL/2.0/.
 */

//! Execution-campaign artifacts (TRUTH item 10).
//!
//! An artifact records declared source paths, blake3 per file, specimen
//! verdict, and timestamp. Meta reds: hash mismatch, specimen unflagged,
//! campaign missing, past freshness bound. Specimen verdict ≠ flagged
//! fails meta regardless of hashes and timestamp.

use std::path::{Path, PathBuf};

use serde::Deserialize;

use crate::boundary::{Label, RelPath};
use crate::engines::Hit;

/// Specimen campaign outcome recorded on the artifact.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SpecimenVerdict {
    Flagged,
    Unflagged,
    Clean,
}

impl SpecimenVerdict {
    pub fn as_str(&self) -> &'static str {
        match self {
            SpecimenVerdict::Flagged => "flagged",
            SpecimenVerdict::Unflagged => "unflagged",
            SpecimenVerdict::Clean => "clean",
        }
    }
}

/// One source file binding on a campaign artifact.
///
/// Fields are private (TRUTH item 9). Sole admission is
/// [`ArtifactSource::admit`]; callers read through accessors.
#[derive(Clone, Debug, Deserialize)]
pub struct ArtifactSource {
    path: RelPath,
    blake3: Label,
}

impl ArtifactSource {
    pub fn admit(path: impl Into<RelPath>, blake3: impl Into<Label>) -> Self {
        Self {
            path: path.into(),
            blake3: blake3.into(),
        }
    }

    pub fn path(&self) -> &str {
        self.path.as_str()
    }

    pub fn blake3(&self) -> &str {
        self.blake3.as_str()
    }
}

/// On-disk campaign artifact (committed under campaigns/).
///
/// Fields are private (TRUTH item 9). Sole admission is
/// [`CampaignArtifact::admit`]; callers read through accessors.
#[derive(Clone, Debug, Deserialize)]
pub struct CampaignArtifact {
    name: Label,
    timestamp_unix: u64,
    specimen_verdict: SpecimenVerdict,
    sources: Vec<ArtifactSource>,
}

impl CampaignArtifact {
    pub fn admit(
        name: impl Into<Label>,
        timestamp_unix: u64,
        specimen_verdict: SpecimenVerdict,
        sources: Vec<ArtifactSource>,
    ) -> Self {
        Self {
            name: name.into(),
            timestamp_unix,
            specimen_verdict,
            sources,
        }
    }

    pub fn name(&self) -> &str {
        self.name.as_str()
    }

    pub fn timestamp_unix(&self) -> u64 {
        self.timestamp_unix
    }

    pub fn specimen_verdict(&self) -> &SpecimenVerdict {
        &self.specimen_verdict
    }

    pub fn sources(&self) -> &[ArtifactSource] {
        &self.sources
    }
}

/// Campaign seat from laws.toml [[campaign]].
///
/// Fields are private (TRUTH item 9). Sole admission is
/// [`CampaignSeat::admit`]; callers read through accessors.
#[derive(Clone, Debug)]
pub struct CampaignSeat {
    name: Label,
    artifact: RelPath,
    freshness_bound_secs: u64,
    sources: Vec<RelPath>,
}

impl CampaignSeat {
    pub fn admit(
        name: impl Into<Label>,
        artifact: impl Into<RelPath>,
        freshness_bound_secs: u64,
        sources: Vec<RelPath>,
    ) -> Self {
        Self {
            name: name.into(),
            artifact: artifact.into(),
            freshness_bound_secs,
            sources,
        }
    }

    pub fn name(&self) -> &str {
        self.name.as_str()
    }

    pub fn artifact(&self) -> &str {
        self.artifact.as_str()
    }

    pub fn freshness_bound_secs(&self) -> u64 {
        self.freshness_bound_secs
    }

    pub fn sources(&self) -> &[RelPath] {
        &self.sources
    }
}

/// Refuse reasons when loading/building an artifact (typed, not String).
#[derive(Debug)]
pub enum ArtifactRefuse {
    Io(Label),
    Parse(Label),
    Hash(Label),
}

impl std::fmt::Display for ArtifactRefuse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ArtifactRefuse::Io(s) | ArtifactRefuse::Parse(s) | ArtifactRefuse::Hash(s) => {
                f.write_str(s.as_str())
            }
        }
    }
}

impl CampaignArtifact {
    pub fn load(path: &Path) -> Result<Self, ArtifactRefuse> {
        let text = std::fs::read_to_string(path).map_err(|e| {
            ArtifactRefuse::Io(Label::admit(format!("reading {}: {e}", path.display())))
        })?;
        toml::from_str(&text).map_err(|e| {
            ArtifactRefuse::Parse(Label::admit(format!("parsing {}: {e}", path.display())))
        })
    }

    /// Build a fresh artifact from live source bytes + specimen verdict.
    /// `timestamp_unix` is host-injected — this crate never reads the wall clock.
    pub fn mint(
        name: &str,
        repo_root: &Path,
        sources: &[String],
        specimen_verdict: SpecimenVerdict,
        timestamp_unix: u64,
    ) -> Result<Self, ArtifactRefuse> {
        let mut out = Vec::with_capacity(sources.len());
        for rel in sources {
            let abs = repo_root.join(rel);
            let bytes = std::fs::read(&abs).map_err(|e| {
                ArtifactRefuse::Io(Label::admit(format!("hashing {rel}: {e}")))
            })?;
            let digest = blake3::hash(&bytes);
            out.push(ArtifactSource::admit(
                rel.clone(),
                digest.to_hex().to_string(),
            ));
        }
        Ok(Self::admit(name, timestamp_unix, specimen_verdict, out))
    }

    pub fn render_toml(&self) -> String {
        let mut s = String::new();
        s.push_str(&format!("name = {:?}\n", self.name()));
        s.push_str(&format!("timestamp_unix = {}\n", self.timestamp_unix()));
        s.push_str(&format!(
            "specimen_verdict = {:?}\n\n",
            self.specimen_verdict.as_str()
        ));
        for src in &self.sources {
            s.push_str("[[sources]]\n");
            s.push_str(&format!("path = {:?}\n", src.path()));
            s.push_str(&format!("blake3 = {:?}\n\n", src.blake3()));
        }
        s
    }
}

/// Campaign-meta authority — tip 806/914: no free helpers.
pub struct CampaignLaw;

/// The one production door for campaign artifact meta.
pub const CAMPAIGN: CampaignLaw = CampaignLaw;

impl CampaignLaw {
    fn live_blake3(&self, repo_root: &Path, rel: &str) -> Result<String, ArtifactRefuse> {
        let bytes = std::fs::read(repo_root.join(rel))
            .map_err(|e| ArtifactRefuse::Io(Label::admit(format!("reading {rel}: {e}"))))?;
        Ok(blake3::hash(&bytes).to_hex().to_string())
    }

    /// Meta pass over every seated campaign. Proof law: specimen ≠ flagged →
    /// red regardless of hashes and timestamp.
    ///
    /// `now_unix` is the host observation instant — this crate never reads the
    /// wall clock (nondeterminism ban).
    pub fn verify_campaigns(
        &self,
        repo_root: &Path,
        seats: &[CampaignSeat],
        now_unix: u64,
    ) -> Vec<Hit> {
        let mut hits = Vec::new();
        for seat in seats {
            let art_path = repo_root
                .join("crates/bs-detector")
                .join(seat.artifact());
            let artifact = match CampaignArtifact::load(&art_path) {
                Ok(a) => a,
                Err(_) => {
                    hits.push(Hit::admit(
                        seat.artifact(),
                        1,
                        format!("campaign_missing:{}", seat.name()),
                    ));
                    continue;
                }
            };

            // Specimen first — the proof law: unflagged fails even if hashes ok.
            if *artifact.specimen_verdict() != SpecimenVerdict::Flagged {
                hits.push(Hit::admit(
                    seat.artifact(),
                    1,
                    format!(
                        "campaign_specimen_unflagged:{}:{}",
                        seat.name(),
                        artifact.specimen_verdict().as_str()
                    ),
                ));
                // Still report other defects, but specimen alone is enough to red.
            }

            if artifact.name() != seat.name() {
                hits.push(Hit::admit(
                    seat.artifact(),
                    1,
                    format!("campaign_missing:{}:name_mismatch", seat.name()),
                ));
            }

            // INVARIANT(CampaignFreshness): age is only defined when observation
            // instant is at/after the artifact stamp. A future stamp is clock
            // skew or forgery — typed red (`campaign_future_stamp`), never
            // silently-fresh via u64::MIN / Err→0 / saturating_sub (tip 1007).
            match now_unix.checked_sub(artifact.timestamp_unix()) {
                Some(age) if age > seat.freshness_bound_secs() => {
                    hits.push(Hit::admit(
                        seat.artifact(),
                        1,
                        format!("campaign_stale:{}", seat.name()),
                    ));
                }
                Some(_fresh) => {}
                None => {
                    hits.push(Hit::admit(
                        seat.artifact(),
                        1,
                        format!("campaign_future_stamp:{}", seat.name()),
                    ));
                }
            }

            // Declared sources must match seat and hash live bytes.
            let declared: std::collections::BTreeSet<&str> =
                seat.sources().iter().map(RelPath::as_str).collect();
            let recorded: std::collections::BTreeSet<&str> =
                artifact.sources().iter().map(ArtifactSource::path).collect();
            if declared != recorded {
                hits.push(Hit::admit(
                    seat.artifact(),
                    1,
                    format!("campaign_hash_mismatch:{}:source_set", seat.name()),
                ));
            }
            for src in artifact.sources() {
                match self.live_blake3(repo_root, src.path()) {
                    Ok(live) if live == src.blake3() => {}
                    Ok(_) => hits.push(Hit::admit(
                        src.path(),
                        1,
                        format!("campaign_hash_mismatch:{}", seat.name()),
                    )),
                    Err(_) => hits.push(Hit::admit(
                        src.path(),
                        1,
                        format!("campaign_hash_mismatch:{}:unreadable", seat.name()),
                    )),
                }
            }
        }
        hits
    }

    /// Resolve artifact path under the detector crate.
    pub fn artifact_abs(&self, repo_root: &Path, seat: &CampaignSeat) -> PathBuf {
        repo_root
            .join("crates/bs-detector")
            .join(seat.artifact())
    }
}

#[cfg(test)]
#[derive(Debug)]
enum CampaignProofRefuse {
    Tempdir,
    Mkdir,
    WriteSource,
    MkdirArt,
    WriteArtifact,
    SpecimenUnflaggedMustRed,
    FutureStampMustRed,
}
#[cfg(test)]
impl CampaignProofRefuse {
    fn require(self, cond: bool) -> Result<(), CampaignProofRefuse> {
        if cond {
            Ok(())
        } else {
            Err(self)
        }
    }
}


#[cfg(test)]
mod tests {
    use super::{
        ArtifactSource, CampaignArtifact, CampaignProofRefuse, CampaignSeat, RelPath,
        SpecimenVerdict, CAMPAIGN,
    };
    use std::path::{Path, PathBuf};

    type TestResult = Result<(), CampaignProofRefuse>;

    struct CampaignProbe {
        root: PathBuf,
        seats: [CampaignSeat; 1],
    }

    /// Receiver for seed helper — free helpers are unclassified-fn (tip 1071).
    struct CampaignProofs;
    const P: CampaignProofs = CampaignProofs;

    impl CampaignProofs {
        /// One shared seed for campaign freshness proofs (tip 1010 — not twin bodies).
        fn seed_campaign_probe(
            &self,
            body: &[u8],
            artifact_stamp: u64,
            verdict: SpecimenVerdict,
        ) -> Result<(tempfile::TempDir, CampaignProbe), CampaignProofRefuse> {
            let tmp = tempfile::tempdir().map_err(|_| CampaignProofRefuse::Tempdir)?;
            let root = tmp.path().to_path_buf();
            let src_rel = "crates/bs-detector/src/engines/behavior/campaign.rs";
            let src_path = root.join(src_rel);
            match src_path.parent() {
                None => return Err(CampaignProofRefuse::Mkdir),
                Some(dir) => {
                    std::fs::create_dir_all(dir).map_err(|_| CampaignProofRefuse::Mkdir)?;
                }
            }
            match std::fs::write(&src_path, body) {
                Ok(()) => {}
                Err(_) => return Err(CampaignProofRefuse::WriteSource),
            }
            let digest = blake3::hash(body).to_hex().to_string();
            let art_path =
                root.join("crates/bs-detector/campaigns/build_script_sandbox/artifact.toml");
            match art_path.parent() {
                None => return Err(CampaignProofRefuse::MkdirArt),
                Some(dir) => {
                    std::fs::create_dir_all(dir).map_err(|_| CampaignProofRefuse::MkdirArt)?;
                }
            }
            let art = CampaignArtifact::admit(
                "build_script_sandbox",
                artifact_stamp,
                verdict,
                vec![ArtifactSource::admit(src_rel, digest)],
            );
            match std::fs::write(&art_path, art.render_toml()) {
                Ok(()) => {}
                Err(_) => return Err(CampaignProofRefuse::WriteArtifact),
            }
            let seats = [CampaignSeat::admit(
                "build_script_sandbox",
                "campaigns/build_script_sandbox/artifact.toml",
                86_400,
                vec![RelPath::admit(src_rel)],
            )];
            Ok((
                tmp,
                CampaignProbe {
                    root,
                    seats,
                },
            ))
        }
    }

    #[test]
    fn specimen_unflagged_reds_even_with_fresh_matching_hashes() -> TestResult {
        let stamp = 1_700_000_000_u64;
        let (_tmp, probe) = P.seed_campaign_probe(
            b"fn campaign_fixture() {}\n",
            stamp,
            SpecimenVerdict::Unflagged,
        )?;
        let hits = CAMPAIGN.verify_campaigns(Path::new(&probe.root), &probe.seats, stamp);
        CampaignProofRefuse::SpecimenUnflaggedMustRed.require(
            hits.iter()
                .any(|h| h.construct().starts_with("campaign_specimen_unflagged:")),
        )
    }

    /// Tip 1007: a future-dated artifact must red as `campaign_future_stamp`,
    /// never pass freshness as silently-fresh age 0.
    /// Control flow deliberately ≠ the specimen proof (tip 1010 copy_detector).
    #[test]
    fn future_dated_artifact_reds_as_campaign_future_stamp() -> TestResult {
        let now = 1_700_000_000_u64;
        let seeded = P.seed_campaign_probe(
            b"fn campaign_future_fixture() {}\n",
            now + 86_400,
            SpecimenVerdict::Flagged,
        )?;
        let hits = CAMPAIGN.verify_campaigns(Path::new(&seeded.1.root), &seeded.1.seats, now);
        match hits.iter().find(|h| h.construct().contains("future_stamp")) {
            Some(_hit) => Ok(()),
            None => Err(CampaignProofRefuse::FutureStampMustRed),
        }
    }
}

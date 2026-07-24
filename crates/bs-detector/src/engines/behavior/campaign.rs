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
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::engines::Hit;

/// Specimen campaign outcome recorded on the artifact.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
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
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ArtifactSource {
    pub path: String,
    pub blake3: String,
}

/// On-disk campaign artifact (committed under campaigns/).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CampaignArtifact {
    pub name: String,
    pub timestamp_unix: u64,
    pub specimen_verdict: SpecimenVerdict,
    pub sources: Vec<ArtifactSource>,
}

/// Campaign seat from laws.toml [[campaign]].
#[derive(Clone, Debug)]
pub struct CampaignSeat {
    pub name: String,
    pub artifact: String,
    pub freshness_bound_secs: u64,
    pub sources: Vec<String>,
}

/// Refuse reasons when loading/building an artifact (typed, not String).
#[derive(Debug)]
pub enum ArtifactRefuse {
    Io(String),
    Parse(String),
    Hash(String),
}

impl std::fmt::Display for ArtifactRefuse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ArtifactRefuse::Io(s) | ArtifactRefuse::Parse(s) | ArtifactRefuse::Hash(s) => {
                f.write_str(s)
            }
        }
    }
}

impl CampaignArtifact {
    pub fn load(path: &Path) -> Result<Self, ArtifactRefuse> {
        let text = std::fs::read_to_string(path).map_err(|e| {
            ArtifactRefuse::Io(format!("reading {}: {e}", path.display()))
        })?;
        toml::from_str(&text).map_err(|e| {
            ArtifactRefuse::Parse(format!("parsing {}: {e}", path.display()))
        })
    }

    /// Build a fresh artifact from live source bytes + specimen verdict.
    pub fn mint(
        name: &str,
        repo_root: &Path,
        sources: &[String],
        specimen_verdict: SpecimenVerdict,
    ) -> Result<Self, ArtifactRefuse> {
        let mut out = Vec::with_capacity(sources.len());
        for rel in sources {
            let abs = repo_root.join(rel);
            let bytes = std::fs::read(&abs).map_err(|e| {
                ArtifactRefuse::Io(format!("hashing {rel}: {e}"))
            })?;
            let digest = blake3::hash(&bytes);
            out.push(ArtifactSource {
                path: rel.clone(),
                blake3: digest.to_hex().to_string(),
            });
        }
        let timestamp_unix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        Ok(Self {
            name: name.to_string(),
            timestamp_unix,
            specimen_verdict,
            sources: out,
        })
    }

    pub fn render_toml(&self) -> String {
        let mut s = String::new();
        s.push_str(&format!("name = {:?}\n", self.name));
        s.push_str(&format!("timestamp_unix = {}\n", self.timestamp_unix));
        s.push_str(&format!(
            "specimen_verdict = {:?}\n\n",
            self.specimen_verdict.as_str()
        ));
        for src in &self.sources {
            s.push_str("[[sources]]\n");
            s.push_str(&format!("path = {:?}\n", src.path));
            s.push_str(&format!("blake3 = {:?}\n\n", src.blake3));
        }
        s
    }
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn live_blake3(repo_root: &Path, rel: &str) -> Result<String, ArtifactRefuse> {
    let bytes = std::fs::read(repo_root.join(rel))
        .map_err(|e| ArtifactRefuse::Io(format!("reading {rel}: {e}")))?;
    Ok(blake3::hash(&bytes).to_hex().to_string())
}

/// Meta pass over every seated campaign. Proof law: specimen ≠ flagged →
/// red regardless of hashes and timestamp.
pub fn verify_campaigns(repo_root: &Path, seats: &[CampaignSeat]) -> Vec<Hit> {
    let mut hits = Vec::new();
    for seat in seats {
        let art_path = repo_root
            .join("crates/bs-detector")
            .join(&seat.artifact);
        let artifact = match CampaignArtifact::load(&art_path) {
            Ok(a) => a,
            Err(_) => {
                hits.push(Hit::admit(
                    seat.artifact.clone(),
                    1,
                    format!("campaign_missing:{}", seat.name),
                ));
                continue;
            }
        };

        // Specimen first — the proof law: unflagged fails even if hashes ok.
        if artifact.specimen_verdict != SpecimenVerdict::Flagged {
            hits.push(Hit::admit(
                seat.artifact.clone(),
                1,
                format!(
                    "campaign_specimen_unflagged:{}:{}",
                    seat.name,
                    artifact.specimen_verdict.as_str()
                ),
            ));
            // Still report other defects, but specimen alone is enough to red.
        }

        if artifact.name != seat.name {
            hits.push(Hit::admit(
                seat.artifact.clone(),
                1,
                format!("campaign_missing:{}:name_mismatch", seat.name),
            ));
        }

        let now = now_unix();
        if now.saturating_sub(artifact.timestamp_unix) > seat.freshness_bound_secs {
            hits.push(Hit::admit(
                seat.artifact.clone(),
                1,
                format!("campaign_stale:{}", seat.name),
            ));
        }

        // Declared sources must match seat and hash live bytes.
        let declared: std::collections::BTreeSet<&str> =
            seat.sources.iter().map(String::as_str).collect();
        let recorded: std::collections::BTreeSet<&str> =
            artifact.sources.iter().map(|s| s.path.as_str()).collect();
        if declared != recorded {
            hits.push(Hit::admit(
                seat.artifact.clone(),
                1,
                format!("campaign_hash_mismatch:{}:source_set", seat.name),
            ));
        }
        for src in &artifact.sources {
            match live_blake3(repo_root, &src.path) {
                Ok(live) if live == src.blake3 => {}
                Ok(_) => hits.push(Hit::admit(
                    src.path.clone(),
                    1,
                    format!("campaign_hash_mismatch:{}", seat.name),
                )),
                Err(_) => hits.push(Hit::admit(
                    src.path.clone(),
                    1,
                    format!("campaign_hash_mismatch:{}:unreadable", seat.name),
                )),
            }
        }
    }
    hits
}

/// Resolve artifact path under the detector crate.
pub fn artifact_abs(repo_root: &Path, seat: &CampaignSeat) -> PathBuf {
    repo_root
        .join("crates/bs-detector")
        .join(&seat.artifact)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn specimen_unflagged_reds_even_with_fresh_matching_hashes() {
        let tmp = tempfile::tempdir().expect("tmp");
        let root = tmp.path();
        let src_rel = "crates/bs-detector/src/engines/behavior/campaign.rs";
        let src_dir = root.join("crates/bs-detector/src/engines/behavior");
        std::fs::create_dir_all(&src_dir).expect("mkdir");
        let body = b"fn campaign_fixture() {}\n";
        std::fs::write(src_dir.join("campaign.rs"), body).expect("write");
        let digest = blake3::hash(body).to_hex().to_string();

        let art_dir = root.join("crates/bs-detector/campaigns/build_script_sandbox");
        std::fs::create_dir_all(&art_dir).expect("mkdir art");
        let art = CampaignArtifact {
            name: "build_script_sandbox".to_string(),
            timestamp_unix: now_unix(),
            specimen_verdict: SpecimenVerdict::Unflagged,
            sources: vec![ArtifactSource {
                path: src_rel.to_string(),
                blake3: digest,
            }],
        };
        std::fs::write(art_dir.join("artifact.toml"), art.render_toml()).expect("art");

        let seats = vec![CampaignSeat {
            name: "build_script_sandbox".to_string(),
            artifact: "campaigns/build_script_sandbox/artifact.toml".to_string(),
            freshness_bound_secs: 86_400,
            sources: vec![src_rel.to_string()],
        }];
        let hits = verify_campaigns(root, &seats);
        assert!(
            hits.iter()
                .any(|h| h.construct().starts_with("campaign_specimen_unflagged:")),
            "specimen ≠ flagged must red: {hits:?}"
        );
    }
}

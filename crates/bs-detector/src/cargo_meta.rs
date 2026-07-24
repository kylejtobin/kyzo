/*
 * Copyright 2026, The KyzoDB Authors.
 * KyzoDB is a fork of CozoDB (Copyright 2022, The Cozo Project Authors).
 *
 * This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
 * If a copy of the MPL was not distributed with this file,
 * You can obtain one at https://mozilla.org/MPL/2.0/.
 */

//! Shared `cargo metadata` JSON shape for the pure-Rust and build-script-
//! sandbox gates. One deserialize type — never a per-check twin that can
//! drift field-by-field.

use serde::Deserialize;
use serde::de::Error as _;
use serde_json::{Map, Value};

use crate::boundary::{Label, RelPath};

/// Shape of `cargo metadata --format-version=1`, trimmed to the fields the
/// two gates need. `--no-deps` callers simply never see dependency packages;
/// full-graph callers get them. Extra JSON fields cargo may emit are ignored.
///
/// Fields are private (TRUTH item 9). Deserialize is the sole admission
/// door; callers read through accessors.
#[derive(Debug)]
pub struct CargoMetadata {
    packages: Vec<MetaPackage>,
    workspace_members: Vec<Label>,
    workspace_root: RelPath,
    /// Present on a full-graph `cargo metadata` response; empty when a
    /// `--no-deps` parse omits the key (explicit absence at this door).
    target_directory: RelPath,
}

impl CargoMetadata {
    pub fn packages(&self) -> &[MetaPackage] {
        &self.packages
    }

    pub fn workspace_members(&self) -> &[Label] {
        &self.workspace_members
    }

    pub fn workspace_root(&self) -> &str {
        self.workspace_root.as_str()
    }

    pub fn target_directory(&self) -> &str {
        self.target_directory.as_str()
    }
}

/// Fields are private (TRUTH item 9). Deserialize is the sole admission
/// door; callers read through accessors.
#[derive(Debug)]
pub struct MetaPackage {
    id: Label,
    name: Label,
    manifest_path: RelPath,
    /// Empty when a `--no-deps` payload omits version; the build-script
    /// sandbox always sees a real version on a full-graph parse.
    version: Label,
    /// `null` unless the manifest sets `publish`; `Some([])` is exactly
    /// `publish = false`, `Some([..])` is a registry allowlist. Missing key
    /// is `None` — same meaning as cargo omitting the field.
    publish: Option<Vec<Label>>,
    /// Empty when the payload omits targets.
    targets: Vec<MetaTarget>,
}

impl MetaPackage {
    pub fn id(&self) -> &str {
        self.id.as_str()
    }

    pub fn name(&self) -> &str {
        self.name.as_str()
    }

    pub fn manifest_path(&self) -> &str {
        self.manifest_path.as_str()
    }

    pub fn version(&self) -> &str {
        self.version.as_str()
    }

    pub fn publish(&self) -> Option<&[Label]> {
        self.publish.as_deref()
    }

    pub fn targets(&self) -> &[MetaTarget] {
        &self.targets
    }
}

/// Fields are private (TRUTH item 9). Deserialize is the sole admission
/// door; callers read through [`MetaTarget::kind`].
#[derive(Debug, Deserialize)]
pub struct MetaTarget {
    kind: Vec<Label>,
}

impl MetaTarget {
    pub fn kind(&self) -> &[Label] {
        &self.kind
    }
}

/// Cargo-metadata decode authority — tip 806/914: no free helpers.
pub struct CargoMetaLaw;

/// The one production door for cargo-metadata field lifts.
pub const CARGO_META: CargoMetaLaw = CargoMetaLaw;

impl CargoMetaLaw {
    fn take_string(&self, map: &mut Map<String, Value>, key: &str) -> Result<String, String> {
        match map.remove(key) {
            Some(Value::String(s)) => Ok(s),
            Some(other) => Err(format!("{key} must be a string, got {other}")),
            None => Err(format!("missing field `{key}`")),
        }
    }

    fn take_string_or_empty(
        &self,
        map: &mut Map<String, Value>,
        key: &str,
    ) -> Result<String, String> {
        match map.remove(key) {
            None | Some(Value::Null) => Ok(String::new()),
            Some(Value::String(s)) => Ok(s),
            Some(other) => Err(format!("{key} must be a string, got {other}")),
        }
    }
}

impl<'de> Deserialize<'de> for CargoMetadata {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let mut map = Map::<String, Value>::deserialize(deserializer)?;
        let packages = match map.remove("packages") {
            Some(v) => Vec::<MetaPackage>::deserialize(v).map_err(D::Error::custom)?,
            None => return Err(D::Error::missing_field("packages")),
        };
        let workspace_members = match map.remove("workspace_members") {
            Some(v) => Vec::<Label>::deserialize(v).map_err(D::Error::custom)?,
            None => return Err(D::Error::missing_field("workspace_members")),
        };
        let workspace_root = CARGO_META
            .take_string(&mut map, "workspace_root")
            .map_err(D::Error::custom)?;
        let target_directory = CARGO_META
            .take_string_or_empty(&mut map, "target_directory")
            .map_err(D::Error::custom)?;
        Ok(Self {
            packages,
            workspace_members,
            workspace_root: RelPath::admit(workspace_root),
            target_directory: RelPath::admit(target_directory),
        })
    }
}

impl<'de> Deserialize<'de> for MetaPackage {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let mut map = Map::<String, Value>::deserialize(deserializer)?;
        let id = CARGO_META
            .take_string(&mut map, "id")
            .map_err(D::Error::custom)?;
        let name = CARGO_META
            .take_string(&mut map, "name")
            .map_err(D::Error::custom)?;
        let manifest_path = CARGO_META
            .take_string(&mut map, "manifest_path")
            .map_err(D::Error::custom)?;
        let version = CARGO_META
            .take_string_or_empty(&mut map, "version")
            .map_err(D::Error::custom)?;
        let publish = match map.remove("publish") {
            None | Some(Value::Null) => None,
            Some(v) => Some(Vec::<Label>::deserialize(v).map_err(D::Error::custom)?),
        };
        let targets = match map.remove("targets") {
            None | Some(Value::Null) => Vec::new(),
            Some(v) => Vec::<MetaTarget>::deserialize(v).map_err(D::Error::custom)?,
        };
        Ok(Self {
            id: Label::admit(id),
            name: Label::admit(name),
            manifest_path: RelPath::admit(manifest_path),
            version: Label::admit(version),
            publish,
            targets,
        })
    }
}

/*
 * Copyright 2026, The KyzoDB Authors.
 * KyzoDB is a fork of CozoDB (Copyright 2022, The Cozo Project Authors).
 *
 * This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
 * If a copy of the MPL was not distributed with this file,
 * You can obtain one at https://mozilla.org/MPL/2.0/.
 */

//! Domain-separation tags for identity digests and KDFs (not sealed-artifact wire).
//!
//! Seat 59's [`super::transcript::CanonicalTranscript`] is the one sealed-artifact
//! constructor. Every other SHA-256 domain tag that still must preserve its
//! historical `label ‖ payload` layout sits here as a closed vocabulary — one
//! absorb door, no call-site `hasher.update(b"…")` second serializers.

use sha2::digest::Update;

/// Closed vocabulary of identity-digest / KDF domain tags.
///
/// Each variant's bytes are the published domain label. Call sites absorb via
/// [`DigestDomain::absorb`]; inventing a new tag requires seating a variant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum DigestDomain {
    /// Genesis RootChain content tip at admission seats open.
    AdmissionSeatsGenesisRoot,
    /// Scope manifest identity digest.
    ScopeManifest,
    /// Catalog generation schema-cut identity.
    CatalogGenerationSchemaCut,
    /// Origin-sealed lowering replay meter.
    OriginSealedLowering,
    /// Promotion valid-time seat bind.
    PromotionValidTime,
    /// Promotion provenance seat bind.
    PromotionProvenance,
    /// `StatementSource::Unbound` discriminant inside provenance digest.
    ProvenanceUnbound,
    /// Semantic-deletion content identity.
    SemanticDeletion,
    /// Client-rooted CompositionId (§38).
    CompositionId,
    /// Canonical composition shape digest before CompositionId.
    CompositionDigest,
    /// Compensation-step separator inside composition digest.
    CompositionCompensation,
    /// Address-fence map key.
    AddressFence,
    /// Audit-key leaf MAC domain.
    AuditLeaf,
    /// Per-segment DEK KDF.
    DekDerive,
    /// OperationKey idempotency organ (§38/§39).
    OperationKey,
    /// Degenerate CompositionId for single-store OperationKey.
    CompositionIdDegenerate,
    /// IdempotencyMemo request digest over sealed envelope bytes.
    RequestDigest,
    /// Durable commit-cut pair bind.
    DurableCommitCut,
    /// AEAD nonce KDF.
    Nonce,
    /// StoreId genesis bind.
    StoreIdGenesis,
    /// Recovery-matrix present pole inside StoreId genesis.
    RecoveryMatrixPresent,
    /// Recovery-matrix absent pole inside StoreId genesis.
    RecoveryMatrixAbsent,
    /// WriteAuthority genesis bind.
    WriteAuthorityGenesis,
    /// Authorizing-key seed reroll domain.
    AuthorizingKeySeedReroll,
    /// ReplicaKey custody identity.
    ReplicaKey,
    /// AdmissionCertificate signing domain (over transcript bytes).
    AdmissionCertificateSign,
    /// Live-sweep write-token identity.
    LiveSweepWriteToken,
    /// Live-sweep incarnation entropy domain.
    LiveSweepIncarnationEntropy,
    /// Commit-write content identity.
    CommitWriteContent,
    /// Keyspace-scoped integrity checksum.
    KeyspaceScopedChecksum,
    /// Deep-verify report persistence identity.
    DeepVerifyReport,
    /// Index-row re-derivation compare key.
    IndexRowDigest,
    /// Namespaced federation record identity (four-tuple).
    NamespacedRecordIdentity,
    /// PromotionMeaning four-seat replay meter.
    PromotionMeaning,
    /// Sugar correction content identity.
    SugarCorrection,
    /// Sugar relation-row content identity.
    SugarRow,
}

impl DigestDomain {
    /// Published domain-label bytes for this tag (stable; do not reorder lightly).
    pub(crate) const fn as_bytes(self) -> &'static [u8] {
        match self {
            Self::AdmissionSeatsGenesisRoot => b"kyzo.admission.seats.genesis_root.v1",
            Self::ScopeManifest => b"kyzo.scope.manifest.v1",
            Self::CatalogGenerationSchemaCut => b"kyzo.catalog.generation.schema_cut.v1",
            Self::OriginSealedLowering => b"kyzo.origin_sealed_lowering.v1",
            Self::PromotionValidTime => b"kyzo.promotion.valid_time.v1",
            Self::PromotionProvenance => b"kyzo.promotion.provenance.v1",
            Self::ProvenanceUnbound => b"unbound",
            Self::SemanticDeletion => b"kyzo.semantic.deletion.v1",
            Self::CompositionId => b"kyzo.composition_id.v1",
            Self::CompositionDigest => b"kyzo.composition_digest.v1",
            Self::CompositionCompensation => b"compensation",
            Self::AddressFence => b"kyzo.address_fence.v1",
            Self::AuditLeaf => b"kyzo.audit.leaf.v1",
            Self::DekDerive => b"kyzo.dek.derive.v1",
            Self::OperationKey => b"kyzo.operation_key.v1",
            Self::CompositionIdDegenerate => b"kyzo.composition_id.degenerate.v1",
            Self::RequestDigest => b"kyzo.request_digest.v1",
            Self::DurableCommitCut => b"kyzo.durable_commit_cut.v1",
            Self::Nonce => b"kyzo.nonce.v1",
            Self::StoreIdGenesis => b"kyzo.store_id.genesis.v1",
            Self::RecoveryMatrixPresent => b"recovery_matrix",
            Self::RecoveryMatrixAbsent => b"no_recovery_matrix",
            Self::WriteAuthorityGenesis => b"kyzo.write_authority.genesis.v1",
            Self::AuthorizingKeySeedReroll => b"kyzo.authorizing_key.seed_reroll.v1",
            Self::ReplicaKey => b"kyzo.replica_key.v1",
            Self::AdmissionCertificateSign => b"kyzo.admission_certificate.sign.v1",
            Self::LiveSweepWriteToken => b"kyzo.live_sweep.write_token.v1",
            Self::LiveSweepIncarnationEntropy => b"kyzo.live_sweep.incarnation_entropy.v1",
            Self::CommitWriteContent => b"kyzo.commit_write.content.v1",
            Self::KeyspaceScopedChecksum => b"kyzo.keyspace_scoped_checksum.v1",
            Self::DeepVerifyReport => b"kyzo.deep_verify_report.v1",
            Self::IndexRowDigest => b"kyzo.index_row_digest.v1",
            Self::NamespacedRecordIdentity => b"kyzo.namespaced_record_identity.v1",
            Self::PromotionMeaning => b"kyzo.promotion_meaning.v1",
            Self::SugarCorrection => b"kyzo.sugar.correction.v1",
            Self::SugarRow => b"kyzo.sugar.row.v1",
        }
    }

    /// Absorb this domain tag into a hasher — the one door for identity/KDF labels.
    pub(crate) fn absorb(self, hasher: &mut impl Update) {
        hasher.update(self.as_bytes());
    }
}

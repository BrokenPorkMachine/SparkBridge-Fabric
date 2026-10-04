use anyhow::{Context, Result, bail};
use rusqlite::{Connection, OptionalExtension, params};
use sha2::{Digest, Sha256};
use sparkbridge_core::NodeId;
use sparkbridge_protocol::{
    ActionCacheRecord, ActionCompletionRequest, ActionExecutionResult, ActionLease, ActionRecord, ActionSideEffect, ActionStatus, CacheTrust,
    ApprovalRecord, ApprovalStatus, AuditRecord, AuditVerifyResponse, CapabilityReport,
    CandidateRecord, EnrollmentTokenResponse, NodeRecord, NodeStatus, Permission, PolicyDecision,
    PrincipalKind, PrincipalRecord, PromotionOutcome, PromotionRecord, PromotionReportRequest,
    ProtocolVersion, SnapshotRegistrationRequest, SnapshotRecord, ValidationRunRecord, WorkspacePolicyRecord,
};
use sparkbridge_task::{TaskEvent, TaskEventKind, TaskRecord, TaskStatus};
use sparkbridge_index::{NativeIntelligenceRecord, RepositoryIndexRecord};
use sparkbridge_audit::{AuditEnvelope, hash_envelope, new_event_id};
use std::{path::Path, sync::Mutex};
use tracing::warn;
use uuid::Uuid;

pub struct Store {
    connection: Mutex<Connection>,
}

impl Store {
    pub fn open(path: &Path) -> Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("creating {}", parent.display()))?;
        }
        let connection = Connection::open(path)
            .with_context(|| format!("opening SQLite database {}", path.display()))?;
        connection.pragma_update(None, "journal_mode", "WAL")?;
        connection.pragma_update(None, "foreign_keys", "ON")?;
        migrate_schema(&connection)?;
        seed_default_principal(&connection)?;
        Ok(Self { connection: Mutex::new(connection) })
    }

    pub fn create_enrollment_token(
        &self,
        ttl_seconds: u64,
        label: Option<String>,
        now_ms: u64,
    ) -> Result<EnrollmentTokenResponse> {
        let token = format!("{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple());
        let expires_unix_ms = now_ms.saturating_add(ttl_seconds.saturating_mul(1000));
        let hash = hash_secret(&token);
        let connection = self.connection.lock().expect("database mutex poisoned");
        connection.execute(
            "INSERT INTO enrollment_tokens(token_hash, expires_unix_ms, label) VALUES (?1, ?2, ?3)",
            params![hash, expires_unix_ms as i64, label],
        )?;
        Ok(EnrollmentTokenResponse { token, expires_unix_ms, label })
    }


    pub fn validate_enrollment_token(&self, raw_token: &str, now_ms: u64) -> Result<()> {
        let token_hash = hash_secret(raw_token);
        let connection = self.connection.lock().expect("database mutex poisoned");
        let token = connection
            .query_row(
                "SELECT expires_unix_ms, consumed_unix_ms FROM enrollment_tokens WHERE token_hash = ?1",
                params![token_hash],
                |row| Ok((row.get::<_, i64>(0)?, row.get::<_, Option<i64>>(1)?)),
            )
            .optional()?;
        let Some((expires_ms, consumed_ms)) = token else {
            bail!("invalid enrollment token");
        };
        if consumed_ms.is_some() {
            bail!("enrollment token has already been consumed");
        }
        if expires_ms < now_ms as i64 {
            bail!("enrollment token has expired");
        }
        Ok(())
    }

    pub fn enroll_node(
        &self,
        raw_token: &str,
        record: &NodeRecord,
        raw_node_secret: &str,
        now_ms: u64,
    ) -> Result<()> {
        let token_hash = hash_secret(raw_token);
        let secret_hash = hash_secret(raw_node_secret);
        let mut connection = self.connection.lock().expect("database mutex poisoned");
        let transaction = connection.transaction()?;
        let token = transaction
            .query_row(
                "SELECT expires_unix_ms, consumed_unix_ms FROM enrollment_tokens WHERE token_hash = ?1",
                params![token_hash],
                |row| Ok((row.get::<_, i64>(0)?, row.get::<_, Option<i64>>(1)?)),
            )
            .optional()?;
        let Some((expires_ms, consumed_ms)) = token else {
            bail!("invalid enrollment token");
        };
        if consumed_ms.is_some() {
            bail!("enrollment token has already been consumed");
        }
        if expires_ms < now_ms as i64 {
            bail!("enrollment token has expired");
        }

        transaction.execute(
            "UPDATE enrollment_tokens SET consumed_unix_ms = ?2 WHERE token_hash = ?1 AND consumed_unix_ms IS NULL",
            params![token_hash, now_ms as i64],
        )?;
        transaction.execute(
            "INSERT INTO nodes(id, record_json, secret_hash) VALUES (?1, ?2, ?3)",
            params![record.id.to_string(), serde_json::to_string(record)?, secret_hash],
        )?;
        transaction.commit()?;
        Ok(())
    }

    pub fn authenticate_node(&self, id: NodeId, raw_secret: &str) -> Result<NodeRecord> {
        let connection = self.connection.lock().expect("database mutex poisoned");
        let row = connection
            .query_row(
                "SELECT record_json, secret_hash, previous_secret_hash, previous_secret_expires_unix_ms FROM nodes WHERE id = ?1",
                params![id.to_string()],
                |row| Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, Option<String>>(2)?,
                    row.get::<_, Option<i64>>(3)?,
                )),
            )
            .optional()?;
        let Some((record_json, expected_hash, previous_hash, previous_expires)) = row else {
            bail!("unknown node");
        };
        let candidate = hash_secret(raw_secret);
        let now_ms = crate::unix_ms() as i64;
        let previous_ok = previous_hash.as_deref() == Some(candidate.as_str())
            && previous_expires.is_some_and(|expiry| expiry >= now_ms);
        if expected_hash != candidate && !previous_ok {
            bail!("invalid node credential");
        }
        let record: NodeRecord = serde_json::from_str(&record_json)?;
        if record.revoked_unix_ms.is_some() || record.status == NodeStatus::Revoked {
            bail!("node has been revoked");
        }
        Ok(record)
    }

    pub fn update_connection(
        &self,
        id: NodeId,
        protocol: ProtocolVersion,
        features: Vec<sparkbridge_core::FabricFeature>,
        now_ms: u64,
    ) -> Result<NodeRecord> {
        self.update_node(id, |record| {
            record.protocol = protocol;
            record.features = features;
            record.last_seen_unix_ms = now_ms;
            record.status = NodeStatus::Online;
        })
    }

    pub fn heartbeat(&self, id: NodeId, now_ms: u64) -> Result<NodeRecord> {
        self.update_node(id, |record| {
            record.last_seen_unix_ms = now_ms;
            record.status = NodeStatus::Online;
        })
    }

    pub fn rotate_credentials(
        &self,
        id: NodeId,
        certificate_fingerprint_sha256: String,
        certificate_not_after_unix_ms: u64,
        new_raw_secret: &str,
        presented_raw_secret: &str,
        now_ms: u64,
    ) -> Result<NodeRecord> {
        let new_secret_hash = hash_secret(new_raw_secret);
        let previous_secret_hash = hash_secret(presented_raw_secret);
        let mut connection = self.connection.lock().expect("database mutex poisoned");
        let transaction = connection.transaction()?;
        let record_json: String = transaction.query_row(
            "SELECT record_json FROM nodes WHERE id = ?1",
            params![id.to_string()],
            |row| row.get(0),
        )?;
        let mut record: NodeRecord = serde_json::from_str(&record_json)?;
        if record.revoked_unix_ms.is_some() {
            bail!("node has been revoked");
        }
        record.certificate_fingerprint_sha256 = certificate_fingerprint_sha256;
        record.certificate_not_after_unix_ms = certificate_not_after_unix_ms;
        let previous_expires = now_ms.saturating_add(10 * 60 * 1000);
        transaction.execute(
            "UPDATE nodes SET record_json = ?2, secret_hash = ?3, previous_secret_hash = ?4, previous_secret_expires_unix_ms = ?5 WHERE id = ?1",
            params![
                id.to_string(),
                serde_json::to_string(&record)?,
                new_secret_hash,
                previous_secret_hash,
                previous_expires as i64
            ],
        )?;
        transaction.commit()?;
        Ok(record)
    }

    pub fn revoke_node(&self, id: NodeId, reason: Option<String>, now_ms: u64) -> Result<NodeRecord> {
        let mut record = self.update_node(id, |record| {
            record.status = NodeStatus::Revoked;
            record.revoked_unix_ms = Some(now_ms);
        })?;
        let connection = self.connection.lock().expect("database mutex poisoned");
        connection.execute(
            "UPDATE nodes SET revoke_reason = ?2 WHERE id = ?1",
            params![id.to_string(), reason],
        )?;
        record.status = NodeStatus::Revoked;
        Ok(record)
    }

    pub fn list_nodes(&self, now_ms: u64, stale_seconds: u64, offline_seconds: u64) -> Result<Vec<NodeRecord>> {
        let connection = self.connection.lock().expect("database mutex poisoned");
        let mut statement = connection.prepare("SELECT record_json FROM nodes ORDER BY id")?;
        let mut rows = statement.query([])?;
        let mut records = Vec::new();
        while let Some(row) = rows.next()? {
            let json: String = row.get(0)?;
            let mut record: NodeRecord = serde_json::from_str(&json)?;
            if record.revoked_unix_ms.is_some() {
                record.status = NodeStatus::Revoked;
            } else {
                let age_ms = now_ms.saturating_sub(record.last_seen_unix_ms);
                record.status = if age_ms >= offline_seconds.saturating_mul(1000) {
                    NodeStatus::Offline
                } else if age_ms >= stale_seconds.saturating_mul(1000) {
                    NodeStatus::Stale
                } else {
                    NodeStatus::Online
                };
            }
            records.push(record);
        }
        Ok(records)
    }


    pub fn register_snapshot(&self, request: SnapshotRegistrationRequest) -> Result<SnapshotRecord> {
        let snapshot_id = Uuid::new_v4().to_string();
        let record = SnapshotRecord {
            snapshot_id: snapshot_id.clone(),
            workspace_id: request.workspace_id,
            node_id: request.node_id,
            manifest_digest: request.manifest_digest,
            root_name: request.root_name,
            entry_count: request.entry_count,
            source_generation: request.source_generation,
            git_head: request.git_head,
            created_unix_ms: request.created_unix_ms,
        };
        let connection = self.connection.lock().expect("database mutex poisoned");
        connection.execute(
            "INSERT INTO snapshots(snapshot_id, node_id, workspace_id, manifest_digest, record_json, created_unix_ms) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![&record.snapshot_id, record.node_id.to_string(), &record.workspace_id, &record.manifest_digest, serde_json::to_string(&record)?, record.created_unix_ms as i64],
        )?;
        Ok(record)
    }


    pub fn list_snapshots(&self) -> Result<Vec<SnapshotRecord>> {
        let connection = self.connection.lock().expect("database mutex poisoned");
        let mut statement = connection.prepare("SELECT record_json FROM snapshots ORDER BY created_unix_ms DESC")?;
        let rows = statement.query_map([], |row| row.get::<_, String>(0))?;
        let mut out = Vec::new();
        for row in rows { out.push(serde_json::from_str(&row?)?); }
        Ok(out)
    }

    pub fn list_snapshots_for_node(&self, id: NodeId) -> Result<Vec<SnapshotRecord>> {
        let connection = self.connection.lock().expect("database mutex poisoned");
        let mut statement = connection.prepare("SELECT record_json FROM snapshots WHERE node_id = ?1 ORDER BY created_unix_ms DESC")?;
        let rows = statement.query_map(params![id.to_string()], |row| row.get::<_, String>(0))?;
        let mut out = Vec::new();
        for row in rows { out.push(serde_json::from_str(&row?)?); }
        Ok(out)
    }


    pub fn get_snapshot(&self, snapshot_id: &str) -> Result<SnapshotRecord> {
        let connection = self.connection.lock().expect("database mutex poisoned");
        let json: String = connection.query_row(
            "SELECT record_json FROM snapshots WHERE snapshot_id = ?1",
            params![snapshot_id],
            |row| row.get(0),
        )?;
        Ok(serde_json::from_str(&json)?)
    }

    pub fn register_repository_index(&self, record: &RepositoryIndexRecord) -> Result<()> {
        let connection = self.connection.lock().expect("database mutex poisoned");
        connection.execute(
            "INSERT INTO repository_indexes(snapshot_id, manifest_digest, index_digest, record_json, built_unix_ms) VALUES (?1,?2,?3,?4,?5) ON CONFLICT(snapshot_id) DO UPDATE SET manifest_digest=excluded.manifest_digest,index_digest=excluded.index_digest,record_json=excluded.record_json,built_unix_ms=excluded.built_unix_ms",
            params![&record.snapshot_id,&record.manifest_digest,&record.index_digest,serde_json::to_string(record)?,record.built_unix_ms as i64],
        )?;
        Ok(())
    }

    pub fn get_repository_index(&self, snapshot_id:&str) -> Result<RepositoryIndexRecord> {
        let connection=self.connection.lock().expect("database mutex poisoned");
        let json:String=connection.query_row("SELECT record_json FROM repository_indexes WHERE snapshot_id=?1",params![snapshot_id],|row|row.get(0))?;
        Ok(serde_json::from_str(&json)?)
    }

    pub fn list_repository_indexes(&self)->Result<Vec<RepositoryIndexRecord>>{
        let connection=self.connection.lock().expect("database mutex poisoned");
        let mut statement=connection.prepare("SELECT record_json FROM repository_indexes ORDER BY built_unix_ms DESC")?;
        let rows=statement.query_map([],|row|row.get::<_,String>(0))?; let mut out=Vec::new(); for row in rows{out.push(serde_json::from_str(&row?)?);} Ok(out)
    }

    pub fn register_native_intelligence(&self, record:&NativeIntelligenceRecord)->Result<()> {
        let connection=self.connection.lock().expect("database mutex poisoned");
        connection.execute(
            "INSERT INTO native_intelligence(snapshot_id,node_id,report_digest,record_json,created_unix_ms) VALUES (?1,?2,?3,?4,?5) ON CONFLICT(snapshot_id) DO UPDATE SET node_id=excluded.node_id,report_digest=excluded.report_digest,record_json=excluded.record_json,created_unix_ms=excluded.created_unix_ms",
            params![&record.snapshot_id,&record.node_id,&record.report_digest,serde_json::to_string(record)?,record.created_unix_ms as i64],
        )?; Ok(())
    }

    pub fn get_native_intelligence(&self,snapshot_id:&str)->Result<NativeIntelligenceRecord>{
        let connection=self.connection.lock().expect("database mutex poisoned");
        let json:String=connection.query_row("SELECT record_json FROM native_intelligence WHERE snapshot_id=?1",params![snapshot_id],|row|row.get(0))?;
        Ok(serde_json::from_str(&json)?)
    }

    pub fn register_candidate(&self, record: &CandidateRecord) -> Result<()> {
        let connection = self.connection.lock().expect("database mutex poisoned");
        connection.execute(
            "INSERT INTO candidates(candidate_id, node_id, workspace_id, base_snapshot_id, manifest_digest, record_json, created_unix_ms) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![&record.candidate_id, record.node_id.to_string(), &record.workspace_id, &record.base_snapshot_id, &record.manifest_digest, serde_json::to_string(record)?, record.created_unix_ms as i64],
        )?;
        Ok(())
    }

    pub fn get_candidate(&self, candidate_id: &str) -> Result<CandidateRecord> {
        let connection = self.connection.lock().expect("database mutex poisoned");
        let json: String = connection.query_row(
            "SELECT record_json FROM candidates WHERE candidate_id = ?1",
            params![candidate_id],
            |row| row.get(0),
        )?;
        Ok(serde_json::from_str(&json)?)
    }

    pub fn list_candidates(&self) -> Result<Vec<CandidateRecord>> {
        let connection = self.connection.lock().expect("database mutex poisoned");
        let mut statement = connection.prepare("SELECT record_json FROM candidates ORDER BY created_unix_ms DESC")?;
        let rows = statement.query_map([], |row| row.get::<_, String>(0))?;
        let mut out = Vec::new();
        for row in rows { out.push(serde_json::from_str(&row?)?); }
        Ok(out)
    }

    pub fn register_promotion(&self, request: PromotionReportRequest) -> Result<PromotionRecord> {
        let record = PromotionRecord {
            promotion_id: Uuid::new_v4().to_string(),
            candidate_id: request.candidate_id,
            workspace_id: request.workspace_id,
            node_id: request.node_id,
            outcome: request.outcome,
            base_manifest_digest: request.base_manifest_digest,
            observed_before_manifest_digest: request.observed_before_manifest_digest,
            result_manifest_digest: request.result_manifest_digest,
            generation_before: request.generation_before,
            generation_after: request.generation_after,
            merged_files: request.merged_files,
            conflicts: request.conflicts,
            created_unix_ms: request.created_unix_ms,
        };
        let outcome = match record.outcome {
            PromotionOutcome::Applied => "applied",
            PromotionOutcome::Conflict => "conflict",
            PromotionOutcome::DryRun => "dry_run",
            PromotionOutcome::Failed => "failed",
        };
        let connection = self.connection.lock().expect("database mutex poisoned");
        connection.execute(
            "INSERT INTO promotions(promotion_id, candidate_id, node_id, workspace_id, outcome, record_json, created_unix_ms) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![&record.promotion_id, &record.candidate_id, record.node_id.to_string(), &record.workspace_id, outcome, serde_json::to_string(&record)?, record.created_unix_ms as i64],
        )?;
        Ok(record)
    }

    pub fn list_promotions(&self) -> Result<Vec<PromotionRecord>> {
        let connection = self.connection.lock().expect("database mutex poisoned");
        let mut statement = connection.prepare("SELECT record_json FROM promotions ORDER BY created_unix_ms DESC")?;
        let rows = statement.query_map([], |row| row.get::<_, String>(0))?;
        let mut out = Vec::new();
        for row in rows { out.push(serde_json::from_str(&row?)?); }
        Ok(out)
    }


    pub fn upsert_capabilities(&self, report: &CapabilityReport) -> Result<()> {
        let connection = self.connection.lock().expect("database mutex poisoned");
        connection.execute(
            "INSERT INTO node_capabilities(node_id, report_json, reported_unix_ms) VALUES (?1, ?2, ?3) \
             ON CONFLICT(node_id) DO UPDATE SET report_json = excluded.report_json, reported_unix_ms = excluded.reported_unix_ms",
            params![report.node_id.to_string(), serde_json::to_string(report)?, report.reported_unix_ms as i64],
        )?;
        Ok(())
    }

    pub fn list_capability_reports(&self) -> Result<Vec<CapabilityReport>> {
        let connection = self.connection.lock().expect("database mutex poisoned");
        let mut statement = connection.prepare("SELECT report_json FROM node_capabilities ORDER BY node_id")?;
        let rows = statement.query_map([], |row| row.get::<_, String>(0))?;
        let mut out = Vec::new();
        for row in rows { out.push(serde_json::from_str(&row?)?); }
        Ok(out)
    }

    // Persistence writes mirror the stored column set exactly, which is why the parameter
    // count is high; bundling them would obscure which column each argument feeds.
    #[allow(clippy::too_many_arguments)]
    pub fn create_action(
        &self,
        assigned_node_id: NodeId,
        spec: sparkbridge_protocol::ActionSpec,
        now_ms: u64,
        status: ActionStatus,
        policy_decision: PolicyDecision,
        approval_reason: Option<String>,
        approval_ttl_seconds: u64,
        cache_key: Option<String>,
        toolchain_digest: Option<String>,
        cache_source_action_id: Option<String>,
        cached_result: Option<ActionExecutionResult>,
    ) -> Result<ActionRecord> {
        let action_id = Uuid::new_v4().to_string();
        let approval = if status == ActionStatus::AwaitingApproval {
            Some(ApprovalRecord {
                approval_id: Uuid::new_v4().to_string(),
                principal_id: spec.principal_id.clone(),
                workspace_id: spec.workspace_id.clone(),
                operation: format!("action:{:?}", spec.side_effect),
                action_id: Some(action_id.clone()),
                reason: approval_reason.unwrap_or_else(|| "policy requires explicit approval".into()),
                status: ApprovalStatus::Pending,
                created_unix_ms: now_ms,
                expires_unix_ms: now_ms.saturating_add(approval_ttl_seconds.saturating_mul(1000)),
                decided_unix_ms: None,
                decided_by: None,
            })
        } else { None };
        let cache_hit = cached_result.is_some();
        let effective_status = if cache_hit { ActionStatus::Succeeded } else { status };
        let record = ActionRecord {
            action_id: action_id.clone(),
            assigned_node_id,
            spec,
            status: effective_status,
            policy_decision,
            approval_id: approval.as_ref().map(|record| record.approval_id.clone()),
            cache_key,
            toolchain_digest,
            cache_hit,
            cache_source_action_id,
            cancel_requested: false,
            lease_id: None,
            lease_expires_unix_ms: None,
            created_unix_ms: now_ms,
            started_unix_ms: cache_hit.then_some(now_ms),
            completed_unix_ms: cache_hit.then_some(now_ms),
            result: cached_result,
        };
        let mut connection = self.connection.lock().expect("database mutex poisoned");
        let transaction = connection.transaction()?;
        transaction.execute(
            "INSERT INTO actions(action_id, assigned_node_id, status, record_json, created_unix_ms, started_unix_ms, completed_unix_ms, cancel_requested) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 0)",
            params![&record.action_id, assigned_node_id.to_string(), action_status_str(record.status), serde_json::to_string(&record)?, now_ms as i64, record.started_unix_ms.map(|v| v as i64), record.completed_unix_ms.map(|v| v as i64)],
        )?;
        if let Some(approval) = &approval {
            transaction.execute(
                "INSERT INTO approvals(approval_id, status, action_id, record_json, created_unix_ms, expires_unix_ms) VALUES (?1,'pending',?2,?3,?4,?5)",
                params![&approval.approval_id, &approval.action_id, serde_json::to_string(approval)?, now_ms as i64, approval.expires_unix_ms as i64],
            )?;
        }
        transaction.commit()?;
        Ok(record)
    }

    pub fn list_actions(&self) -> Result<Vec<ActionRecord>> {
        let connection = self.connection.lock().expect("database mutex poisoned");
        let mut statement = connection.prepare("SELECT record_json FROM actions ORDER BY created_unix_ms DESC")?;
        let rows = statement.query_map([], |row| row.get::<_, String>(0))?;
        let mut out = Vec::new();
        for row in rows { out.push(serde_json::from_str(&row?)?); }
        Ok(out)
    }

    pub fn get_action(&self, action_id: &str) -> Result<ActionRecord> {
        let connection = self.connection.lock().expect("database mutex poisoned");
        let json: String = connection.query_row(
            "SELECT record_json FROM actions WHERE action_id = ?1",
            params![action_id], |row| row.get(0),
        )?;
        Ok(serde_json::from_str(&json)?)
    }

    pub fn reap_expired_action_leases(&self, now_ms: u64) -> Result<u64> {
        let mut connection = self.connection.lock().expect("database mutex poisoned");
        let transaction = connection.transaction()?;
        let mut statement = transaction.prepare(
            "SELECT action_id, record_json FROM actions WHERE lease_expires_unix_ms IS NOT NULL AND lease_expires_unix_ms < ?1 AND status IN ('leased','running')"
        )?;
        let rows = statement.query_map(params![now_ms as i64], |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)))?;
        let mut expired = Vec::new();
        for row in rows { expired.push(row?); }
        drop(statement);
        let count = expired.len() as u64;
        for (action_id, json) in expired {
            let mut record: ActionRecord = serde_json::from_str(&json)?;
            if record.spec.side_effect == ActionSideEffect::Pure {
                record.status = ActionStatus::Queued;
            } else {
                record.status = ActionStatus::Lost;
                record.completed_unix_ms = Some(now_ms);
            }
            record.lease_id = None;
            record.lease_expires_unix_ms = None;
            let status = action_status_str(record.status);
            transaction.execute(
                "UPDATE actions SET status = ?2, record_json = ?3, lease_id = NULL, lease_expires_unix_ms = NULL WHERE action_id = ?1",
                params![action_id, status, serde_json::to_string(&record)?],
            )?;
        }
        transaction.commit()?;
        Ok(count)
    }

    pub fn lease_next_action(&self, node_id: NodeId, now_ms: u64, lease_ms: u64) -> Result<Option<ActionLease>> {
        self.expire_approvals(now_ms)?;
        self.reap_expired_action_leases(now_ms)?;
        let mut connection = self.connection.lock().expect("database mutex poisoned");
        let transaction = connection.transaction()?;
        let active: i64 = transaction.query_row(
            "SELECT COUNT(*) FROM actions WHERE assigned_node_id = ?1 AND status IN ('leased','running')",
            params![node_id.to_string()], |row| row.get(0),
        )?;
        if active > 0 { transaction.commit()?; return Ok(None); }
        let row = transaction.query_row(
            "SELECT action_id, record_json FROM actions WHERE assigned_node_id = ?1 AND status = 'queued' AND cancel_requested = 0 ORDER BY created_unix_ms ASC LIMIT 1",
            params![node_id.to_string()],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
        ).optional()?;
        let Some((action_id, json)) = row else { transaction.commit()?; return Ok(None); };
        let mut record: ActionRecord = serde_json::from_str(&json)?;
        let lease_id = Uuid::new_v4().to_string();
        let expires = now_ms.saturating_add(lease_ms);
        record.status = ActionStatus::Leased;
        record.lease_id = Some(lease_id.clone());
        record.lease_expires_unix_ms = Some(expires);
        transaction.execute(
            "UPDATE actions SET status='leased', record_json=?2, lease_id=?3, lease_expires_unix_ms=?4 WHERE action_id=?1 AND status='queued'",
            params![action_id, serde_json::to_string(&record)?, lease_id, expires as i64],
        )?;
        transaction.commit()?;
        Ok(Some(ActionLease { action: record, lease_id, lease_expires_unix_ms: expires }))
    }

    pub fn renew_action_lease(&self, action_id: &str, lease_id: &str, now_ms: u64, lease_ms: u64) -> Result<(u64, bool)> {
        let mut record = self.get_action(action_id)?;
        if record.lease_id.as_deref() != Some(lease_id) { bail!("action lease does not match"); }
        if matches!(record.status, ActionStatus::Succeeded | ActionStatus::Failed | ActionStatus::Cancelled | ActionStatus::TimedOut | ActionStatus::Lost) {
            bail!("action is already terminal");
        }
        let expires = now_ms.saturating_add(lease_ms);
        record.lease_expires_unix_ms = Some(expires);
        let connection = self.connection.lock().expect("database mutex poisoned");
        connection.execute(
            "UPDATE actions SET record_json=?2, lease_expires_unix_ms=?3 WHERE action_id=?1 AND lease_id=?4",
            params![action_id, serde_json::to_string(&record)?, expires as i64, lease_id],
        )?;
        Ok((expires, record.cancel_requested))
    }

    pub fn start_action(&self, action_id: &str, lease_id: &str, started_ms: u64) -> Result<ActionRecord> {
        let mut record = self.get_action(action_id)?;
        if record.lease_id.as_deref() != Some(lease_id) { bail!("action lease does not match"); }
        if record.status != ActionStatus::Leased { bail!("action is not in leased state"); }
        if record.cancel_requested { bail!("action was cancelled before start"); }
        record.status = ActionStatus::Running;
        record.started_unix_ms = Some(started_ms);
        let connection = self.connection.lock().expect("database mutex poisoned");
        connection.execute(
            "UPDATE actions SET status='running', record_json=?2, started_unix_ms=?3 WHERE action_id=?1 AND lease_id=?4",
            params![action_id, serde_json::to_string(&record)?, started_ms as i64, lease_id],
        )?;
        Ok(record)
    }

    pub fn complete_action(&self, action_id: &str, request: ActionCompletionRequest) -> Result<ActionRecord> {
        let mut record = self.get_action(action_id)?;
        if record.lease_id.as_deref() != Some(request.lease_id.as_str()) {
            if record.completed_unix_ms.is_some() { return Ok(record); }
            bail!("action lease does not match");
        }
        record.completed_unix_ms = Some(request.completed_unix_ms);
        record.result = Some(request.result.clone());
        record.status = if request.result.cancelled || record.cancel_requested {
            ActionStatus::Cancelled
        } else if request.result.timed_out {
            ActionStatus::TimedOut
        } else if request.result.exit_code == Some(0) {
            ActionStatus::Succeeded
        } else {
            ActionStatus::Failed
        };
        record.lease_id = None;
        record.lease_expires_unix_ms = None;
        let connection = self.connection.lock().expect("database mutex poisoned");
        connection.execute(
            "UPDATE actions SET status=?2, record_json=?3, completed_unix_ms=?4, lease_id=NULL, lease_expires_unix_ms=NULL WHERE action_id=?1",
            params![action_id, action_status_str(record.status), serde_json::to_string(&record)?, request.completed_unix_ms as i64],
        )?;
        Ok(record)
    }

    pub fn cancel_action(&self, action_id: &str, now_ms: u64) -> Result<ActionRecord> {
        let mut record = self.get_action(action_id)?;
        if matches!(record.status, ActionStatus::Succeeded | ActionStatus::Failed | ActionStatus::Cancelled | ActionStatus::TimedOut | ActionStatus::Lost) {
            return Ok(record);
        }
        record.cancel_requested = true;
        if matches!(record.status, ActionStatus::Queued | ActionStatus::AwaitingApproval) {
            record.status = ActionStatus::Cancelled;
            record.completed_unix_ms = Some(now_ms);
        }
        let connection = self.connection.lock().expect("database mutex poisoned");
        connection.execute(
            "UPDATE actions SET status=?2, cancel_requested=1, record_json=?3, completed_unix_ms=?4 WHERE action_id=?1",
            params![action_id, action_status_str(record.status), serde_json::to_string(&record)?, record.completed_unix_ms.map(|v| v as i64)],
        )?;
        Ok(record)
    }


    pub fn get_action_cache(&self, cache_key: &str) -> Result<Option<ActionCacheRecord>> {
        let connection = self.connection.lock().expect("database mutex poisoned");
        let json = connection.query_row(
            "SELECT record_json FROM action_cache WHERE cache_key=?1", params![cache_key], |row| row.get::<_, String>(0)
        ).optional()?;
        json.map(|value| serde_json::from_str(&value).map_err(Into::into)).transpose()
    }

    pub fn put_action_cache(&self, mut record: ActionCacheRecord) -> Result<ActionCacheRecord> {
        let mut connection = self.connection.lock().expect("database mutex poisoned");
        let transaction = connection.transaction()?;
        let previous = transaction.query_row(
            "SELECT record_json FROM action_cache WHERE cache_key=?1", params![&record.cache_key], |row| row.get::<_, String>(0)
        ).optional()?;
        if let Some(json) = previous {
            let old: ActionCacheRecord = serde_json::from_str(&json)?;
            record.hit_count = old.hit_count;
        }
        transaction.execute(
            "INSERT INTO action_cache(cache_key, trust, workspace_id, candidate_id, toolchain_digest, record_json, created_unix_ms, last_used_unix_ms, hit_count) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9) ON CONFLICT(cache_key) DO UPDATE SET trust=excluded.trust, workspace_id=excluded.workspace_id, candidate_id=excluded.candidate_id, toolchain_digest=excluded.toolchain_digest, record_json=excluded.record_json, last_used_unix_ms=excluded.last_used_unix_ms",
            params![&record.cache_key, cache_trust_str(record.trust), &record.workspace_id, &record.candidate_id, &record.toolchain_digest, serde_json::to_string(&record)?, record.created_unix_ms as i64, record.last_used_unix_ms as i64, record.hit_count as i64],
        )?;
        transaction.commit()?;
        Ok(record)
    }

    pub fn touch_action_cache(&self, cache_key: &str, now_ms: u64) -> Result<ActionCacheRecord> {
        let mut record = self.get_action_cache(cache_key)?.ok_or_else(|| anyhow::anyhow!("cache entry not found"))?;
        record.last_used_unix_ms = now_ms;
        record.hit_count = record.hit_count.saturating_add(1);
        let connection = self.connection.lock().expect("database mutex poisoned");
        connection.execute(
            "UPDATE action_cache SET record_json=?2,last_used_unix_ms=?3,hit_count=?4 WHERE cache_key=?1",
            params![cache_key, serde_json::to_string(&record)?, now_ms as i64, record.hit_count as i64],
        )?;
        Ok(record)
    }

    pub fn list_action_cache(&self) -> Result<Vec<ActionCacheRecord>> {
        let connection = self.connection.lock().expect("database mutex poisoned");
        let mut statement = connection.prepare("SELECT record_json FROM action_cache ORDER BY last_used_unix_ms DESC")?;
        let rows = statement.query_map([], |row| row.get::<_, String>(0))?;
        let mut out = Vec::new();
        for row in rows { out.push(serde_json::from_str(&row?)?); }
        Ok(out)
    }

    pub fn prune_action_cache(&self, max_entries: usize) -> Result<u64> {
        let connection = self.connection.lock().expect("database mutex poisoned");
        let count: i64=connection.query_row("SELECT COUNT(*) FROM action_cache",[],|row|row.get(0))?;
        let excess=(count.max(0) as usize).saturating_sub(max_entries);
        if excess==0{return Ok(0);}
        let deleted=connection.execute("DELETE FROM action_cache WHERE cache_key IN (SELECT cache_key FROM action_cache ORDER BY last_used_unix_ms ASC LIMIT ?1)",params![excess as i64])?;
        Ok(deleted as u64)
    }

    pub fn save_validation_run(&self, record: &ValidationRunRecord) -> Result<ValidationRunRecord> {
        let connection = self.connection.lock().expect("database mutex poisoned");
        connection.execute(
            "INSERT INTO validation_runs(validation_id,candidate_id,workspace_id,status,record_json,created_unix_ms,completed_unix_ms) VALUES (?1,?2,?3,?4,?5,?6,?7) ON CONFLICT(validation_id) DO UPDATE SET status=excluded.status,record_json=excluded.record_json,completed_unix_ms=excluded.completed_unix_ms",
            params![&record.validation_id,&record.candidate_id,&record.workspace_id,validation_status_str(record.status),serde_json::to_string(record)?,record.created_unix_ms as i64,record.completed_unix_ms.map(|v| v as i64)],
        )?;
        Ok(record.clone())
    }

    pub fn get_validation_run(&self, validation_id: &str) -> Result<ValidationRunRecord> {
        let connection = self.connection.lock().expect("database mutex poisoned");
        let json: String = connection.query_row("SELECT record_json FROM validation_runs WHERE validation_id=?1",params![validation_id],|row|row.get(0))?;
        Ok(serde_json::from_str(&json)?)
    }

    pub fn list_validation_runs(&self) -> Result<Vec<ValidationRunRecord>> {
        let connection = self.connection.lock().expect("database mutex poisoned");
        let mut statement = connection.prepare("SELECT record_json FROM validation_runs ORDER BY created_unix_ms DESC")?;
        let rows = statement.query_map([],|row|row.get::<_,String>(0))?;
        let mut out=Vec::new(); for row in rows { out.push(serde_json::from_str(&row?)?); } Ok(out)
    }

    pub fn upsert_principal(&self, record: &PrincipalRecord) -> Result<PrincipalRecord> {
        let connection = self.connection.lock().expect("database mutex poisoned");
        connection.execute(
            "INSERT INTO principals(principal_id, record_json, updated_unix_ms) VALUES (?1,?2,?3) ON CONFLICT(principal_id) DO UPDATE SET record_json=excluded.record_json, updated_unix_ms=excluded.updated_unix_ms",
            params![&record.principal_id, serde_json::to_string(record)?, crate::unix_ms() as i64],
        )?;
        Ok(record.clone())
    }

    pub fn get_principal(&self, principal_id: &str) -> Result<PrincipalRecord> {
        let connection = self.connection.lock().expect("database mutex poisoned");
        let json: String = connection.query_row("SELECT record_json FROM principals WHERE principal_id=?1", params![principal_id], |row| row.get(0))?;
        Ok(serde_json::from_str(&json)?)
    }

    pub fn list_principals(&self) -> Result<Vec<PrincipalRecord>> {
        let connection = self.connection.lock().expect("database mutex poisoned");
        let mut statement = connection.prepare("SELECT record_json FROM principals ORDER BY principal_id")?;
        let rows = statement.query_map([], |row| row.get::<_, String>(0))?;
        let mut out = Vec::new();
        for row in rows { out.push(serde_json::from_str(&row?)?); }
        Ok(out)
    }

    pub fn upsert_workspace_policy(&self, record: &WorkspacePolicyRecord) -> Result<WorkspacePolicyRecord> {
        let connection = self.connection.lock().expect("database mutex poisoned");
        connection.execute(
            "INSERT INTO workspace_policies(workspace_id, record_json, updated_unix_ms) VALUES (?1,?2,?3) ON CONFLICT(workspace_id) DO UPDATE SET record_json=excluded.record_json, updated_unix_ms=excluded.updated_unix_ms",
            params![&record.workspace_id, serde_json::to_string(record)?, record.updated_unix_ms as i64],
        )?;
        Ok(record.clone())
    }

    pub fn get_workspace_policy(&self, workspace_id: &str) -> Result<Option<WorkspacePolicyRecord>> {
        let connection = self.connection.lock().expect("database mutex poisoned");
        let json = connection.query_row("SELECT record_json FROM workspace_policies WHERE workspace_id=?1", params![workspace_id], |row| row.get::<_, String>(0)).optional()?;
        json.map(|value| serde_json::from_str(&value).map_err(Into::into)).transpose()
    }

    pub fn list_workspace_policies(&self) -> Result<Vec<WorkspacePolicyRecord>> {
        let connection = self.connection.lock().expect("database mutex poisoned");
        let mut statement = connection.prepare("SELECT record_json FROM workspace_policies ORDER BY workspace_id")?;
        let rows = statement.query_map([], |row| row.get::<_, String>(0))?;
        let mut out = Vec::new();
        for row in rows { out.push(serde_json::from_str(&row?)?); }
        Ok(out)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn create_approval(
        &self,
        principal_id: String,
        workspace_id: String,
        operation: String,
        action_id: Option<String>,
        reason: String,
        now_ms: u64,
        ttl_seconds: u64,
    ) -> Result<ApprovalRecord> {
        let record = ApprovalRecord {
            approval_id: Uuid::new_v4().to_string(),
            principal_id,
            workspace_id,
            operation,
            action_id,
            reason,
            status: ApprovalStatus::Pending,
            created_unix_ms: now_ms,
            expires_unix_ms: now_ms.saturating_add(ttl_seconds.saturating_mul(1000)),
            decided_unix_ms: None,
            decided_by: None,
        };
        let connection = self.connection.lock().expect("database mutex poisoned");
        connection.execute(
            "INSERT INTO approvals(approval_id, status, action_id, record_json, created_unix_ms, expires_unix_ms) VALUES (?1,'pending',?2,?3,?4,?5)",
            params![&record.approval_id, &record.action_id, serde_json::to_string(&record)?, now_ms as i64, record.expires_unix_ms as i64],
        )?;
        Ok(record)
    }

    pub fn get_approval(&self, approval_id: &str) -> Result<ApprovalRecord> {
        let connection = self.connection.lock().expect("database mutex poisoned");
        let json: String = connection.query_row("SELECT record_json FROM approvals WHERE approval_id=?1", params![approval_id], |row| row.get(0))?;
        Ok(serde_json::from_str(&json)?)
    }

    pub fn list_approvals(&self, now_ms: u64) -> Result<Vec<ApprovalRecord>> {
        self.expire_approvals(now_ms)?;
        let connection = self.connection.lock().expect("database mutex poisoned");
        let mut statement = connection.prepare("SELECT record_json FROM approvals ORDER BY created_unix_ms DESC")?;
        let rows = statement.query_map([], |row| row.get::<_, String>(0))?;
        let mut out = Vec::new();
        for row in rows { out.push(serde_json::from_str(&row?)?); }
        Ok(out)
    }

    pub fn decide_approval(&self, approval_id: &str, approve: bool, decided_by: String, now_ms: u64) -> Result<ApprovalRecord> {
        let mut connection = self.connection.lock().expect("database mutex poisoned");
        let transaction = connection.transaction()?;
        let json: String = transaction.query_row("SELECT record_json FROM approvals WHERE approval_id=?1", params![approval_id], |row| row.get(0))?;
        let mut record: ApprovalRecord = serde_json::from_str(&json)?;
        if record.status != ApprovalStatus::Pending { bail!("approval is no longer pending"); }
        if record.expires_unix_ms < now_ms { bail!("approval has expired"); }
        record.status = if approve { ApprovalStatus::Approved } else { ApprovalStatus::Denied };
        record.decided_unix_ms = Some(now_ms);
        record.decided_by = Some(decided_by);
        transaction.execute(
            "UPDATE approvals SET status=?2, record_json=?3 WHERE approval_id=?1",
            params![approval_id, if approve { "approved" } else { "denied" }, serde_json::to_string(&record)?],
        )?;
        if let Some(action_id) = &record.action_id {
            let action_json: String = transaction.query_row("SELECT record_json FROM actions WHERE action_id=?1", params![action_id], |row| row.get(0))?;
            let mut action: ActionRecord = serde_json::from_str(&action_json)?;
            if action.status == ActionStatus::AwaitingApproval {
                if approve {
                    action.status = ActionStatus::Queued;
                    action.policy_decision = PolicyDecision::Allow;
                } else {
                    action.status = ActionStatus::Cancelled;
                    action.cancel_requested = true;
                    action.completed_unix_ms = Some(now_ms);
                }
                transaction.execute(
                    "UPDATE actions SET status=?2, record_json=?3, cancel_requested=?4, completed_unix_ms=?5 WHERE action_id=?1",
                    params![action_id, action_status_str(action.status), serde_json::to_string(&action)?, if action.cancel_requested {1} else {0}, action.completed_unix_ms.map(|v| v as i64)],
                )?;
            }
        }
        transaction.commit()?;
        Ok(record)
    }

    pub fn expire_approvals(&self, now_ms: u64) -> Result<u64> {
        let mut connection = self.connection.lock().expect("database mutex poisoned");
        let transaction = connection.transaction()?;
        let mut statement = transaction.prepare("SELECT approval_id, record_json FROM approvals WHERE status='pending' AND expires_unix_ms < ?1")?;
        let rows = statement.query_map(params![now_ms as i64], |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)))?;
        let mut expired = Vec::new();
        for row in rows { expired.push(row?); }
        drop(statement);
        for (approval_id, json) in &expired {
            let mut record: ApprovalRecord = serde_json::from_str(json)?;
            record.status = ApprovalStatus::Expired;
            transaction.execute("UPDATE approvals SET status='expired', record_json=?2 WHERE approval_id=?1", params![approval_id, serde_json::to_string(&record)?])?;
            if let Some(action_id) = &record.action_id {
                if let Ok(action_json) = transaction.query_row("SELECT record_json FROM actions WHERE action_id=?1", params![action_id], |row| row.get::<_, String>(0)) {
                    let mut action: ActionRecord = serde_json::from_str(&action_json)?;
                    if action.status == ActionStatus::AwaitingApproval {
                        action.status = ActionStatus::Cancelled;
                        action.cancel_requested = true;
                        action.completed_unix_ms = Some(now_ms);
                        transaction.execute("UPDATE actions SET status='cancelled', record_json=?2, cancel_requested=1, completed_unix_ms=?3 WHERE action_id=?1", params![action_id, serde_json::to_string(&action)?, now_ms as i64])?;
                    }
                }
            }
        }
        transaction.commit()?;
        Ok(expired.len() as u64)
    }

    pub fn append_audit(
        &self,
        kind: impl Into<String>,
        principal_id: Option<String>,
        resource: Option<String>,
        payload: serde_json::Value,
        now_ms: u64,
    ) -> Result<AuditRecord> {
        let mut connection = self.connection.lock().expect("database mutex poisoned");
        let transaction = connection.transaction()?;
        let previous: Option<(i64, String)> = transaction.query_row(
            "SELECT sequence, event_hash FROM audit_events ORDER BY sequence DESC LIMIT 1", [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        ).optional()?;
        let sequence = previous.as_ref().map(|(seq, _)| (*seq as u64).saturating_add(1)).unwrap_or(1);
        let previous_hash = previous.map(|(_, hash)| hash).unwrap_or_else(|| "GENESIS".into());
        let envelope = AuditEnvelope {
            sequence,
            event_id: new_event_id(),
            previous_hash: previous_hash.clone(),
            kind: kind.into(),
            principal_id: principal_id.clone(),
            resource: resource.clone(),
            created_unix_ms: now_ms,
            payload: payload.clone(),
        };
        let event_hash = hash_envelope(&envelope);
        let record = AuditRecord { sequence, event_id: envelope.event_id, previous_hash, event_hash: event_hash.clone(), kind: envelope.kind, principal_id, resource, created_unix_ms: now_ms, payload };
        transaction.execute(
            "INSERT INTO audit_events(sequence,event_id,previous_hash,event_hash,event_json,created_unix_ms) VALUES (?1,?2,?3,?4,?5,?6)",
            params![sequence as i64, &record.event_id, &record.previous_hash, &record.event_hash, serde_json::to_string(&record)?, now_ms as i64],
        )?;
        transaction.commit()?;
        Ok(record)
    }

    pub fn list_audit(&self, limit: usize) -> Result<Vec<AuditRecord>> {
        let connection = self.connection.lock().expect("database mutex poisoned");
        let mut statement = connection.prepare("SELECT event_json FROM audit_events ORDER BY sequence DESC LIMIT ?1")?;
        let rows = statement.query_map(params![limit.clamp(1, 10_000) as i64], |row| row.get::<_, String>(0))?;
        let mut out = Vec::new();
        for row in rows { out.push(serde_json::from_str(&row?)?); }
        out.reverse();
        Ok(out)
    }

    pub fn verify_audit(&self) -> Result<AuditVerifyResponse> {
        let connection = self.connection.lock().expect("database mutex poisoned");
        let mut statement = connection.prepare("SELECT event_json FROM audit_events ORDER BY sequence ASC")?;
        let rows = statement.query_map([], |row| row.get::<_, String>(0))?;
        let mut expected_previous = "GENESIS".to_string();
        let mut checked = 0u64;
        for row in rows {
            let record: AuditRecord = serde_json::from_str(&row?)?;
            checked = checked.saturating_add(1);
            if record.previous_hash != expected_previous {
                return Ok(AuditVerifyResponse { valid: false, records_checked: checked, first_invalid_sequence: Some(record.sequence) });
            }
            let envelope = AuditEnvelope {
                sequence: record.sequence, event_id: record.event_id.clone(), previous_hash: record.previous_hash.clone(), kind: record.kind.clone(),
                principal_id: record.principal_id.clone(), resource: record.resource.clone(), created_unix_ms: record.created_unix_ms, payload: record.payload.clone(),
            };
            if hash_envelope(&envelope) != record.event_hash {
                return Ok(AuditVerifyResponse { valid: false, records_checked: checked, first_invalid_sequence: Some(record.sequence) });
            }
            expected_previous = record.event_hash;
        }
        Ok(AuditVerifyResponse { valid: true, records_checked: checked, first_invalid_sequence: None })
    }

    pub fn create_task(&self, record: &TaskRecord, now_ms: u64) -> Result<TaskRecord> {
        let mut connection = self.connection.lock().expect("database mutex poisoned");
        let transaction = connection.transaction()?;
        transaction.execute(
            "INSERT INTO tasks(task_id, status, record_json, created_unix_ms, updated_unix_ms) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![record.task_id, task_status_str(record.status), serde_json::to_string(record)?, record.created_unix_ms as i64, now_ms as i64],
        )?;
        insert_task_event(&transaction, &record.task_id, 1, TaskEventKind::TaskCreated, serde_json::json!({"data":{"spec": &record.spec},"projection":record}), now_ms)?;
        transaction.commit()?;
        Ok(record.clone())
    }

    pub fn get_task(&self, task_id: &str) -> Result<TaskRecord> {
        let connection = self.connection.lock().expect("database mutex poisoned");
        let json: String = connection.query_row("SELECT record_json FROM tasks WHERE task_id=?1", params![task_id], |row| row.get(0))?;
        Ok(serde_json::from_str(&json)?)
    }

    pub fn list_tasks(&self) -> Result<Vec<TaskRecord>> {
        let connection = self.connection.lock().expect("database mutex poisoned");
        let mut statement = connection.prepare("SELECT record_json FROM tasks ORDER BY created_unix_ms DESC")?;
        let rows = statement.query_map([], |row| row.get::<_, String>(0))?;
        let mut out = Vec::new();
        for row in rows { out.push(serde_json::from_str(&row?)?); }
        Ok(out)
    }

    pub fn save_task_event(&self, record: &TaskRecord, kind: TaskEventKind, payload: serde_json::Value, now_ms: u64) -> Result<TaskEvent> {
        let mut connection = self.connection.lock().expect("database mutex poisoned");
        let transaction = connection.transaction()?;
        let sequence: u64 = transaction.query_row(
            "SELECT COALESCE(MAX(sequence),0)+1 FROM task_events WHERE task_id=?1", params![record.task_id], |row| row.get::<_, i64>(0)
        )?.max(1) as u64;
        transaction.execute(
            "UPDATE tasks SET status=?2, record_json=?3, updated_unix_ms=?4 WHERE task_id=?1",
            params![record.task_id, task_status_str(record.status), serde_json::to_string(record)?, now_ms as i64],
        )?;
        let event_payload = serde_json::json!({"data": payload, "projection": record});
        let event = insert_task_event(&transaction, &record.task_id, sequence, kind, event_payload, now_ms)?;
        transaction.commit()?;
        Ok(event)
    }

    pub fn replay_task_projection(&self, task_id: &str) -> Result<TaskRecord> {
        let connection = self.connection.lock().expect("database mutex poisoned");
        let json: String = connection.query_row(
            "SELECT event_json FROM task_events WHERE task_id=?1 ORDER BY sequence DESC LIMIT 1",
            params![task_id], |row| row.get(0),
        )?;
        let event: TaskEvent = serde_json::from_str(&json)?;
        let projection = event.payload.get("projection").ok_or_else(|| anyhow::anyhow!("task event has no projection"))?;
        Ok(serde_json::from_value(projection.clone())?)
    }

    pub fn list_task_events(&self, task_id: &str) -> Result<Vec<TaskEvent>> {
        let connection = self.connection.lock().expect("database mutex poisoned");
        let mut statement = connection.prepare("SELECT event_json FROM task_events WHERE task_id=?1 ORDER BY sequence ASC")?;
        let rows = statement.query_map(params![task_id], |row| row.get::<_, String>(0))?;
        let mut out = Vec::new();
        for row in rows { out.push(serde_json::from_str(&row?)?); }
        Ok(out)
    }

    pub fn recover_tasks(&self, now_ms: u64) -> Result<u64> {
        let (tasks, repaired) = self.load_task_projections(now_ms)?;
        if repaired > 0 {
            warn!(repaired, "rebuilt task projections from the durable event log during startup recovery");
        }
        let actions = self.list_actions()?;
        let mut recovered = 0u64;
        for mut task in tasks {
            if task.status == TaskStatus::Running && (task.pending_action_id.is_some() || !task.pending_action_ids.is_empty()) {
                task.status = TaskStatus::WaitingForAction;
                task.updated_unix_ms = now_ms;
                self.save_task_event(&task, TaskEventKind::Recovered, serde_json::json!({"reason":"server restart recovered pending action"}), now_ms)?;
                recovered += 1;
                continue;
            }
            if task.status == TaskStatus::Running && task.pending_action_id.is_none() && task.pending_action_ids.is_empty() {
                let mut orphaned:Vec<_>=actions.iter().filter(|action|action.spec.origin_task_id.as_deref()==Some(task.task_id.as_str())&&action.created_unix_ms>task.updated_unix_ms).collect();
                orphaned.sort_by_key(|action|action.created_unix_ms);
                if !orphaned.is_empty() {
                    let orphan_ids: Vec<String> = orphaned.iter().map(|action| action.action_id.clone()).collect();
                    for action_id in &orphan_ids { if !task.validation_action_ids.contains(action_id) { task.validation_action_ids.push(action_id.clone()); } }
                    if task.spec.validation_fanout && orphaned.len()>1 {
                        task.pending_action_ids=orphan_ids;
                        task.counters.actions=task.counters.actions.saturating_add(orphaned.len() as u32);
                    } else {
                        task.pending_action_id=Some(orphaned[0].action_id.clone());
                        task.counters.actions=task.counters.actions.saturating_add(1);
                    }
                    task.status=TaskStatus::WaitingForAction; task.updated_unix_ms=now_ms;
                    self.save_task_event(&task,TaskEventKind::Recovered,serde_json::json!({"reason":"reattached orphaned validation action(s)","action_ids":orphaned.iter().map(|a|a.action_id.clone()).collect::<Vec<_>>() }),now_ms)?; recovered+=1;
                }
            }
        }
        Ok(recovered)
    }

    /// The `tasks` row is a denormalized projection of the immutable event log. A row that
    /// no longer decodes must not wedge server startup, so fall back to the newest event
    /// projection and rewrite the row. Rows with no usable event projection are reported
    /// and skipped rather than aborting recovery for every other task.
    fn load_task_projections(&self, now_ms: u64) -> Result<(Vec<TaskRecord>, u64)> {
        let rows: Vec<(String, String)> = {
            let connection = self.connection.lock().expect("database mutex poisoned");
            let mut statement = connection.prepare("SELECT task_id, record_json FROM tasks ORDER BY created_unix_ms ASC")?;
            let mapped = statement.query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?;
            let mut collected = Vec::new();
            for row in mapped { collected.push(row?); }
            collected
        };
        let mut tasks = Vec::with_capacity(rows.len());
        let mut repaired = 0u64;
        for (task_id, record_json) in rows {
            match serde_json::from_str::<TaskRecord>(&record_json) {
                Ok(task) => tasks.push(task),
                Err(error) => match self.replay_task_projection(&task_id) {
                    Ok(task) => {
                        warn!(%task_id, %error, "task projection row failed to decode; rebuilt from event log");
                        self.write_task_projection(&task, now_ms)?;
                        tasks.push(task);
                        repaired += 1;
                    }
                    Err(replay_error) => {
                        warn!(%task_id, %error, %replay_error, "task projection row is unrecoverable; skipping during startup recovery");
                    }
                },
            }
        }
        Ok((tasks, repaired))
    }

    fn write_task_projection(&self, record: &TaskRecord, now_ms: u64) -> Result<()> {
        let connection = self.connection.lock().expect("database mutex poisoned");
        connection.execute(
            "UPDATE tasks SET status=?2, record_json=?3, updated_unix_ms=?4 WHERE task_id=?1",
            params![record.task_id, task_status_str(record.status), serde_json::to_string(record)?, now_ms as i64],
        )?;
        Ok(())
    }

    fn update_node(&self, id: NodeId, update: impl FnOnce(&mut NodeRecord)) -> Result<NodeRecord> {
        let connection = self.connection.lock().expect("database mutex poisoned");
        let record_json: String = connection.query_row(
            "SELECT record_json FROM nodes WHERE id = ?1",
            params![id.to_string()],
            |row| row.get(0),
        )?;
        let mut record: NodeRecord = serde_json::from_str(&record_json)?;
        update(&mut record);
        connection.execute(
            "UPDATE nodes SET record_json = ?2 WHERE id = ?1",
            params![id.to_string(), serde_json::to_string(&record)?],
        )?;
        Ok(record)
    }
}

fn seed_default_principal(connection: &Connection) -> Result<()> {
    let now_ms = crate::unix_ms();
    let record = PrincipalRecord {
        principal_id: "local-admin".into(),
        display_name: "Local Administrator".into(),
        kind: PrincipalKind::Human,
        enabled: true,
        permissions: vec![Permission::Read, Permission::Snapshot, Permission::CandidateCreate, Permission::Execute, Permission::Promote, Permission::Approve, Permission::UseSecret, Permission::ManagePolicy],
        created_unix_ms: now_ms,
    };
    connection.execute(
        "INSERT OR IGNORE INTO principals(principal_id, record_json, updated_unix_ms) VALUES (?1,?2,?3)",
        params![&record.principal_id, serde_json::to_string(&record)?, now_ms as i64],
    )?;
    Ok(())
}

fn hash_secret(secret: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(secret.as_bytes());
    hex::encode(hasher.finalize())
}


const SCHEMA_VERSION: u32 = 9;

fn migrate_schema(connection: &Connection) -> Result<()> {
    let version: u32 = connection.query_row("PRAGMA user_version", [], |row| row.get(0))?;
    if version > SCHEMA_VERSION {
        bail!("database schema version {version} is newer than this server supports ({SCHEMA_VERSION})");
    }
    connection.execute_batch(r#"
        BEGIN IMMEDIATE;
        CREATE TABLE IF NOT EXISTS enrollment_tokens (
            token_hash TEXT PRIMARY KEY,
            expires_unix_ms INTEGER NOT NULL,
            consumed_unix_ms INTEGER,
            label TEXT
        );
        CREATE TABLE IF NOT EXISTS nodes (
            id TEXT PRIMARY KEY,
            record_json TEXT NOT NULL,
            secret_hash TEXT NOT NULL,
            previous_secret_hash TEXT,
            previous_secret_expires_unix_ms INTEGER,
            revoke_reason TEXT
        );
        CREATE TABLE IF NOT EXISTS snapshots (
            snapshot_id TEXT PRIMARY KEY,
            node_id TEXT NOT NULL,
            workspace_id TEXT NOT NULL,
            manifest_digest TEXT NOT NULL,
            record_json TEXT NOT NULL,
            created_unix_ms INTEGER NOT NULL,
            FOREIGN KEY(node_id) REFERENCES nodes(id)
        );
        CREATE INDEX IF NOT EXISTS snapshots_node_created ON snapshots(node_id, created_unix_ms DESC);
        CREATE TABLE IF NOT EXISTS candidates (
            candidate_id TEXT PRIMARY KEY,
            node_id TEXT NOT NULL,
            workspace_id TEXT NOT NULL,
            base_snapshot_id TEXT NOT NULL,
            manifest_digest TEXT NOT NULL,
            record_json TEXT NOT NULL,
            created_unix_ms INTEGER NOT NULL,
            FOREIGN KEY(node_id) REFERENCES nodes(id),
            FOREIGN KEY(base_snapshot_id) REFERENCES snapshots(snapshot_id)
        );
        CREATE INDEX IF NOT EXISTS candidates_created ON candidates(created_unix_ms DESC);
        CREATE TABLE IF NOT EXISTS promotions (
            promotion_id TEXT PRIMARY KEY,
            candidate_id TEXT NOT NULL,
            node_id TEXT NOT NULL,
            workspace_id TEXT NOT NULL,
            outcome TEXT NOT NULL,
            record_json TEXT NOT NULL,
            created_unix_ms INTEGER NOT NULL,
            FOREIGN KEY(candidate_id) REFERENCES candidates(candidate_id),
            FOREIGN KEY(node_id) REFERENCES nodes(id)
        );
        CREATE INDEX IF NOT EXISTS promotions_created ON promotions(created_unix_ms DESC);
        CREATE TABLE IF NOT EXISTS node_capabilities (
            node_id TEXT PRIMARY KEY,
            report_json TEXT NOT NULL,
            reported_unix_ms INTEGER NOT NULL,
            FOREIGN KEY(node_id) REFERENCES nodes(id)
        );
        CREATE TABLE IF NOT EXISTS actions (
            action_id TEXT PRIMARY KEY,
            assigned_node_id TEXT NOT NULL,
            status TEXT NOT NULL,
            record_json TEXT NOT NULL,
            created_unix_ms INTEGER NOT NULL,
            started_unix_ms INTEGER,
            completed_unix_ms INTEGER,
            lease_id TEXT,
            lease_expires_unix_ms INTEGER,
            cancel_requested INTEGER NOT NULL DEFAULT 0,
            FOREIGN KEY(assigned_node_id) REFERENCES nodes(id)
        );
        CREATE INDEX IF NOT EXISTS actions_node_status_created ON actions(assigned_node_id, status, created_unix_ms ASC);
        CREATE INDEX IF NOT EXISTS actions_lease_expiry ON actions(lease_expires_unix_ms) WHERE lease_expires_unix_ms IS NOT NULL;
        CREATE TABLE IF NOT EXISTS tasks (
            task_id TEXT PRIMARY KEY,
            status TEXT NOT NULL,
            record_json TEXT NOT NULL,
            created_unix_ms INTEGER NOT NULL,
            updated_unix_ms INTEGER NOT NULL
        );
        CREATE INDEX IF NOT EXISTS tasks_status_updated ON tasks(status, updated_unix_ms DESC);
        CREATE TABLE IF NOT EXISTS task_events (
            event_id TEXT PRIMARY KEY,
            task_id TEXT NOT NULL,
            sequence INTEGER NOT NULL,
            event_json TEXT NOT NULL,
            created_unix_ms INTEGER NOT NULL,
            UNIQUE(task_id, sequence),
            FOREIGN KEY(task_id) REFERENCES tasks(task_id)
        );
        CREATE INDEX IF NOT EXISTS task_events_task_sequence ON task_events(task_id, sequence ASC);
        CREATE TABLE IF NOT EXISTS repository_indexes (
            snapshot_id TEXT PRIMARY KEY,
            manifest_digest TEXT NOT NULL,
            index_digest TEXT NOT NULL,
            record_json TEXT NOT NULL,
            built_unix_ms INTEGER NOT NULL,
            FOREIGN KEY(snapshot_id) REFERENCES snapshots(snapshot_id)
        );
        CREATE INDEX IF NOT EXISTS repository_indexes_built ON repository_indexes(built_unix_ms DESC);
        CREATE TABLE IF NOT EXISTS native_intelligence (
            snapshot_id TEXT PRIMARY KEY,
            node_id TEXT NOT NULL,
            report_digest TEXT NOT NULL,
            record_json TEXT NOT NULL,
            created_unix_ms INTEGER NOT NULL,
            FOREIGN KEY(snapshot_id) REFERENCES snapshots(snapshot_id),
            FOREIGN KEY(node_id) REFERENCES nodes(id)
        );
        CREATE TABLE IF NOT EXISTS principals (
            principal_id TEXT PRIMARY KEY,
            record_json TEXT NOT NULL,
            updated_unix_ms INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS workspace_policies (
            workspace_id TEXT PRIMARY KEY,
            record_json TEXT NOT NULL,
            updated_unix_ms INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS approvals (
            approval_id TEXT PRIMARY KEY,
            status TEXT NOT NULL,
            action_id TEXT,
            record_json TEXT NOT NULL,
            created_unix_ms INTEGER NOT NULL,
            expires_unix_ms INTEGER NOT NULL,
            FOREIGN KEY(action_id) REFERENCES actions(action_id)
        );
        CREATE INDEX IF NOT EXISTS approvals_status_created ON approvals(status, created_unix_ms DESC);
        CREATE TABLE IF NOT EXISTS action_cache (
            cache_key TEXT PRIMARY KEY,
            trust TEXT NOT NULL,
            workspace_id TEXT NOT NULL,
            candidate_id TEXT,
            toolchain_digest TEXT NOT NULL,
            record_json TEXT NOT NULL,
            created_unix_ms INTEGER NOT NULL,
            last_used_unix_ms INTEGER NOT NULL,
            hit_count INTEGER NOT NULL DEFAULT 0
        );
        CREATE INDEX IF NOT EXISTS action_cache_workspace_used ON action_cache(workspace_id,last_used_unix_ms DESC);
        CREATE TABLE IF NOT EXISTS validation_runs (
            validation_id TEXT PRIMARY KEY,
            candidate_id TEXT NOT NULL,
            workspace_id TEXT NOT NULL,
            status TEXT NOT NULL,
            record_json TEXT NOT NULL,
            created_unix_ms INTEGER NOT NULL,
            completed_unix_ms INTEGER
        );
        CREATE INDEX IF NOT EXISTS validation_runs_candidate_created ON validation_runs(candidate_id,created_unix_ms DESC);
        CREATE TABLE IF NOT EXISTS audit_events (
            sequence INTEGER PRIMARY KEY,
            event_id TEXT UNIQUE NOT NULL,
            previous_hash TEXT NOT NULL,
            event_hash TEXT NOT NULL,
            event_json TEXT NOT NULL,
            created_unix_ms INTEGER NOT NULL
        );
        PRAGMA user_version = 9;
        COMMIT;
    "#)?;
    Ok(())
}


fn insert_task_event(
    transaction: &rusqlite::Transaction<'_>, task_id: &str, sequence: u64,
    kind: TaskEventKind, payload: serde_json::Value, now_ms: u64,
) -> Result<TaskEvent> {
    let event = TaskEvent {
        event_id: Uuid::new_v4().to_string(), task_id: task_id.to_owned(), sequence,
        kind, created_unix_ms: now_ms, payload,
    };
    transaction.execute(
        "INSERT INTO task_events(event_id, task_id, sequence, event_json, created_unix_ms) VALUES (?1,?2,?3,?4,?5)",
        params![event.event_id, event.task_id, sequence as i64, serde_json::to_string(&event)?, now_ms as i64],
    )?;
    Ok(event)
}

fn task_status_str(status: TaskStatus) -> &'static str {
    match status {
        TaskStatus::Created => "created", TaskStatus::Running => "running", TaskStatus::WaitingForAction => "waiting_for_action",
        TaskStatus::Paused => "paused", TaskStatus::Completed => "completed", TaskStatus::Failed => "failed",
        TaskStatus::Cancelled => "cancelled", TaskStatus::BudgetExceeded => "budget_exceeded",
    }
}

fn cache_trust_str(trust: CacheTrust) -> &'static str {
    match trust { CacheTrust::Strong => "strong", CacheTrust::BestEffort => "best_effort", CacheTrust::Disabled => "disabled" }
}

fn validation_status_str(status: sparkbridge_protocol::ValidationRunStatus) -> &'static str {
    use sparkbridge_protocol::ValidationRunStatus::*;
    match status { Running=>"running", AwaitingApproval=>"awaiting_approval", Succeeded=>"succeeded", Failed=>"failed", Cancelled=>"cancelled" }
}

fn action_status_str(status: ActionStatus) -> &'static str {
    match status {
        ActionStatus::AwaitingApproval => "awaiting_approval",
        ActionStatus::Queued => "queued",
        ActionStatus::Leased => "leased",
        ActionStatus::Running => "running",
        ActionStatus::Succeeded => "succeeded",
        ActionStatus::Failed => "failed",
        ActionStatus::Cancelled => "cancelled",
        ActionStatus::TimedOut => "timed_out",
        ActionStatus::Lost => "lost",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sparkbridge_task::TaskSpec;

    fn temp_store(name: &str) -> (Store, std::path::PathBuf) {
        let path = std::env::temp_dir().join(format!("sparkbridge-store-test-{name}-{}.db", Uuid::new_v4()));
        (Store::open(&path).expect("opening test store"), path)
    }

    fn spec() -> TaskSpec {
        // Only the four required fields are supplied; the rest exercise serde defaults.
        serde_json::from_value(serde_json::json!({
            "objective": "projection replay",
            "workspace_id": "repo",
            "base_snapshot_id": "snap",
            "model": "qwen3-coder",
        }))
        .expect("task spec defaults")
    }

    // Task state must be recoverable from the durable event log alone: every
    // `save_task_event` embeds the full projection, and `replay_task_projection`
    // must return the newest one even after the denormalized tasks row is gone.
    #[test]
    fn task_projection_replays_from_event_log() {
        let (store, path) = temp_store("projection");
        let mut record = TaskRecord::new("task-1".into(), spec(), 10);
        store.create_task(&record, 10).expect("creating task");

        record.status = TaskStatus::Running;
        record.counters.actions = 3;
        record.pending_action_id = Some("action-7".into());
        record.updated_unix_ms = 20;
        store.save_task_event(&record, TaskEventKind::ActionScheduled, serde_json::json!({"action_id":"action-7"}), 20)
            .expect("saving task event");

        let replayed = store.replay_task_projection("task-1").expect("replaying projection");
        assert_eq!(replayed.status, TaskStatus::Running);
        assert_eq!(replayed.counters.actions, 3);
        assert_eq!(replayed.pending_action_id.as_deref(), Some("action-7"));

        // The event log, not the denormalized tasks row, is authoritative: a stale or
        // corrupt projection row must still replay forward to the newest event.
        store.connection.lock().expect("database mutex poisoned")
            .execute(
                "UPDATE tasks SET record_json=?2, status=?3 WHERE task_id=?1",
                params!["task-1", "{\"stale\":true}", "created"],
            )
            .expect("corrupting tasks projection row");
        let stale = store.get_task("task-1");
        assert!(stale.is_err(), "stale projection row must not deserialize into a task");
        let replayed = store.replay_task_projection("task-1").expect("replaying projection after row corruption");
        assert_eq!(replayed.status, TaskStatus::Running);
        assert_eq!(replayed.pending_action_id.as_deref(), Some("action-7"));

        // Startup recovery must self-heal that row instead of refusing to boot, and must
        // still park the in-flight task it recovered.
        assert_eq!(store.recover_tasks(30).expect("startup recovery"), 1);
        let healed = store.get_task("task-1").expect("projection row rebuilt by startup recovery");
        assert_eq!(healed.status, TaskStatus::WaitingForAction);
        assert_eq!(healed.pending_action_id.as_deref(), Some("action-7"));

        drop(store);
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(path.with_extension("db-wal"));
        let _ = std::fs::remove_file(path.with_extension("db-shm"));
    }

    // A task left mid-flight across a restart is parked for re-attachment, and a task
    // whose projection row is unrecoverable must not abort recovery for the others.
    #[test]
    fn startup_recovery_parks_in_flight_tasks_and_survives_unrecoverable_rows() {
        let (store, path) = temp_store("recover");
        let mut inflight = TaskRecord::new("task-inflight".into(), spec(), 10);
        store.create_task(&inflight, 10).expect("creating task");
        inflight.status = TaskStatus::Running;
        inflight.pending_action_id = Some("action-1".into());
        store.save_task_event(&inflight, TaskEventKind::ActionScheduled, serde_json::json!({"action_id":"action-1"}), 15)
            .expect("saving task event");

        let mut finished = TaskRecord::new("task-finished".into(), spec(), 10);
        finished.status = TaskStatus::Completed;
        store.create_task(&finished, 10).expect("creating task");

        assert_eq!(store.recover_tasks(30).expect("startup recovery"), 1);
        let recovered = store.get_task("task-inflight").expect("recovered task");
        assert_eq!(recovered.status, TaskStatus::WaitingForAction);

        // An orphaned task with no decodable projection and no event projection at all.
        store.connection.lock().expect("database mutex poisoned")
            .execute(
                "INSERT INTO tasks(task_id, status, record_json, created_unix_ms, updated_unix_ms) VALUES ('task-broken','created','not-json',1,1)",
                [],
            )
            .expect("inserting unrecoverable projection row");

        // Recovery still succeeds for the healthy tasks instead of failing startup.
        assert_eq!(store.recover_tasks(40).expect("startup recovery with a broken row"), 0);
        assert_eq!(store.get_task("task-inflight").expect("still readable").status, TaskStatus::WaitingForAction);

        drop(store);
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(path.with_extension("db-wal"));
        let _ = std::fs::remove_file(path.with_extension("db-shm"));
    }
}

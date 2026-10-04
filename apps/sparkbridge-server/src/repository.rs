use crate::{ApiError, AppState};
use axum::http::StatusCode;
use serde_json::json;
use sparkbridge_cas::Digest;
use sparkbridge_index::{
    NativeIntelligenceRecord, NativeIntelligenceReport, RepositoryIndex, RepositoryIndexRecord, SearchHit, SymbolHit, build_repository_index,
    extension_counts, git_history, lexical_search, rank_paths, reference_search, symbol_search,
};
use sparkbridge_snapshot::WorkspaceSnapshot;

pub fn ensure_index(state: &AppState, snapshot_id: &str) -> Result<(RepositoryIndexRecord, RepositoryIndex, WorkspaceSnapshot), ApiError> {
    let snapshot_record = state.store.get_snapshot(snapshot_id)
        .map_err(|e| (StatusCode::NOT_FOUND, e.to_string()))?;
    let manifest_bytes = state.cas.get_bytes(&Digest(snapshot_record.manifest_digest.clone()), state.config.cas_max_object_bytes as u64)
        .map_err(crate::internal_error)?;
    let snapshot: WorkspaceSnapshot = serde_json::from_slice(&manifest_bytes)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    if let Ok(record) = state.store.get_repository_index(snapshot_id) {
        if record.manifest_digest == snapshot_record.manifest_digest {
            let bytes = state.cas.get_bytes(&Digest(record.index_digest.clone()), state.config.cas_max_object_bytes as u64)
                .map_err(crate::internal_error)?;
            let index: RepositoryIndex = serde_json::from_slice(&bytes)
                .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
            return Ok((record,index,snapshot));
        }
    }

    let index = build_repository_index(
        snapshot_id,
        &snapshot_record.manifest_digest,
        &snapshot,
        &state.cas,
        state.config.intelligence_max_file_bytes,
        state.config.intelligence_max_files,
        state.config.intelligence_max_symbols,
        state.config.intelligence_max_references,
        crate::unix_ms(),
    ).map_err(crate::internal_error)?;
    let encoded = serde_json::to_vec(&index).map_err(|error| crate::internal_error(error.into()))?;
    let object = state.cas.put_bytes(None,&encoded).map_err(crate::internal_error)?;
    let record = RepositoryIndexRecord {
        snapshot_id: snapshot_id.to_owned(),
        manifest_digest: snapshot_record.manifest_digest,
        index_digest: object.digest.0,
        file_count: index.files.len() as u64,
        symbol_count: index.symbols.len() as u64,
        reference_count: index.references.len() as u64,
        built_unix_ms: index.built_unix_ms,
    };
    state.store.register_repository_index(&record).map_err(crate::internal_error)?;
    Ok((record,index,snapshot))
}

pub fn build_index(state:&AppState,snapshot_id:&str)->Result<RepositoryIndexRecord,ApiError>{
    ensure_index(state,snapshot_id).map(|(record,_,_)|record)
}

pub fn search(state:&AppState,snapshot_id:&str,query:&str,limit:usize)->Result<Vec<SearchHit>,ApiError>{
    let (_,_,snapshot)=ensure_index(state,snapshot_id)?;
    lexical_search(&state.cas,&snapshot,query,limit.min(state.config.intelligence_search_limit),state.config.intelligence_max_file_bytes).map_err(crate::internal_error)
}

pub fn symbols(state:&AppState,snapshot_id:&str,query:&str,limit:usize)->Result<Vec<SymbolHit>,ApiError>{
    let (_,index,_)=ensure_index(state,snapshot_id)?;
    let limit=limit.min(state.config.intelligence_search_limit); let mut hits=symbol_search(&index,query,limit);
    if let Some((_record,report))=load_native_report(state,snapshot_id)? { let needle=query.trim().to_ascii_lowercase(); if needle.is_empty(){return Ok(hits);} for symbol in report.symbols { let name=symbol.name.to_ascii_lowercase(); let score=if name==needle{120}else if name.starts_with(&needle){95}else if name.contains(&needle){75}else{continue}; hits.push(SymbolHit{symbol,score}); } }
    hits.sort_by(|a,b|b.score.cmp(&a.score).then_with(||a.symbol.path.cmp(&b.symbol.path))); hits.truncate(limit); Ok(hits)
}

pub fn references(state:&AppState,snapshot_id:&str,query:&str,limit:usize)->Result<Vec<sparkbridge_index::ReferenceRecord>,ApiError>{
    let (_,index,_)=ensure_index(state,snapshot_id)?;
    Ok(reference_search(&index,query,limit.min(state.config.intelligence_search_limit)))
}

pub fn history(state:&AppState,snapshot_id:&str)->Result<Vec<sparkbridge_snapshot::GitCommitSummary>,ApiError>{
    let (_,_,snapshot)=ensure_index(state,snapshot_id)?; Ok(git_history(&snapshot))
}

pub fn context_intelligence(state:&AppState,snapshot_id:&str,query:&str)->Result<(Vec<String>,serde_json::Value),ApiError>{
    let (record,index,snapshot)=ensure_index(state,snapshot_id)?;
    let mut paths=rank_paths(&index,query,state.config.intelligence_ranked_paths);
    let symbols=symbol_search(&index,query,32);
    let native_report=load_native_report(state,snapshot_id)?;
    let mut native_symbols=Vec::new();
    if let Some((_record,report))=&native_report { let needle_terms:Vec<_>=query.split(|c:char|!c.is_ascii_alphanumeric()&&c!='_').filter(|x|x.len()>=3).map(|x|x.to_ascii_lowercase()).collect(); for symbol in &report.symbols { let name=symbol.name.to_ascii_lowercase(); if needle_terms.iter().any(|term|name==*term||name.contains(term)){ native_symbols.push(symbol.clone()); if !paths.iter().any(|p|p==&symbol.path){paths.insert(0,symbol.path.clone());} }
        if native_symbols.len()>=32{break;} } }
    paths.truncate(state.config.intelligence_ranked_paths);
    let commits=git_history(&snapshot);
    let languages=extension_counts(&index);
    Ok((paths.clone(),json!({
        "index_digest":record.index_digest,
        "snapshot_id":snapshot_id,
        "ranked_paths":paths,
        "symbol_matches":symbols,
        "native_symbol_matches":native_symbols,
        "native_intelligence":native_report.as_ref().map(|(record,report)|serde_json::json!({"report_digest":record.report_digest,"symbols":record.symbol_count,"adapters":report.adapters,"truncated":report.truncated})),
        "recent_git_history":commits,
        "language_file_counts":languages,
        "index_stats":{"files":record.file_count,"symbols":record.symbol_count,"references":record.reference_count,"truncated":index.truncated}
    })))
}


pub fn register_native_report(state:&AppState,node_id:sparkbridge_core::NodeId,snapshot_id:&str,report:NativeIntelligenceReport)->Result<NativeIntelligenceRecord,ApiError>{
    let snapshot_record=state.store.get_snapshot(snapshot_id).map_err(|e|(StatusCode::NOT_FOUND,e.to_string()))?;
    if snapshot_record.node_id!=node_id{return Err((StatusCode::FORBIDDEN,"snapshot belongs to another executor".into()));}
    if report.snapshot_id!=snapshot_id||report.workspace_id!=snapshot_record.workspace_id{return Err((StatusCode::BAD_REQUEST,"native intelligence report does not match snapshot/workspace".into()));}
    if report.symbols.len()>state.config.intelligence_max_symbols{return Err((StatusCode::PAYLOAD_TOO_LARGE,"native intelligence symbol limit exceeded".into()));}
    let manifest_bytes=state.cas.get_bytes(&Digest(snapshot_record.manifest_digest.clone()),state.config.cas_max_object_bytes as u64).map_err(crate::internal_error)?;
    let snapshot:WorkspaceSnapshot=serde_json::from_slice(&manifest_bytes).map_err(|e|(StatusCode::INTERNAL_SERVER_ERROR,e.to_string()))?;
    let allowed:std::collections::BTreeSet<_>=snapshot.entries.iter().filter(|e|e.kind==sparkbridge_snapshot::EntryKind::File).map(|e|e.path.as_str()).collect();
    if report.symbols.iter().any(|symbol|!allowed.contains(symbol.path.as_str())){return Err((StatusCode::BAD_REQUEST,"native intelligence references a path outside the snapshot".into()));}
    let bytes=serde_json::to_vec(&report).map_err(|error| crate::internal_error(error.into()))?; let object=state.cas.put_bytes(None,&bytes).map_err(crate::internal_error)?;
    let record=NativeIntelligenceRecord{snapshot_id:snapshot_id.into(),workspace_id:report.workspace_id,node_id:node_id.to_string(),report_digest:object.digest.0,symbol_count:report.symbols.len() as u64,adapters:report.adapters,created_unix_ms:report.created_unix_ms,truncated:report.truncated};
    state.store.register_native_intelligence(&record).map_err(crate::internal_error)?; Ok(record)
}

fn load_native_report(state:&AppState,snapshot_id:&str)->Result<Option<(NativeIntelligenceRecord,NativeIntelligenceReport)>,ApiError>{
    let record=match state.store.get_native_intelligence(snapshot_id){Ok(r)=>r,Err(_)=>return Ok(None)};
    let bytes=state.cas.get_bytes(&Digest(record.report_digest.clone()),state.config.cas_max_object_bytes as u64).map_err(crate::internal_error)?;
    let report=serde_json::from_slice(&bytes).map_err(|e|(StatusCode::INTERNAL_SERVER_ERROR,e.to_string()))?;
    Ok(Some((record,report)))
}

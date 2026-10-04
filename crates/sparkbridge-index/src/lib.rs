use anyhow::{Context, Result};
use regex::Regex;
use serde::{Deserialize, Serialize};
use sparkbridge_cas::{Cas, Digest};
use sparkbridge_snapshot::{EntryKind, WorkspaceSnapshot};
use std::{collections::{BTreeMap, BTreeSet, HashMap}, path::Path};
use tree_sitter::{Language, Node, Parser};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceLanguage { Rust, Python, C, Cpp, Javascript, Typescript, Tsx, Swift, Csharp, Java, Kotlin, Go, Other }

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SymbolKind { Function, Method, Type, Struct, Class, Enum, Trait, Interface, Module, Namespace, Variable, Constant, Field, Property, Unknown }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IndexedFile {
    pub path: String,
    pub digest: String,
    pub language: SourceLanguage,
    pub size_bytes: u64,
    pub line_count: u32,
    pub parser: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SymbolRecord {
    pub symbol_id: String,
    pub name: String,
    pub kind: SymbolKind,
    pub path: String,
    pub language: SourceLanguage,
    pub start_line: u32,
    pub start_column: u32,
    pub end_line: u32,
    pub end_column: u32,
    pub container: Option<String>,
    pub source: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReferenceRecord {
    pub name: String,
    pub path: String,
    pub language: SourceLanguage,
    pub line: u32,
    pub column: u32,
    pub source: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RepositoryIndex {
    pub format_version: u32,
    pub snapshot_id: String,
    pub manifest_digest: String,
    pub files: Vec<IndexedFile>,
    pub symbols: Vec<SymbolRecord>,
    pub references: Vec<ReferenceRecord>,
    pub built_unix_ms: u64,
    pub truncated: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RepositoryIndexRecord {
    pub snapshot_id: String,
    pub manifest_digest: String,
    pub index_digest: String,
    pub file_count: u64,
    pub symbol_count: u64,
    pub reference_count: u64,
    pub built_unix_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SearchHit {
    pub path: String,
    pub line: u32,
    pub column: u32,
    pub excerpt: String,
    pub score: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SymbolHit {
    pub symbol: SymbolRecord,
    pub score: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NativeAdapterDescriptor {
    pub language: SourceLanguage,
    pub executable: String,
    pub adapter: String,
    pub available: bool,
    pub capabilities: Vec<String>,
}

pub fn detect_language(path: &str) -> SourceLanguage {
    let lower = path.to_ascii_lowercase();
    if lower.ends_with(".rs") { SourceLanguage::Rust }
    else if lower.ends_with(".py") || lower.ends_with(".pyi") { SourceLanguage::Python }
    else if lower.ends_with(".c") || lower.ends_with(".h") { SourceLanguage::C }
    else if lower.ends_with(".cc") || lower.ends_with(".cpp") || lower.ends_with(".cxx") || lower.ends_with(".hpp") || lower.ends_with(".hh") { SourceLanguage::Cpp }
    else if lower.ends_with(".js") || lower.ends_with(".jsx") || lower.ends_with(".mjs") || lower.ends_with(".cjs") { SourceLanguage::Javascript }
    else if lower.ends_with(".tsx") { SourceLanguage::Tsx }
    else if lower.ends_with(".ts") || lower.ends_with(".mts") || lower.ends_with(".cts") { SourceLanguage::Typescript }
    else if lower.ends_with(".swift") { SourceLanguage::Swift }
    else if lower.ends_with(".cs") { SourceLanguage::Csharp }
    else if lower.ends_with(".java") { SourceLanguage::Java }
    else if lower.ends_with(".kt") || lower.ends_with(".kts") { SourceLanguage::Kotlin }
    else if lower.ends_with(".go") { SourceLanguage::Go }
    else { SourceLanguage::Other }
}

pub fn indexed_files_from_snapshot(snapshot:&WorkspaceSnapshot)->Vec<IndexedFile>{
    snapshot.entries.iter().filter_map(|entry|{
        if entry.kind!=EntryKind::File{return None;} let language=detect_language(&entry.path); if language==SourceLanguage::Other{return None;} let digest=entry.digest.as_ref()?;
        Some(IndexedFile{path:entry.path.clone(),digest:digest.0.clone(),language,size_bytes:entry.size_bytes,line_count:0,parser:"unparsed".into()})
    }).collect()
}

// The bounded-index limits are passed explicitly so the caller cannot silently change the
// intelligence budget; grouping them would hide which bound each call site is choosing.
#[allow(clippy::too_many_arguments)]
pub fn build_repository_index(
    snapshot_id: &str,
    manifest_digest: &str,
    snapshot: &WorkspaceSnapshot,
    cas: &Cas,
    max_file_bytes: u64,
    max_files: usize,
    max_symbols: usize,
    max_references: usize,
    built_unix_ms: u64,
) -> Result<RepositoryIndex> {
    let mut files = Vec::new();
    let mut symbols = Vec::new();
    let mut references = Vec::new();
    let mut truncated = false;
    for entry in &snapshot.entries {
        if files.len() >= max_files { truncated = true; break; }
        if entry.kind != EntryKind::File || entry.size_bytes > max_file_bytes { continue; }
        let language = detect_language(&entry.path);
        if language == SourceLanguage::Other { continue; }
        let Some(digest) = &entry.digest else { continue; };
        let bytes = cas.get_bytes(digest, max_file_bytes).with_context(|| format!("reading {} for repository index", entry.path))?;
        let Ok(text) = std::str::from_utf8(&bytes) else { continue; };
        let parser_name;
        if let Some(language_handle) = tree_sitter_language(language) {
            parser_name = "tree_sitter".to_string();
            if let Ok((mut file_symbols, mut file_references)) = parse_tree_sitter(&entry.path, language, text, language_handle) {
                let remaining_symbols = max_symbols.saturating_sub(symbols.len());
                let remaining_references = max_references.saturating_sub(references.len());
                if file_symbols.len() > remaining_symbols || file_references.len() > remaining_references { truncated = true; }
                symbols.extend(file_symbols.drain(..file_symbols.len().min(remaining_symbols)));
                references.extend(file_references.drain(..file_references.len().min(remaining_references)));
            }
        } else {
            parser_name = "structural_fallback".to_string();
            let (mut file_symbols, mut file_references) = parse_structural_fallback(&entry.path, language, text);
            let remaining_symbols = max_symbols.saturating_sub(symbols.len());
            let remaining_references = max_references.saturating_sub(references.len());
            if file_symbols.len() > remaining_symbols || file_references.len() > remaining_references { truncated = true; }
            symbols.extend(file_symbols.drain(..file_symbols.len().min(remaining_symbols)));
            references.extend(file_references.drain(..file_references.len().min(remaining_references)));
        }
        files.push(IndexedFile {
            path: entry.path.clone(), digest: digest.0.clone(), language, size_bytes: entry.size_bytes,
            line_count: text.lines().count().min(u32::MAX as usize) as u32, parser: parser_name,
        });
    }
    symbols.sort_by(|a,b| (&a.path,a.start_line,a.start_column,&a.name).cmp(&(&b.path,b.start_line,b.start_column,&b.name)));
    references.sort_by(|a,b| (&a.path,a.line,a.column,&a.name).cmp(&(&b.path,b.line,b.column,&b.name)));
    Ok(RepositoryIndex { format_version: 1, snapshot_id: snapshot_id.into(), manifest_digest: manifest_digest.into(), files, symbols, references, built_unix_ms, truncated })
}

fn tree_sitter_language(language: SourceLanguage) -> Option<Language> {
    match language {
        SourceLanguage::Rust => Some(tree_sitter_rust::LANGUAGE.into()),
        SourceLanguage::Python => Some(tree_sitter_python::LANGUAGE.into()),
        SourceLanguage::C => Some(tree_sitter_c::LANGUAGE.into()),
        SourceLanguage::Cpp => Some(tree_sitter_cpp::LANGUAGE.into()),
        SourceLanguage::Javascript => Some(tree_sitter_javascript::LANGUAGE.into()),
        SourceLanguage::Typescript => Some(tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into()),
        SourceLanguage::Tsx => Some(tree_sitter_typescript::LANGUAGE_TSX.into()),
        _ => None,
    }
}

fn parse_tree_sitter(path: &str, language: SourceLanguage, text: &str, language_handle: Language) -> Result<(Vec<SymbolRecord>, Vec<ReferenceRecord>)> {
    let mut parser = Parser::new();
    parser.set_language(&language_handle).context("setting Tree-sitter language")?;
    let tree = parser.parse(text, None).context("Tree-sitter parser returned no tree")?;
    let mut symbols = Vec::new();
    let mut references = Vec::new();
    collect_nodes(tree.root_node(), path, language, text.as_bytes(), None, &mut symbols, &mut references);
    let symbol_positions: BTreeSet<(u32,u32,String)> = symbols.iter().map(|s|(s.start_line,s.start_column,s.name.clone())).collect();
    references.retain(|r| !symbol_positions.contains(&(r.line,r.column,r.name.clone())));
    Ok((symbols,references))
}

fn collect_nodes(
    node: Node<'_>, path: &str, language: SourceLanguage, source: &[u8], container: Option<&str>,
    symbols: &mut Vec<SymbolRecord>, references: &mut Vec<ReferenceRecord>,
) {
    let mut next_container = container.map(str::to_owned);
    if let Some(kind) = symbol_kind(node.kind()) {
        if let Some(name_node) = symbol_name_node(node) {
            if let Ok(name) = name_node.utf8_text(source) {
                if !name.trim().is_empty() {
                    let start = name_node.start_position();
                    let end = node.end_position();
                    let symbol = SymbolRecord {
                        symbol_id: Digest::from_bytes(format!("{path}\0{}\0{}\0{}", start.row, start.column, name).as_bytes()).0,
                        name: name.to_owned(), kind, path: path.to_owned(), language,
                        start_line: start.row.saturating_add(1) as u32, start_column: start.column.saturating_add(1) as u32,
                        end_line: end.row.saturating_add(1) as u32, end_column: end.column.saturating_add(1) as u32,
                        container: container.map(str::to_owned), source: "tree_sitter".into(),
                    };
                    if matches!(kind, SymbolKind::Type|SymbolKind::Struct|SymbolKind::Class|SymbolKind::Enum|SymbolKind::Trait|SymbolKind::Interface|SymbolKind::Module|SymbolKind::Namespace) {
                        next_container = Some(name.to_owned());
                    }
                    symbols.push(symbol);
                }
            }
        }
    }
    if is_reference_kind(node.kind()) {
        if let Ok(name) = node.utf8_text(source) {
            if is_identifier(name) {
                let p = node.start_position();
                references.push(ReferenceRecord { name:name.to_owned(), path:path.to_owned(), language, line:p.row.saturating_add(1) as u32, column:p.column.saturating_add(1) as u32, source:"tree_sitter".into() });
            }
        }
    }
    for i in 0..node.named_child_count() {
        if let Some(child) = node.named_child(i) {
            collect_nodes(child, path, language, source, next_container.as_deref(), symbols, references);
        }
    }
}

fn symbol_kind(kind: &str) -> Option<SymbolKind> {
    Some(match kind {
        "function_item"|"function_definition"|"function_declaration"|"function_expression"|"arrow_function" => SymbolKind::Function,
        "method_definition"|"method_declaration" => SymbolKind::Method,
        "struct_item"|"struct_specifier" => SymbolKind::Struct,
        "class_definition"|"class_declaration"|"class_specifier" => SymbolKind::Class,
        "enum_item"|"enum_specifier"|"enum_declaration" => SymbolKind::Enum,
        "trait_item" => SymbolKind::Trait,
        "interface_declaration" => SymbolKind::Interface,
        "mod_item"|"module" => SymbolKind::Module,
        "namespace_definition" => SymbolKind::Namespace,
        "type_item"|"type_alias_declaration" => SymbolKind::Type,
        "const_item"|"constant_declaration" => SymbolKind::Constant,
        _ => return None,
    })
}

fn symbol_name_node(node: Node<'_>) -> Option<Node<'_>> {
    node.child_by_field_name("name")
        .or_else(|| node.child_by_field_name("declarator").and_then(first_identifier))
        .or_else(|| first_identifier(node))
}

fn first_identifier(node: Node<'_>) -> Option<Node<'_>> {
    if is_reference_kind(node.kind()) { return Some(node); }
    for i in 0..node.named_child_count() {
        if let Some(child) = node.named_child(i) {
            if let Some(found) = first_identifier(child) { return Some(found); }
        }
    }
    None
}

fn is_reference_kind(kind: &str) -> bool {
    matches!(kind, "identifier"|"type_identifier"|"field_identifier"|"property_identifier"|"shorthand_property_identifier_pattern")
}
fn is_identifier(value:&str)->bool { !value.is_empty() && value.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'$') }

fn parse_structural_fallback(path:&str, language:SourceLanguage, text:&str)->(Vec<SymbolRecord>,Vec<ReferenceRecord>) {
    let declaration = Regex::new(r"(?x)^\s*(?:(?:public|private|internal|open|final|static|class|struct|enum|protocol|interface|func|function|def|fn|type|let|var|const)\s+){0,3}(?:class|struct|enum|protocol|interface|func|function|def|fn|type)\s+([A-Za-z_$][A-Za-z0-9_$]*)").expect("fallback declaration regex");
    let identifiers = Regex::new(r"[A-Za-z_$][A-Za-z0-9_$]*").expect("identifier regex");
    let mut symbols=Vec::new(); let mut references=Vec::new();
    for (line_index,line) in text.lines().enumerate() {
        if let Some(caps)=declaration.captures(line) { if let Some(m)=caps.get(1) {
            let kind = if line.contains("class "){SymbolKind::Class}else if line.contains("struct "){SymbolKind::Struct}else if line.contains("enum "){SymbolKind::Enum}else if line.contains("protocol ")||line.contains("interface "){SymbolKind::Interface}else if line.contains("type "){SymbolKind::Type}else{SymbolKind::Function};
            symbols.push(SymbolRecord{symbol_id:Digest::from_bytes(format!("{path}\0{line_index}\0{}",m.as_str()).as_bytes()).0,name:m.as_str().into(),kind,path:path.into(),language,start_line:(line_index+1) as u32,start_column:(m.start()+1) as u32,end_line:(line_index+1) as u32,end_column:(m.end()+1) as u32,container:None,source:"structural_fallback".into()});
        }}
        for m in identifiers.find_iter(line) { references.push(ReferenceRecord{name:m.as_str().into(),path:path.into(),language,line:(line_index+1) as u32,column:(m.start()+1) as u32,source:"structural_fallback".into()}); }
    }
    (symbols,references)
}

pub fn symbol_search(index:&RepositoryIndex, query:&str, limit:usize)->Vec<SymbolHit> {
    let needle=query.trim().to_ascii_lowercase(); if needle.is_empty(){return Vec::new();}
    let mut hits:Vec<_>=index.symbols.iter().filter_map(|symbol|{
        let name=symbol.name.to_ascii_lowercase(); let score=if name==needle{100}else if name.starts_with(&needle){80}else if name.contains(&needle){60}else{return None};
        Some(SymbolHit{symbol:symbol.clone(),score})
    }).collect();
    hits.sort_by(|a,b| b.score.cmp(&a.score).then_with(||a.symbol.path.cmp(&b.symbol.path)).then_with(||a.symbol.start_line.cmp(&b.symbol.start_line))); hits.truncate(limit); hits
}

pub fn reference_search(index:&RepositoryIndex, query:&str, limit:usize)->Vec<ReferenceRecord> {
    let needle=query.trim().to_ascii_lowercase(); if needle.is_empty(){return Vec::new();}
    let mut hits:Vec<_>=index.references.iter().filter(|reference|reference.name.to_ascii_lowercase()==needle).cloned().collect();
    hits.sort_by(|a,b|a.path.cmp(&b.path).then_with(||a.line.cmp(&b.line)).then_with(||a.column.cmp(&b.column))); hits.truncate(limit); hits
}

pub fn rank_paths(index:&RepositoryIndex, query:&str, limit:usize)->Vec<String> {
    let terms:Vec<String>=query.split(|c:char| !c.is_ascii_alphanumeric() && c!='_').filter(|x|x.len()>=3).map(|x|x.to_ascii_lowercase()).collect();
    if terms.is_empty(){return Vec::new();}
    let mut scores:HashMap<&str,u32>=HashMap::new();
    for symbol in &index.symbols { let name=symbol.name.to_ascii_lowercase(); for term in &terms { if name==*term{*scores.entry(&symbol.path).or_default()+=30}else if name.contains(term){*scores.entry(&symbol.path).or_default()+=12} } }
    for reference in &index.references { let name=reference.name.to_ascii_lowercase(); for term in &terms { if name==*term{*scores.entry(&reference.path).or_default()+=3} } }
    let mut ranked:Vec<_>=scores.into_iter().collect(); ranked.sort_by(|a,b|b.1.cmp(&a.1).then_with(||a.0.cmp(b.0))); ranked.into_iter().take(limit).map(|(p,_)|p.to_owned()).collect()
}

pub fn lexical_search(cas:&Cas,snapshot:&WorkspaceSnapshot,query:&str,limit:usize,max_file_bytes:u64)->Result<Vec<SearchHit>> {
    let needle=query.trim(); if needle.is_empty(){return Ok(Vec::new());}
    let needle_lower=needle.to_ascii_lowercase(); let mut out=Vec::new();
    for entry in &snapshot.entries { if out.len()>=limit{break;}
        if entry.kind!=EntryKind::File || entry.size_bytes>max_file_bytes{continue;} let Some(digest)=&entry.digest else{continue;}; let bytes=cas.get_bytes(digest,max_file_bytes)?; let Ok(text)=std::str::from_utf8(&bytes) else{continue;};
        for (line_index,line) in text.lines().enumerate(){ if out.len()>=limit{break;} let lower=line.to_ascii_lowercase(); if let Some(pos)=lower.find(&needle_lower){out.push(SearchHit{path:entry.path.clone(),line:(line_index+1) as u32,column:(pos+1) as u32,excerpt:line.chars().take(400).collect(),score:if line[pos..].starts_with(needle){20}else{10}});}}
    }
    Ok(out)
}

pub fn discover_native_adapters() -> Vec<NativeAdapterDescriptor> {
    [
        (SourceLanguage::Swift,"sourcekit-lsp","sourcekit_lsp"),
        (SourceLanguage::Rust,"rust-analyzer","rust_analyzer"),
        (SourceLanguage::C,"clangd","clangd"),
        (SourceLanguage::Cpp,"clangd","clangd"),
        (SourceLanguage::Csharp,"Microsoft.CodeAnalysis.LanguageServer","roslyn_lsp"),
    ].into_iter().map(|(language,executable,adapter)|NativeAdapterDescriptor{language,executable:executable.into(),adapter:adapter.into(),available:command_available(executable),capabilities:vec!["document_symbols".into()]}).collect()
}

fn command_available(command:&str)->bool {
    let Some(path)=std::env::var_os("PATH") else{return false;};
    std::env::split_paths(&path).any(|dir|{
        let candidate=dir.join(command); if candidate.is_file(){return true;}
        #[cfg(windows)] { if dir.join(format!("{command}.exe")).is_file(){return true;} }
        false
    })
}

pub fn git_history(snapshot:&WorkspaceSnapshot)->Vec<sparkbridge_snapshot::GitCommitSummary>{ snapshot.git.as_ref().map(|g|g.recent_commits.clone()).unwrap_or_default() }

pub fn extension_counts(index:&RepositoryIndex)->BTreeMap<SourceLanguage,u64>{ let mut out=BTreeMap::new(); for file in &index.files{*out.entry(file.language).or_default()+=1;} out }

#[cfg(test)]
mod tests {
    use super::*;
    #[test] fn language_detection(){assert_eq!(detect_language("src/main.rs"),SourceLanguage::Rust);assert_eq!(detect_language("App/View.swift"),SourceLanguage::Swift);assert_eq!(detect_language("web/app.tsx"),SourceLanguage::Tsx);}
    #[test] fn fallback_extracts_swift_symbols(){let (symbols,_)=parse_structural_fallback("A.swift",SourceLanguage::Swift,"struct Demo {}\nfunc run() {}\n");assert!(symbols.iter().any(|s|s.name=="Demo"));assert!(symbols.iter().any(|s|s.name=="run"));}
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NativeIntelligenceReport {
    pub format_version: u32,
    pub snapshot_id: String,
    pub workspace_id: String,
    pub adapters: Vec<NativeAdapterDescriptor>,
    pub symbols: Vec<SymbolRecord>,
    pub created_unix_ms: u64,
    pub truncated: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NativeIntelligenceRecord {
    pub snapshot_id: String,
    pub workspace_id: String,
    pub node_id: String,
    pub report_digest: String,
    pub symbol_count: u64,
    pub adapters: Vec<NativeAdapterDescriptor>,
    pub created_unix_ms: u64,
    pub truncated: bool,
}

#[derive(Debug)]
pub struct NativeCollectionOptions {
    pub max_files: usize,
    pub max_file_bytes: u64,
    pub request_timeout: std::time::Duration,
    pub commands: BTreeMap<String, Vec<String>>,
}

pub async fn collect_native_symbols(root:&Path, files:&[IndexedFile], options:&NativeCollectionOptions) -> Result<(Vec<NativeAdapterDescriptor>,Vec<SymbolRecord>,bool)> {
    let descriptors = discover_native_adapters_with_commands(&options.commands);
    let mut symbols=Vec::new(); let mut truncated=false; let mut handled=0usize;
    for descriptor in descriptors.iter().filter(|d|d.available) {
        let Some(argv)=options.commands.get(&adapter_key(descriptor.language)).filter(|v|!v.is_empty()) else { continue; };
        let matching:Vec<_>=files.iter().filter(|f|native_adapter_matches(descriptor.language,f.language)).take(options.max_files.saturating_sub(handled)).collect();
        if matching.is_empty(){continue;}
        if handled>=options.max_files{truncated=true;break;}
        let mut session=match LspSession::spawn(argv,root,options.request_timeout).await { Ok(s)=>s,Err(_)=>continue };
        for file in matching {
            if handled>=options.max_files{truncated=true;break;} handled+=1;
            if file.size_bytes>options.max_file_bytes{continue;}
            let path=root.join(file.path.replace('/',std::path::MAIN_SEPARATOR_STR));
            let Ok(bytes)=tokio::fs::read(&path).await else{continue;}; if bytes.len() as u64>options.max_file_bytes{continue;}
            let Ok(text)=String::from_utf8(bytes) else{continue;};
            if let Ok(mut found)=session.document_symbols(&path,&file.path,language_id(file.language),&text,file.language,options.request_timeout).await { symbols.append(&mut found); }
        }
        let _=session.shutdown(options.request_timeout).await;
    }
    Ok((descriptors,symbols,truncated))
}

fn adapter_key(language:SourceLanguage)->String { match language { SourceLanguage::Rust=>"rust",SourceLanguage::Swift=>"swift",SourceLanguage::C|SourceLanguage::Cpp=>"c_cpp",SourceLanguage::Csharp=>"csharp",_=>"other" }.into() }
fn native_adapter_matches(adapter:SourceLanguage,file:SourceLanguage)->bool { adapter==file || matches!((adapter,file),(SourceLanguage::C,SourceLanguage::Cpp)|(SourceLanguage::Cpp,SourceLanguage::C)) }
fn language_id(language:SourceLanguage)->&'static str { match language { SourceLanguage::Rust=>"rust",SourceLanguage::Swift=>"swift",SourceLanguage::C=>"c",SourceLanguage::Cpp=>"cpp",SourceLanguage::Csharp=>"csharp",SourceLanguage::Python=>"python",SourceLanguage::Javascript=>"javascript",SourceLanguage::Typescript=>"typescript",SourceLanguage::Tsx=>"typescriptreact",_=>"plaintext" } }

pub fn discover_native_adapters_with_commands(commands:&BTreeMap<String,Vec<String>>)->Vec<NativeAdapterDescriptor>{
    [(SourceLanguage::Rust,"rust","rust_analyzer"),(SourceLanguage::Swift,"swift","sourcekit_lsp"),(SourceLanguage::Cpp,"c_cpp","clangd"),(SourceLanguage::Csharp,"csharp","roslyn_lsp")].into_iter().map(|(language,key,adapter)|{
        let argv=commands.get(key).cloned().unwrap_or_default(); let executable=argv.first().cloned().unwrap_or_default();
        NativeAdapterDescriptor{language,executable:executable.clone(),adapter:adapter.into(),available:!executable.is_empty()&&command_available(&executable),capabilities:vec!["document_symbols".into()]}
    }).collect()
}

struct LspSession {
    child: tokio::process::Child,
    stdin: tokio::process::ChildStdin,
    stdout: tokio::io::BufReader<tokio::process::ChildStdout>,
    next_id:u64,
}

impl LspSession {
    async fn spawn(argv:&[String],root:&Path,timeout:std::time::Duration)->Result<Self>{
        use tokio::process::Command as TokioCommand;
        let exe=argv.first().context("empty LSP command")?;
        let mut child=TokioCommand::new(exe).args(&argv[1..]).stdin(std::process::Stdio::piped()).stdout(std::process::Stdio::piped()).stderr(std::process::Stdio::null()).kill_on_drop(true).spawn().with_context(||format!("starting LSP adapter {exe}"))?;
        let stdin=child.stdin.take().context("LSP stdin unavailable")?; let stdout=tokio::io::BufReader::new(child.stdout.take().context("LSP stdout unavailable")?);
        let mut session=Self{child,stdin,stdout,next_id:1};
        let root_uri=url::Url::from_directory_path(root).map_err(|_|anyhow::anyhow!("workspace path cannot be represented as file URI"))?.to_string();
        let id=session.next_request_id();
        session.send(json_rpc_request(id,"initialize",serde_json::json!({"processId":null,"rootUri":root_uri,"capabilities":{"textDocument":{"documentSymbol":{"hierarchicalDocumentSymbolSupport":true}}},"clientInfo":{"name":"SparkBridge","version":env!("CARGO_PKG_VERSION")}}))).await?;
        let _=session.wait_response(id,timeout).await?;
        session.send(serde_json::json!({"jsonrpc":"2.0","method":"initialized","params":{}})).await?;
        Ok(session)
    }
    fn next_request_id(&mut self)->u64{let id=self.next_id;self.next_id=self.next_id.saturating_add(1);id}
    async fn send(&mut self,value:serde_json::Value)->Result<()>{
        use tokio::io::AsyncWriteExt; let bytes=serde_json::to_vec(&value)?; self.stdin.write_all(format!("Content-Length: {}\r\n\r\n",bytes.len()).as_bytes()).await?; self.stdin.write_all(&bytes).await?; self.stdin.flush().await?; Ok(())
    }
    async fn read_message(&mut self)->Result<serde_json::Value>{
        use tokio::io::{AsyncBufReadExt,AsyncReadExt}; let mut content_length=None;
        loop { let mut line=String::new(); let n=self.stdout.read_line(&mut line).await?; if n==0{return Err(anyhow::anyhow!("LSP server closed stdout"));}
            if line=="\r\n"||line=="\n"{break;}
            if let Some(value)=line.to_ascii_lowercase().strip_prefix("content-length:"){content_length=Some(value.trim().parse::<usize>()?);} }
        let len=content_length.context("LSP response missing Content-Length")?; let mut body=vec![0u8;len]; self.stdout.read_exact(&mut body).await?; Ok(serde_json::from_slice(&body)?)
    }
    async fn wait_response(&mut self,id:u64,timeout:std::time::Duration)->Result<serde_json::Value>{
        tokio::time::timeout(timeout,async {
            loop {
                let message=self.read_message().await?;
                if message.get("id").and_then(|v|v.as_u64())==Some(id) && message.get("method").is_none() {
                    return Ok::<_,anyhow::Error>(message);
                }
                // Language servers may ask the client for configuration or dynamic registration
                // while an initialize/documentSymbol request is outstanding. v0.8 has no mutable
                // editor configuration surface, so acknowledge these deterministically rather than
                // ignoring them and risking an otherwise healthy adapter timing out.
                if let (Some(request_id),Some(method))=(message.get("id").cloned(),message.get("method").and_then(|v|v.as_str())) {
                    let result=match method {
                        "workspace/configuration" => serde_json::json!([]),
                        "workspace/workspaceFolders" => serde_json::json!([]),
                        "client/registerCapability" | "client/unregisterCapability" | "window/workDoneProgress/create" => serde_json::Value::Null,
                        _ => serde_json::Value::Null,
                    };
                    self.send(serde_json::json!({"jsonrpc":"2.0","id":request_id,"result":result})).await?;
                }
            }
        }).await.context("LSP request timed out")?
    }
    async fn document_symbols(&mut self,path:&Path,logical_path:&str,language_id:&str,text:&str,language:SourceLanguage,timeout:std::time::Duration)->Result<Vec<SymbolRecord>>{
        let uri=url::Url::from_file_path(path).map_err(|_|anyhow::anyhow!("source path cannot be represented as file URI"))?.to_string();
        self.send(serde_json::json!({"jsonrpc":"2.0","method":"textDocument/didOpen","params":{"textDocument":{"uri":uri,"languageId":language_id,"version":1,"text":text}}})).await?;
        let id=self.next_request_id(); self.send(json_rpc_request(id,"textDocument/documentSymbol",serde_json::json!({"textDocument":{"uri":uri}}))).await?; let response=self.wait_response(id,timeout).await?;
        let mut out=Vec::new(); if let Some(result)=response.get("result"){flatten_lsp_symbols(result,logical_path,language,None,&mut out);}
        self.send(serde_json::json!({"jsonrpc":"2.0","method":"textDocument/didClose","params":{"textDocument":{"uri":uri}}})).await?; Ok(out)
    }
    async fn shutdown(&mut self,timeout:std::time::Duration)->Result<()>{ let id=self.next_request_id(); self.send(json_rpc_request(id,"shutdown",serde_json::Value::Null)).await?; let _=self.wait_response(id,timeout).await; let _=self.send(serde_json::json!({"jsonrpc":"2.0","method":"exit","params":null})).await; if tokio::time::timeout(timeout,self.child.wait()).await.is_err(){let _=self.child.kill().await;} Ok(()) }
}
fn json_rpc_request(id:u64,method:&str,params:serde_json::Value)->serde_json::Value{serde_json::json!({"jsonrpc":"2.0","id":id,"method":method,"params":params})}
fn flatten_lsp_symbols(value:&serde_json::Value,path:&str,language:SourceLanguage,container:Option<String>,out:&mut Vec<SymbolRecord>){
    let Some(items)=value.as_array() else{return;}; for item in items { let Some(name)=item.get("name").and_then(|v|v.as_str()) else{continue;}; let range=item.get("range").or_else(||item.get("location").and_then(|l|l.get("range"))); let start=range.and_then(|r|r.get("start")); let end=range.and_then(|r|r.get("end")); let sl=start.and_then(|p|p.get("line")).and_then(|v|v.as_u64()).unwrap_or(0) as u32+1; let sc=start.and_then(|p|p.get("character")).and_then(|v|v.as_u64()).unwrap_or(0) as u32+1; let el=end.and_then(|p|p.get("line")).and_then(|v|v.as_u64()).unwrap_or(sl.saturating_sub(1) as u64) as u32+1; let ec=end.and_then(|p|p.get("character")).and_then(|v|v.as_u64()).unwrap_or(0) as u32+1;
        let kind=lsp_symbol_kind(item.get("kind").and_then(|v|v.as_u64()).unwrap_or(0));
        out.push(SymbolRecord{symbol_id:Digest::from_bytes(format!("native\0{path}\0{sl}\0{sc}\0{name}").as_bytes()).0,name:name.into(),kind,path:path.to_owned(),language,start_line:sl,start_column:sc,end_line:el,end_column:ec,container:container.clone(),source:"native_lsp".into()});
        if let Some(children)=item.get("children"){flatten_lsp_symbols(children,path,language,Some(name.into()),out);}
    }
}
fn lsp_symbol_kind(kind:u64)->SymbolKind{match kind{2=>SymbolKind::Module,3=>SymbolKind::Namespace,5=>SymbolKind::Class,6=>SymbolKind::Method,7=>SymbolKind::Property,8=>SymbolKind::Field,10=>SymbolKind::Enum,11=>SymbolKind::Interface,12=>SymbolKind::Function,13=>SymbolKind::Variable,14=>SymbolKind::Constant,22=>SymbolKind::Enum,23=>SymbolKind::Struct,_=>SymbolKind::Unknown}}

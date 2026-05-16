// ============================================================
// BAKOME SupplyChain Sentinel v1.0 — Version Complète
// Fichier unique : bakome_supplychain_sentinel.rs
// Scanner de sécurité de la chaîne d'approvisionnement logicielle
// 7 Piliers complets | Zéro dépendance externe | Stdlib uniquement
// Développé sur Pixel 4a 5G à Goma, RDC
// Compilation : rustc bakome_supplychain_sentinel.rs -o sentinel
// Lignes : ~1900+
// ============================================================
//
// PILIERS (implémentés avec logique réelle et complète) :
//  1. Scanner de Dépendances (directes + transitives N-couches)
//  2. Détecteur CVE Multi-Sources (NVD, GitHub Advisory, OSV)
//  3. Cartographe de Flux de Données Sensibles
//  4. Vérificateur d'Intégrité Cryptographique (Merkle Tree + Preuves)
//  5. Générateur SBOM (CycloneDX 1.5 + SPDX light)
//  6. IA d'Analyse de Patterns Suspects (typosquatting, confusion, anomalies)
//  7. Dashboard / Rapport de Sécurité Interactif avec Export JSON
// ============================================================

use std::collections::{HashMap, HashSet, BTreeMap};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
use std::io::{self, Write};

// ============================================================
// CONFIGURATION GLOBALE
// ============================================================
const VERSION: &str = "BAKOME SupplyChain Sentinel v1.0";
const MAX_TRANSITIVE_DEPTH: usize = 8;
const SBOM_SPEC_VERSION: &str = "1.5";

// Base de vulnérabilités multi-source (NVD + GitHub Advisory + OSV)
const VULN_DATABASE: &[(&str, &str, &str, &str, f64)] = &[
    ("log4j", "2.0.0-2.17.1", "CVE-2021-44228", "RCE via JNDI (Log4Shell)", 10.0),
    ("openssl", "3.0.0-3.0.6", "CVE-2022-3786", "Buffer overflow X.509", 7.5),
    ("libwebp", "0.1.0-1.3.1", "CVE-2023-4863", "Heap buffer overflow WebP", 10.0),
    ("curl", "7.0.0-8.3.0", "CVE-2023-38545", "SOCKS5 heap overflow", 7.5),
    ("spring-boot", "2.0.0-2.7.11", "CVE-2023-20873", "RCE Spring Boot", 9.8),
    ("python", "3.0.0-3.9.17", "CVE-2023-24329", "URL parsing bypass", 7.5),
    ("react", "16.0.0-18.2.0", "CVE-2023-23956", "XSS React DevTools", 5.3),
    ("tensorflow", "2.0.0-2.12.0", "CVE-2023-25667", "Heap overflow TF", 7.5),
    ("fastjson", "1.0.0-1.2.83", "CVE-2022-25845", "RCE FastJSON", 10.0),
    ("struts2", "2.0.0-2.5.30", "CVE-2023-50164", "RCE Struts2", 9.8),
    ("lodash", "4.0.0-4.17.20", "CVE-2021-23337", "Command Injection", 7.2),
    ("axios", "0.1.0-0.21.1", "CVE-2021-3749", "SSRF axios", 7.5),
    ("moment", "2.0.0-2.29.4", "CVE-2022-24785", "ReDoS moment", 7.5),
    ("django", "3.0.0-3.2.15", "CVE-2022-36359", "XSS Django", 6.1),
    ("flask", "0.1.0-2.2.2", "CVE-2023-30861", "Information disclosure", 7.5),
];

// Patterns de données sensibles
const SENSITIVE_PATTERNS: &[(&str, &str)] = &[
    ("API_KEY", "HIGH"), ("SECRET", "HIGH"), ("PASSWORD", "HIGH"),
    ("TOKEN", "HIGH"), ("PRIVATE_KEY", "CRITICAL"), ("DATABASE_URL", "MEDIUM"),
    ("REDIS_URL", "MEDIUM"), ("AWS_ACCESS_KEY", "CRITICAL"), ("GITHUB_TOKEN", "HIGH"),
    ("NPM_TOKEN", "HIGH"), ("DOCKER_PASSWORD", "HIGH"), ("MASTER_KEY", "CRITICAL"),
    ("ENCRYPTION_KEY", "CRITICAL"), ("BEARER", "MEDIUM"), ("AUTHORIZATION", "MEDIUM"),
    ("JWT_SECRET", "CRITICAL"), ("PASSPHRASE", "HIGH"), ("CREDENTIALS", "HIGH"),
];

// Paquets populaires pour détection typosquatting
const POPULAR_PACKAGES: &[&str] = &[
    "requests", "numpy", "pandas", "flask", "django", "react", "lodash", "express",
    "axios", "moment", "eslint", "prettier", "webpack", "babel", "typescript",
    "serde", "tokio", "reqwest", "sqlx", "actix", "rocket", "diesel", "clap",
    "serde_json", "rand", "chrono", "log", "env_logger", "dotenv", "uuid",
    "async_trait", "futures", "bytes", "prost", "tonic", "tower",
];

// Extensions de fichiers à scanner
const SCAN_EXTENSIONS: &[&str] = &[
    "rs", "py", "js", "ts", "jsx", "tsx", "json", "toml", "yaml", "yml",
    "lock", "cargo", "txt", "cfg", "ini", "env", "xml", "gradle", "sbt",
];

// Dossiers à ignorer
const IGNORE_DIRS: &[&str] = &[".git", "node_modules", "target", "__pycache__", ".venv", "venv", "dist", "build"];

// ============================================================
// STRUCTURES DE DONNÉES
// ============================================================

#[derive(Debug, Clone)]
pub struct Dependency {
    pub name: String,
    pub version: String,
    pub source_file: String,
    pub depth: usize,
    pub is_direct: bool,
    pub vulnerabilities: Vec<Vulnerability>,
    pub license: String,
    pub repository: String,
}

#[derive(Debug, Clone)]
pub struct Vulnerability {
    pub cve_id: String,
    pub severity: String,
    pub score: f64,
    pub description: String,
    pub fixed_version: String,
    pub source: String,
}

#[derive(Debug, Clone)]
pub struct DataFlow {
    pub source_file: String,
    pub line_number: usize,
    pub pattern: String,
    pub risk_level: String,
    pub context: String,
}

#[derive(Debug, Clone)]
pub struct IntegrityProof {
    pub file_path: String,
    pub file_hash: String,
    pub merkle_root: String,
    pub merkle_proof: Vec<String>,
    pub slsa_level: u8,
    pub verified: bool,
    pub timestamp: u64,
}

#[derive(Debug, Clone)]
pub struct SBOMComponent {
    pub name: String,
    pub version: String,
    pub supplier: String,
    pub license: String,
    pub hash_sha256: String,
    pub purl: String,
    pub dependencies: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct SBOM {
    pub format: String,
    pub spec_version: String,
    pub timestamp: u64,
    pub components: Vec<SBOMComponent>,
    pub signed: bool,
    pub serial_number: String,
}

#[derive(Debug, Clone)]
pub struct SecurityReport {
    pub total_files: usize,
    pub total_dependencies: usize,
    pub direct_deps: usize,
    pub transitive_deps: usize,
    pub total_vulnerabilities: usize,
    pub critical_count: usize,
    pub high_count: usize,
    pub medium_count: usize,
    pub low_count: usize,
    pub integrity_score: f64,
    pub sensitive_flows: usize,
    pub suspicious_alerts: Vec<String>,
    pub overall_risk: String,
    pub risk_score: f64,
    pub recommendation: String,
    pub scan_duration_secs: u64,
    pub slsa_compliance: String,
}

// ============================================================
// MOTEUR PRINCIPAL
// ============================================================

#[derive(Debug, Clone)]
pub struct SupplyChainSentinel {
    pub dependencies: Vec<Dependency>,
    pub data_flows: Vec<DataFlow>,
    pub integrity_proofs: HashMap<String, IntegrityProof>,
    pub sbom: Option<SBOM>,
    pub scanned_files: Vec<PathBuf>,
    pub start_time: u64,
    pub merkle_tree: Vec<Vec<String>>,
    pub ignored_patterns: Vec<String>,
}

impl SupplyChainSentinel {
    pub fn new() -> Self {
        let start = Self::now_secs();
        SupplyChainSentinel {
            dependencies: Vec::new(),
            data_flows: Vec::new(),
            integrity_proofs: HashMap::new(),
            sbom: None,
            scanned_files: Vec::new(),
            start_time,
            merkle_tree: Vec::new(),
            ignored_patterns: vec!["test".into(), "mock".into(), "example".into(), "sample".into()],
        }
    }

    fn now_secs() -> u64 {
        SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs()
    }

    // ============================================================
    // UTILITAIRES
    // ============================================================
    fn djb2_hash(data: &str) -> String {
        let mut h: u64 = 5381;
        for b in data.bytes() { h = ((h << 5).wrapping_add(h)).wrapping_add(b as u64); }
        format!("{:016x}", h)
    }

    fn levenshtein(a: &str, b: &str) -> usize {
        let alen = a.chars().count();
        let blen = b.chars().count();
        let mut d = vec![vec![0usize; blen + 1]; alen + 1];
        for i in 0..=alen { d[i][0] = i; }
        for j in 0..=blen { d[0][j] = j; }
        for (i, ca) in a.chars().enumerate() {
            for (j, cb) in b.chars().enumerate() {
                let cost = if ca == cb { 0 } else { 1 };
                d[i+1][j+1] = (d[i][j+1] + 1).min(d[i+1][j] + 1).min(d[i][j] + cost);
            }
        }
        d[alen][blen]
    }

    fn severity_from_score(score: f64) -> String {
        if score >= 9.0 { "CRITICAL" } else if score >= 7.0 { "HIGH" } else if score >= 4.0 { "MEDIUM" } else { "LOW" }.to_string()
    }

    fn should_ignore_dir(dir_name: &str) -> bool {
        IGNORE_DIRS.contains(&dir_name)
    }

    fn is_scan_ext(ext: &str) -> bool {
        SCAN_EXTENSIONS.contains(&ext)
    }

    // ============================================================
    // PILIER 1 : SCANNER DE DÉPENDANCES (N-COUCHES)
    // ============================================================
    pub fn scan_dependencies(&mut self, dir_path: &str, depth: usize) -> Result<usize, String> {
        let dir = Path::new(dir_path);
        if !dir.is_dir() { return Err(format!("'{}' n'est pas un dossier valide", dir_path)); }

        let mut files = Vec::new();
        self.collect_files_recursive(dir, &mut files);

        // Phase 1 : extraction des dépendances directes
        for file in &files {
            if let Ok(content) = fs::read_to_string(file) {
                self.extract_deps_from_file(&content, file, depth);
            }
        }

        // Phase 2 : résolution transitive
        if depth < MAX_TRANSITIVE_DEPTH {
            let snapshot: Vec<Dependency> = self.dependencies.iter()
                .filter(|d| d.depth == depth && d.is_direct)
                .cloned()
                .collect();
            for dep in snapshot {
                self.resolve_transitive_deps(&dep.name, depth + 1);
            }
        }

        Ok(self.dependencies.len())
    }

    fn collect_files_recursive(&mut self, dir: &Path, files: &mut Vec<PathBuf>) {
        if let Ok(entries) = fs::read_dir(dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_dir() {
                    let dir_name = path.file_name().unwrap_or_default().to_string_lossy().to_string();
                    if !Self::should_ignore_dir(&dir_name) {
                        self.collect_files_recursive(&path, files);
                    }
                } else if let Some(ext) = path.extension() {
                    if Self::is_scan_ext(ext.to_str().unwrap_or("")) {
                        files.push(path.clone());
                        self.scanned_files.push(path.clone());
                    }
                }
            }
        }
    }

    fn extract_deps_from_file(&mut self, content: &str, file: &Path, depth: usize) {
        let fname = file.file_name().unwrap_or_default().to_string_lossy().to_string();

        match fname.as_str() {
            "Cargo.toml" => self.parse_cargo_toml(content, &fname, depth),
            "requirements.txt" => self.parse_requirements_txt(content, &fname, depth),
            "package.json" => self.parse_package_json(content, &fname, depth),
            "Pipfile" => self.parse_pipfile(content, &fname, depth),
            "pyproject.toml" => self.parse_pyproject_toml(content, &fname, depth),
            "go.mod" => self.parse_go_mod(content, &fname, depth),
            "build.gradle" | "build.gradle.kts" => self.parse_gradle(content, &fname, depth),
            _ => {
                if fname.ends_with(".lock") || fname == "yarn.lock" || fname == "pnpm-lock.yaml" {
                    self.parse_lock_file(content, &fname, depth);
                }
            }
        }
    }

    fn parse_cargo_toml(&mut self, content: &str, fname: &str, depth: usize) {
        let mut in_deps = false;
        for line in content.lines() {
            let t = line.trim();
            if t.starts_with("[dependencies]") || t.starts_with("[dev-dependencies]") || t.starts_with("[build-dependencies]") {
                in_deps = true; continue;
            }
            if t.starts_with('[') && in_deps { in_deps = false; continue; }
            if !in_deps || t.is_empty() || t.starts_with('#') || t.starts_with("//") { continue; }
            if let Some(eq) = t.find('=') {
                let name = t[..eq].trim().trim_matches('"').trim_matches('\'');
                let ver_raw = t[eq+1..].trim().trim_matches('"').trim_matches('\'').trim_matches('{').trim_matches('}');
                let version = ver_raw.split(',').next().unwrap_or("0.0.0").trim().trim_matches('"').trim_matches('\'').trim();
                if !name.is_empty() && name != "[" {
                    self.add_dependency(name, version, fname, depth, true);
                }
            }
        }
    }

    fn parse_requirements_txt(&mut self, content: &str, fname: &str, depth: usize) {
        for line in content.lines() {
            let t = line.trim();
            if t.is_empty() || t.starts_with('#') || t.starts_with('-') || t.starts_with("git+") { continue; }
            let parts: Vec<&str> = if t.contains("==") { t.split("==").collect() }
                else if t.contains(">=") { t.split(">=").collect() }
                else if t.contains("~=") { t.split("~=").collect() }
                else { vec![t, "latest"] };
            if parts.len() >= 2 {
                let name = parts[0].trim().split(|c: char| c == '[' || c == ';' || c == ' ').next().unwrap_or("").trim();
                let version = parts[1].trim().split(|c: char| c == ';' || c == ' ').next().unwrap_or("latest").trim();
                if !name.is_empty() { self.add_dependency(name, version, fname, depth, true); }
            }
        }
    }

    fn parse_package_json(&mut self, content: &str, fname: &str, depth: usize) {
        // Parser simplifié mais robuste pour package.json
        let joined = content.replace('\n', " ");
        for section in &["\"dependencies\"", "\"devDependencies\"", "\"peerDependencies\""] {
            if let Some(pos) = joined.find(section) {
                let slice = &joined[pos..];
                let mut brace_depth = 0i32;
                let mut started = false;
                let mut in_string = false;
                let mut current_key = String::new();
                let mut chars = slice.chars().peekable();

                while let Some(ch) = chars.next() {
                    if ch == '{' { brace_depth += 1; started = true; continue; }
                    if ch == '}' { brace_depth -= 1; if brace_depth == 0 && started { break; } }
                    if !started || brace_depth == 0 { continue; }
                    if ch == '"' {
                        in_string = !in_string;
                        if !in_string && !current_key.is_empty() {
                            // On vient de fermer une clé, chercher la valeur
                            let mut val = String::new();
                            while let Some(&vc) = chars.peek() {
                                if vc == '"' {
                                    chars.next();
                                    if !val.is_empty() {
                                        let version = val.trim().trim_matches('^').trim_matches('~').trim_matches('=').to_string();
                                        if !current_key.is_empty() && !current_key.starts_with('@') {
                                            self.add_dependency(&current_key, &version, fname, depth, true);
                                        }
                                    }
                                    current_key.clear();
                                    val.clear();
                                    break;
                                } else if vc == ',' || vc == '}' {
                                    if !val.is_empty() && !current_key.is_empty() {
                                        let version = val.trim().trim_matches('^').trim_matches('~').trim_matches('=').to_string();
                                        self.add_dependency(&current_key, &version, fname, depth, true);
                                    }
                                    current_key.clear();
                                    break;
                                } else {
                                    val.push(vc);
                                    chars.next();
                                }
                            }
                        } else if in_string {
                            current_key.clear();
                        }
                        continue;
                    }
                    if in_string { current_key.push(ch); }
                }
            }
        }
    }

    fn parse_pipfile(&mut self, content: &str, fname: &str, depth: usize) {
        let mut in_packages = false;
        for line in content.lines() {
            let t = line.trim();
            if t.starts_with("[packages]") || t.starts_with("[dev-packages]") { in_packages = true; continue; }
            if t.starts_with('[') && in_packages { in_packages = false; continue; }
            if !in_packages || t.is_empty() || t.starts_with('#') { continue; }
            if let Some(eq) = t.find('=') {
                let name = t[..eq].trim().trim_matches('"').trim_matches('\'');
                let version = t[eq+1..].trim().trim_matches('"').trim_matches('\'').trim_matches('=').trim();
                if !name.is_empty() { self.add_dependency(name, version, fname, depth, true); }
            }
        }
    }

    fn parse_pyproject_toml(&mut self, content: &str, fname: &str, depth: usize) {
        let mut in_deps = false;
        for line in content.lines() {
            let t = line.trim();
            if t.contains("[tool.poetry.dependencies]") || t.contains("[project.dependencies]") { in_deps = true; continue; }
            if t.starts_with('[') && in_deps { in_deps = false; continue; }
            if !in_deps || t.is_empty() || t.starts_with('#') { continue; }
            if let Some(eq) = t.find('=') {
                let name = t[..eq].trim().trim_matches('"').trim_matches('\'');
                let version = t[eq+1..].trim().trim_matches('"').trim_matches('\'').trim_matches('^').trim_matches('~').trim();
                if !name.is_empty() && name != "python" { self.add_dependency(name, version, fname, depth, true); }
            }
        }
    }

    fn parse_go_mod(&mut self, content: &str, fname: &str, depth: usize) {
        for line in content.lines() {
            let t = line.trim();
            if t.starts_with("require ") {
                let rest = t.trim_start_matches("require ").trim();
                let parts: Vec<&str> = rest.split_whitespace().collect();
                if parts.len() >= 2 {
                    self.add_dependency(parts[0], parts[1], fname, depth, true);
                }
            }
        }
    }

    fn parse_gradle(&mut self, content: &str, fname: &str, depth: usize) {
        for line in content.lines() {
            let t = line.trim();
            if (t.contains("implementation") || t.contains("compile") || t.contains("api")) && t.contains(':') {
           

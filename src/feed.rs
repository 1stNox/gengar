//! The vulnerability feed: Arch Linux Security Tracker JSON (`all.json`),
//! cached on disk and refreshed with conditional HTTP requests.

use crate::util::{cache_dir, now_secs, write_atomic};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::time::Duration;

/// One "Arch Vulnerability Group" (AVG) from the tracker.
#[derive(Debug, Clone, Deserialize)]
pub struct Avg {
    pub name: String,
    #[serde(default)]
    pub packages: Vec<String>,
    #[serde(default)]
    pub status: String,
    #[serde(default)]
    pub severity: String,
    #[serde(rename = "type", default)]
    pub kind: String,
    #[serde(default)]
    pub fixed: Option<String>,
    #[serde(default)]
    pub issues: Vec<String>,
    #[serde(default)]
    pub advisories: Vec<String>,
}

/// How to obtain the feed for this scan.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FetchPolicy {
    /// Use the cache; download only when there is no cache at all.
    Offline,
    /// Revalidate the cache when it is older than this many seconds.
    MaxAge(u64),
}

/// Where the feed came from and how fresh it is.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FeedInfo {
    pub source: String,
    /// Unix time the feed was last downloaded or confirmed unchanged.
    pub updated_at: Option<u64>,
    pub groups: usize,
    /// Set when refreshing failed and an older cached copy was used.
    pub error: Option<String>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct CacheMeta {
    url: String,
    etag: Option<String>,
    last_modified: Option<String>,
    checked_at: u64,
}

pub fn parse(bytes: &[u8]) -> Result<Vec<Avg>, String> {
    serde_json::from_slice(bytes).map_err(|e| format!("invalid feed JSON: {e}"))
}

fn is_url(source: &str) -> bool {
    source.starts_with("https://") || source.starts_with("http://")
}

fn cache_paths() -> (PathBuf, PathBuf) {
    let dir = cache_dir();
    (dir.join("feed.json"), dir.join("feed.meta.json"))
}

/// Load the feed from a URL (with caching) or a local file.
pub fn load(source: &str, policy: FetchPolicy) -> Result<(Vec<Avg>, FeedInfo), String> {
    if !is_url(source) {
        return load_file(Path::new(source.strip_prefix("file://").unwrap_or(source)));
    }
    let (data_path, meta_path) = cache_paths();
    let mut meta: Option<CacheMeta> = std::fs::read(&meta_path)
        .ok()
        .and_then(|b| serde_json::from_slice(&b).ok())
        .filter(|m: &CacheMeta| m.url == source && data_path.exists());

    let age = meta.as_ref().map(|m| now_secs().saturating_sub(m.checked_at));
    let need_fetch = match (policy, age) {
        (_, None) => true,
        (FetchPolicy::Offline, Some(_)) => false,
        (FetchPolicy::MaxAge(max), Some(age)) => age >= max,
    };

    let mut error = None;
    if need_fetch {
        match fetch(source, meta.as_ref(), &data_path) {
            Ok(new_meta) => {
                let _ = write_atomic(&meta_path, &serde_json::to_vec(&new_meta).unwrap_or_default());
                meta = Some(new_meta);
            }
            Err(e) => error = Some(e),
        }
    }

    let Some(meta) = meta else {
        return Err(error.unwrap_or_else(|| "no vulnerability feed available".to_string()));
    };
    let bytes = std::fs::read(&data_path).map_err(|e| format!("cannot read cached feed: {e}"))?;
    let avgs = parse(&bytes)?;
    let info = FeedInfo {
        source: source.to_string(),
        updated_at: Some(meta.checked_at),
        groups: avgs.len(),
        error,
    };
    Ok((avgs, info))
}

fn load_file(path: &Path) -> Result<(Vec<Avg>, FeedInfo), String> {
    let bytes = std::fs::read(path).map_err(|e| format!("cannot read feed {}: {e}", path.display()))?;
    let avgs = parse(&bytes)?;
    let updated_at = std::fs::metadata(path)
        .and_then(|m| m.modified())
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_secs());
    let info = FeedInfo {
        source: path.display().to_string(),
        updated_at,
        groups: avgs.len(),
        error: None,
    };
    Ok((avgs, info))
}

/// Conditional GET; on 200 the body is validated and written to `data_path`.
fn fetch(url: &str, old: Option<&CacheMeta>, data_path: &Path) -> Result<CacheMeta, String> {
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .timeout_global(Some(Duration::from_secs(90)))
        .http_status_as_error(false)
        .user_agent(concat!("gengar/", env!("CARGO_PKG_VERSION")))
        .build()
        .into();

    let mut req = agent.get(url);
    if let Some(m) = old {
        if let Some(etag) = &m.etag {
            req = req.header("If-None-Match", etag);
        }
        if let Some(lm) = &m.last_modified {
            req = req.header("If-Modified-Since", lm);
        }
    }
    let mut resp = req.call().map_err(|e| format!("feed download failed: {e}"))?;
    let status = resp.status().as_u16();
    let header = |name: &str| {
        resp.headers()
            .get(name)
            .and_then(|v| v.to_str().ok())
            .map(str::to_string)
    };

    if status == 304 {
        if let Some(m) = old {
            return Ok(CacheMeta {
                url: url.to_string(),
                etag: header("etag").or_else(|| m.etag.clone()),
                last_modified: header("last-modified").or_else(|| m.last_modified.clone()),
                checked_at: now_secs(),
            });
        }
    }
    if status != 200 {
        return Err(format!("feed download failed: HTTP {status}"));
    }
    let etag = header("etag");
    let last_modified = header("last-modified");
    let body = resp
        .body_mut()
        .with_config()
        .limit(128 * 1024 * 1024)
        .read_to_vec()
        .map_err(|e| format!("feed download failed: {e}"))?;
    parse(&body)?; // never replace a good cache with garbage
    write_atomic(data_path, &body).map_err(|e| format!("cannot write feed cache: {e}"))?;
    Ok(CacheMeta { url: url.to_string(), etag, last_modified, checked_at: now_secs() })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_tracker_fixture() {
        let bytes = std::fs::read(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/all.json")).unwrap();
        let avgs = parse(&bytes).unwrap();
        assert!(avgs.len() >= 5);
        let first = &avgs[0];
        assert!(first.name.starts_with("AVG-"));
        assert!(!first.packages.is_empty());
        assert!(avgs.iter().any(|a| a.fixed.is_none()));
    }

    #[test]
    fn tolerates_missing_optional_fields() {
        let avgs = parse(br#"[{"name":"AVG-1","packages":["x"]}]"#).unwrap();
        assert_eq!(avgs[0].fixed, None);
        assert!(avgs[0].issues.is_empty());
    }

    #[test]
    fn file_source() {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/all.json");
        let (avgs, info) = load(path, FetchPolicy::Offline).unwrap();
        assert_eq!(info.groups, avgs.len());
        assert!(info.updated_at.is_some());
        assert!(info.error.is_none());
    }
}

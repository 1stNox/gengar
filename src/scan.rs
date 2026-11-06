//! Matching installed packages against the vulnerability feed.

use crate::config::Config;
use crate::feed::{Avg, FeedInfo};
use crate::pacman::Installed;
use crate::util::now_secs;
use crate::vercmp::vercmp;
use serde::{Deserialize, Serialize};
use std::cmp::Ordering;
use std::collections::{BTreeMap, HashMap};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "&'static str")]
pub enum Severity {
    Unknown,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub const ALL_DESC: [Severity; 5] =
        [Severity::Critical, Severity::High, Severity::Medium, Severity::Low, Severity::Unknown];

    pub fn as_str(self) -> &'static str {
        match self {
            Severity::Unknown => "Unknown",
            Severity::Low => "Low",
            Severity::Medium => "Medium",
            Severity::High => "High",
            Severity::Critical => "Critical",
        }
    }

    /// Lenient parsing for feed data: anything unrecognised is `Unknown`.
    pub fn from_feed(s: &str) -> Severity {
        Severity::try_from(s.to_string()).unwrap_or(Severity::Unknown)
    }
}

impl TryFrom<String> for Severity {
    type Error = String;
    fn try_from(s: String) -> Result<Self, Self::Error> {
        match s.trim().to_ascii_lowercase().as_str() {
            "unknown" => Ok(Severity::Unknown),
            "low" => Ok(Severity::Low),
            "medium" => Ok(Severity::Medium),
            "high" => Ok(Severity::High),
            "critical" => Ok(Severity::Critical),
            _ => Err(format!("unknown severity {s:?} (use low, medium, high or critical)")),
        }
    }
}

impl From<Severity> for &'static str {
    fn from(s: Severity) -> Self {
        s.as_str()
    }
}

/// One advisory group affecting one installed package.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Issue {
    pub avg: String,
    pub severity: Severity,
    pub kind: String,
    pub status: String,
    pub fixed: Option<String>,
    pub cves: Vec<String>,
    pub advisories: Vec<String>,
    /// Acknowledged via the `ignore` config list.
    pub ignored: bool,
}

/// An installed package with one or more known vulnerabilities.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub package: String,
    pub installed: String,
    pub foreign: bool,
    /// Highest severity among the issues that are not ignored.
    pub severity: Severity,
    /// Version that fixes every (non-ignored) issue, if all of them have a fix.
    pub fixed_in: Option<String>,
    /// At least one non-ignored issue is at or above the alert threshold.
    pub alert: bool,
    /// Every issue of this package is ignored.
    pub ignored: bool,
    pub issues: Vec<Issue>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanReport {
    pub scanned_at: u64,
    pub packages_scanned: usize,
    pub alert_severity: Severity,
    pub feed: FeedInfo,
    /// The feed could not be refreshed for longer than `stale_after_days`.
    pub stale: bool,
    pub findings: Vec<Finding>,
}

impl ScanReport {
    /// Findings that are not fully ignored.
    pub fn active(&self) -> impl Iterator<Item = &Finding> {
        self.findings.iter().filter(|f| !f.ignored)
    }

    pub fn alert_findings(&self) -> impl Iterator<Item = &Finding> {
        self.findings.iter().filter(|f| f.alert)
    }

    pub fn has_alert(&self) -> bool {
        self.findings.iter().any(|f| f.alert)
    }

    /// Number of affected packages per severity (ignored ones excluded).
    pub fn counts(&self) -> BTreeMap<Severity, usize> {
        let mut m = BTreeMap::new();
        for f in self.active() {
            *m.entry(f.severity).or_insert(0) += 1;
        }
        m
    }

    /// "3 vulnerable packages (1 Critical, 2 High)".
    pub fn summary(&self) -> String {
        let n = self.active().count();
        if n == 0 {
            return "No known vulnerabilities".to_string();
        }
        let counts = self.counts();
        let parts: Vec<String> = Severity::ALL_DESC
            .iter()
            .filter_map(|s| counts.get(s).map(|c| format!("{c} {}", s.as_str())))
            .collect();
        let noun = if n == 1 { "package" } else { "packages" };
        format!("{n} vulnerable {noun} ({})", parts.join(", "))
    }

    /// Stable keys (`AVG:package`) of every alert-level issue, used to
    /// notify only about issues that were not seen before.
    pub fn alert_keys(&self) -> Vec<String> {
        let mut keys = Vec::new();
        for f in self.alert_findings() {
            for i in &f.issues {
                if !i.ignored && i.severity >= self.alert_severity {
                    keys.push(format!("{}:{}", i.avg, f.package));
                }
            }
        }
        keys.sort();
        keys.dedup();
        keys
    }
}

fn is_ignored(cfg: &Config, pkg: &str, avg: &Avg) -> bool {
    cfg.ignore.iter().any(|ig| {
        let ig = ig.trim();
        ig == pkg || ig.eq_ignore_ascii_case(&avg.name) || avg.issues.iter().any(|c| ig.eq_ignore_ascii_case(c))
    })
}

/// Is `installed` affected by this advisory group?
pub fn is_vulnerable(avg: &Avg, installed: &str) -> bool {
    let status = avg.status.to_ascii_lowercase();
    if status == "not affected" {
        return false;
    }
    match avg.fixed.as_deref().map(str::trim).filter(|f| !f.is_empty()) {
        Some(fixed) => vercmp(installed, fixed) == Ordering::Less,
        // "Fixed" without a fixed version is inconsistent data: don't guess.
        None => status != "fixed",
    }
}

pub fn scan(installed: &[Installed], avgs: &[Avg], cfg: &Config, feed: FeedInfo) -> ScanReport {
    let by_name: HashMap<&str, &Installed> = installed.iter().map(|p| (p.name.as_str(), p)).collect();
    let mut issues: BTreeMap<&str, Vec<Issue>> = BTreeMap::new();

    for avg in avgs {
        for pkg in &avg.packages {
            let Some(inst) = by_name.get(pkg.as_str()) else { continue };
            if !is_vulnerable(avg, &inst.version) {
                continue;
            }
            let list = issues.entry(inst.name.as_str()).or_default();
            if list.iter().any(|i| i.avg == avg.name) {
                continue;
            }
            list.push(Issue {
                avg: avg.name.clone(),
                severity: Severity::from_feed(&avg.severity),
                kind: avg.kind.clone(),
                status: avg.status.clone(),
                fixed: avg.fixed.clone().filter(|f| !f.trim().is_empty()),
                cves: avg.issues.clone(),
                advisories: avg.advisories.clone(),
                ignored: is_ignored(cfg, pkg, avg),
            });
        }
    }

    let mut findings: Vec<Finding> = issues
        .into_iter()
        .map(|(name, mut list)| {
            let inst = by_name[name];
            list.sort_by(|a, b| b.severity.cmp(&a.severity).then_with(|| a.avg.cmp(&b.avg)));
            let ignored = list.iter().all(|i| i.ignored);
            let relevant: Vec<&Issue> = list.iter().filter(|i| ignored || !i.ignored).collect();
            let severity = relevant.iter().map(|i| i.severity).max().unwrap_or(Severity::Unknown);
            let fixed_in = if relevant.iter().all(|i| i.fixed.is_some()) {
                relevant
                    .iter()
                    .filter_map(|i| i.fixed.clone())
                    .max_by(|a, b| vercmp(a, b))
            } else {
                None
            };
            let alert = list.iter().any(|i| !i.ignored && i.severity >= cfg.alert_severity);
            Finding {
                package: inst.name.clone(),
                installed: inst.version.clone(),
                foreign: inst.foreign,
                severity,
                fixed_in,
                alert,
                ignored,
                issues: list,
            }
        })
        .collect();

    findings.sort_by(|a, b| {
        b.alert
            .cmp(&a.alert)
            .then_with(|| a.ignored.cmp(&b.ignored))
            .then_with(|| b.severity.cmp(&a.severity))
            .then_with(|| a.package.cmp(&b.package))
    });

    let stale = match feed.updated_at {
        Some(t) => now_secs().saturating_sub(t) > cfg.stale_secs(),
        None => true,
    };

    ScanReport {
        scanned_at: now_secs(),
        packages_scanned: installed.len(),
        alert_severity: cfg.alert_severity,
        feed,
        stale,
        findings,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn avg(name: &str, pkgs: &[&str], status: &str, sev: &str, fixed: Option<&str>) -> Avg {
        Avg {
            name: name.into(),
            packages: pkgs.iter().map(|s| s.to_string()).collect(),
            status: status.into(),
            severity: sev.into(),
            kind: "arbitrary code execution".into(),
            fixed: fixed.map(Into::into),
            issues: vec![format!("CVE-2026-{}", &name[4..])],
            advisories: vec![],
        }
    }

    fn pkg(name: &str, version: &str) -> Installed {
        Installed { name: name.into(), version: version.into(), foreign: false }
    }

    fn feed() -> FeedInfo {
        FeedInfo { source: "test".into(), updated_at: Some(now_secs()), groups: 0, error: None }
    }

    #[test]
    fn vulnerability_rules() {
        let a = avg("AVG-1", &["openssl"], "Fixed", "High", Some("3.0.8-1"));
        assert!(is_vulnerable(&a, "3.0.7-1"));
        assert!(!is_vulnerable(&a, "3.0.8-1"));
        assert!(!is_vulnerable(&a, "3.0.8-1.1")); // CachyOS rebuild of the fix
        assert!(!is_vulnerable(&a, "3.1.0-1"));
        let unfixed = avg("AVG-2", &["x"], "Vulnerable", "Low", None);
        assert!(is_vulnerable(&unfixed, "1.0-1"));
        let na = avg("AVG-3", &["x"], "Not affected", "High", None);
        assert!(!is_vulnerable(&na, "1.0-1"));
        let inconsistent = avg("AVG-4", &["x"], "Fixed", "High", None);
        assert!(!is_vulnerable(&inconsistent, "1.0-1"));
    }

    #[test]
    fn scan_groups_sorts_and_alerts() {
        let installed = vec![pkg("openssl", "3.0.7-1"), pkg("curl", "8.0.0-1"), pkg("zlib", "1:1.3-1"), pkg("vim", "9.0-1")];
        let avgs = vec![
            avg("AVG-10", &["openssl", "lib32-openssl"], "Fixed", "Critical", Some("3.0.8-1")),
            avg("AVG-11", &["openssl"], "Vulnerable", "Medium", None),
            avg("AVG-12", &["curl"], "Fixed", "Medium", Some("8.1.0-1")),
            avg("AVG-13", &["zlib"], "Fixed", "High", Some("1:1.2.13-1")), // already fixed
            avg("AVG-14", &["notinstalled"], "Vulnerable", "Critical", None),
        ];
        let r = scan(&installed, &avgs, &Config::default(), feed());
        assert_eq!(r.findings.len(), 2);
        let o = &r.findings[0];
        assert_eq!(o.package, "openssl");
        assert_eq!(o.severity, Severity::Critical);
        assert!(o.alert);
        assert_eq!(o.issues.len(), 2);
        assert_eq!(o.fixed_in, None, "one issue has no fix yet");
        let c = &r.findings[1];
        assert_eq!(c.package, "curl");
        assert!(!c.alert);
        assert_eq!(c.fixed_in.as_deref(), Some("8.1.0-1"));
        assert!(r.has_alert());
        assert_eq!(r.alert_keys(), vec!["AVG-10:openssl".to_string()]);
        assert_eq!(r.summary(), "2 vulnerable packages (1 Critical, 1 Medium)");
        assert!(!r.stale);
    }

    #[test]
    fn ignore_list() {
        let installed = vec![pkg("openssl", "3.0.7-1"), pkg("curl", "8.0.0-1")];
        let avgs = vec![
            avg("AVG-10", &["openssl"], "Fixed", "Critical", Some("3.0.8-1")),
            avg("AVG-11", &["openssl"], "Fixed", "Low", Some("3.0.9-1")),
            avg("AVG-12", &["curl"], "Fixed", "High", Some("8.1.0-1")),
        ];
        let cfg = Config { ignore: vec!["avg-10".into(), "curl".into()], ..Config::default() };
        let r = scan(&installed, &avgs, &cfg, feed());
        assert!(!r.has_alert());
        let o = r.findings.iter().find(|f| f.package == "openssl").unwrap();
        assert_eq!(o.severity, Severity::Low);
        assert!(!o.ignored);
        assert_eq!(o.fixed_in.as_deref(), Some("3.0.9-1"));
        let c = r.findings.iter().find(|f| f.package == "curl").unwrap();
        assert!(c.ignored);
        assert_eq!(r.active().count(), 1);

        // Ignoring by CVE ID works as well.
        let cfg = Config { ignore: vec!["CVE-2026-12".into()], ..Config::default() };
        let r = scan(&installed, &avgs, &cfg, feed());
        assert!(r.findings.iter().find(|f| f.package == "curl").unwrap().ignored);
    }

    #[test]
    fn threshold_and_staleness() {
        let installed = vec![pkg("curl", "8.0.0-1")];
        let avgs = vec![avg("AVG-12", &["curl"], "Fixed", "Medium", Some("8.1.0-1"))];
        let cfg = Config { alert_severity: Severity::Medium, ..Config::default() };
        let old = FeedInfo { updated_at: Some(now_secs() - 30 * 86400), ..feed() };
        let r = scan(&installed, &avgs, &cfg, old);
        assert!(r.has_alert());
        assert!(r.stale);
    }

    #[test]
    fn report_roundtrips_as_json() {
        let installed = vec![pkg("curl", "8.0.0-1")];
        let avgs = vec![avg("AVG-12", &["curl"], "Fixed", "High", Some("8.1.0-1"))];
        let r = scan(&installed, &avgs, &Config::default(), feed());
        let json = serde_json::to_string(&r).unwrap();
        assert!(json.contains("\"severity\":\"High\""));
        let back: ScanReport = serde_json::from_str(&json).unwrap();
        assert_eq!(back.findings[0].package, "curl");
        assert_eq!(back.alert_keys(), r.alert_keys());
    }
}

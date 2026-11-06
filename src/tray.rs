//! The system tray icon (freedesktop StatusNotifierItem over D-Bus).

use crate::config::Config;
use crate::scan::ScanReport;
use crate::util::{avg_url, cache_dir, fmt_age, fmt_time, open};
use ksni::menu::{StandardItem, SubMenu};
use ksni::{MenuItem, Status, ToolTip};
use std::path::{Path, PathBuf};
use std::sync::mpsc::Sender;

/// Requests from the tray menu to the scheduler.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Cmd {
    ScanNow,
    Quit,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Level {
    /// No vulnerable packages.
    Ok,
    /// Vulnerable packages below the alert threshold.
    Warning,
    /// At least one vulnerability at or above the alert threshold.
    Danger,
    /// No result yet, or the feed is outdated.
    Unknown,
}

/// Icon names for each level: Gengar's own icons when they are installed
/// (or available next to a source checkout), otherwise stock theme icons.
#[derive(Debug, Clone)]
pub struct Icons {
    pub theme_path: String,
    own: bool,
}

const MAX_MENU_FINDINGS: usize = 25;

impl Icons {
    pub fn detect() -> Icons {
        let rel = Path::new("hicolor/scalable/apps/gengar-ok.svg");
        // Running from a source checkout: target/{debug,release}/gengar -> assets/icons
        if let Ok(exe) = std::env::current_exe() {
            for up in exe.ancestors().skip(1).take(4) {
                let dir = up.join("assets/icons");
                if dir.join(rel).is_file() {
                    return Icons { theme_path: dir.display().to_string(), own: true };
                }
            }
        }
        let mut data_dirs: Vec<PathBuf> = dirs::data_dir().into_iter().collect();
        let sys = std::env::var("XDG_DATA_DIRS").unwrap_or_else(|_| "/usr/local/share:/usr/share".into());
        data_dirs.extend(sys.split(':').filter(|s| !s.is_empty()).map(PathBuf::from));
        let own = data_dirs.iter().any(|d| d.join("icons").join(rel).is_file());
        Icons { theme_path: String::new(), own }
    }

    pub fn name(&self, level: Level) -> &'static str {
        match (self.own, level) {
            (true, Level::Ok) => "gengar-ok",
            (true, Level::Warning) => "gengar-warning",
            (true, Level::Danger) => "gengar-danger",
            (true, Level::Unknown) => "gengar-unknown",
            (false, Level::Ok) => "security-high",
            (false, Level::Warning) => "security-medium",
            (false, Level::Danger) => "security-low",
            (false, Level::Unknown) => "dialog-question",
        }
    }
}

pub struct GengarTray {
    pub report: Option<ScanReport>,
    pub scanning: bool,
    pub error: Option<String>,
    pub icons: Icons,
    pub tx: Sender<Cmd>,
}

impl GengarTray {
    pub fn new(tx: Sender<Cmd>, icons: Icons) -> Self {
        GengarTray { report: None, scanning: false, error: None, icons, tx }
    }

    pub fn level(&self) -> Level {
        match &self.report {
            None => Level::Unknown,
            Some(r) if r.has_alert() => Level::Danger,
            Some(r) if r.stale => Level::Unknown,
            Some(r) if r.active().next().is_some() => Level::Warning,
            Some(_) => Level::Ok,
        }
    }

    fn headline(&self) -> String {
        match (&self.report, &self.error) {
            (Some(r), _) => r.summary(),
            (None, Some(_)) => "Scan failed".to_string(),
            (None, None) => "Waiting for first scan…".to_string(),
        }
    }

    fn detail_lines(&self) -> Vec<String> {
        let mut lines = Vec::new();
        if let Some(r) = &self.report {
            lines.push(format!("Last scan: {} ({} packages)", fmt_time(r.scanned_at), r.packages_scanned));
            if let Some(t) = r.feed.updated_at {
                lines.push(format!("Feed updated {}", fmt_age(t)));
            }
            if r.stale {
                lines.push("Vulnerability feed is outdated".to_string());
            } else if r.feed.error.is_some() {
                lines.push("Feed refresh failed, using cached copy".to_string());
            }
        }
        if let Some(e) = &self.error {
            lines.push(format!("Error: {e}"));
        }
        lines
    }
}

fn info_item(label: String) -> MenuItem<GengarTray> {
    StandardItem { label: escape_mnemonic(&label), enabled: false, ..Default::default() }.into()
}

/// Underscores mark access keys in menu labels; double them to show them literally.
fn escape_mnemonic(s: &str) -> String {
    s.replace('_', "__")
}

impl ksni::Tray for GengarTray {
    const MENU_ON_ACTIVATE: bool = true;

    fn id(&self) -> String {
        "gengar".into()
    }

    fn title(&self) -> String {
        "Gengar".into()
    }

    fn category(&self) -> ksni::Category {
        ksni::Category::SystemServices
    }

    fn status(&self) -> Status {
        // NeedsAttention makes Plasma show the icon even when it sits in the
        // hidden part of the system tray.
        match self.level() {
            Level::Danger => Status::NeedsAttention,
            _ => Status::Active,
        }
    }

    fn icon_theme_path(&self) -> String {
        self.icons.theme_path.clone()
    }

    fn icon_name(&self) -> String {
        self.icons.name(self.level()).into()
    }

    fn attention_icon_name(&self) -> String {
        self.icons.name(Level::Danger).into()
    }

    fn tool_tip(&self) -> ToolTip {
        let mut description = self.headline();
        if self.scanning {
            description.push_str("\nScanning…");
        }
        for line in self.detail_lines() {
            description.push('\n');
            description.push_str(&line);
        }
        ToolTip {
            icon_name: self.icon_name(),
            title: "Gengar – package vulnerability scanner".into(),
            description,
            icon_pixmap: Vec::new(),
        }
    }

    fn menu(&self) -> Vec<MenuItem<Self>> {
        let mut items = vec![info_item(self.headline())];
        items.extend(self.detail_lines().into_iter().map(info_item));
        items.push(MenuItem::Separator);

        if let Some(r) = &self.report {
            let active: Vec<_> = r.active().collect();
            if !active.is_empty() {
                let mut sub: Vec<MenuItem<Self>> = active
                    .iter()
                    .take(MAX_MENU_FINDINGS)
                    .map(|f| {
                        let fixed = f
                            .fixed_in
                            .as_deref()
                            .map(|v| format!("fixed in {v}"))
                            .unwrap_or_else(|| "no fix yet".into());
                        let url = avg_url(&f.issues[0].avg);
                        StandardItem {
                            label: escape_mnemonic(&format!(
                                "{} {} — {} — {}{}",
                                f.package,
                                f.installed,
                                f.severity.as_str(),
                                fixed,
                                if f.foreign { " (AUR)" } else { "" }
                            )),
                            icon_name: if f.alert { "dialog-warning".into() } else { String::new() },
                            activate: Box::new(move |_: &mut Self| open(&url)),
                            ..Default::default()
                        }
                        .into()
                    })
                    .collect();
                if active.len() > MAX_MENU_FINDINGS {
                    sub.push(info_item(format!("… and {} more (see full report)", active.len() - MAX_MENU_FINDINGS)));
                }
                items.push(
                    SubMenu { label: "Vulnerable packages".into(), submenu: sub, ..Default::default() }.into(),
                );
            }
        }

        let report_path = cache_dir().join("report.html");
        items.push(
            StandardItem {
                label: "Open full report".into(),
                icon_name: "document-open".into(),
                enabled: report_path.exists(),
                activate: Box::new(move |_: &mut Self| open(&report_path.display().to_string())),
                ..Default::default()
            }
            .into(),
        );
        items.push(
            StandardItem {
                label: if self.scanning { "Scanning…".into() } else { "Scan now".into() },
                icon_name: "view-refresh".into(),
                enabled: !self.scanning,
                activate: Box::new(|this: &mut Self| {
                    let _ = this.tx.send(Cmd::ScanNow);
                }),
                ..Default::default()
            }
            .into(),
        );
        items.push(
            StandardItem {
                label: "Settings…".into(),
                icon_name: "configure".into(),
                activate: Box::new(|_: &mut Self| match Config::ensure_file() {
                    Ok(p) => open(&p.display().to_string()),
                    Err(e) => eprintln!("gengar: cannot create config file: {e}"),
                }),
                ..Default::default()
            }
            .into(),
        );
        items.push(MenuItem::Separator);
        items.push(
            StandardItem {
                label: "Quit Gengar".into(),
                icon_name: "application-exit".into(),
                activate: Box::new(|this: &mut Self| {
                    let _ = this.tx.send(Cmd::Quit);
                }),
                ..Default::default()
            }
            .into(),
        );
        items
    }

    fn watcher_offline(&self, reason: ksni::OfflineReason) -> bool {
        eprintln!("gengar: system tray not available ({reason:?}); waiting for it to come back");
        true // keep running; the icon reappears when the panel restarts
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::feed::FeedInfo;
    use crate::scan::Severity;
    use crate::util::now_secs;

    fn tray(report: Option<ScanReport>) -> GengarTray {
        let (tx, _rx) = std::sync::mpsc::channel();
        let mut t = GengarTray::new(tx, Icons { theme_path: String::new(), own: true });
        t.report = report;
        t
    }

    fn report(alert: bool, findings: bool, stale: bool) -> ScanReport {
        use crate::scan::{Finding, Issue};
        let f = Finding {
            package: "openssl".into(),
            installed: "1-1".into(),
            foreign: false,
            severity: if alert { Severity::Critical } else { Severity::Low },
            fixed_in: Some("2-1".into()),
            alert,
            ignored: false,
            issues: vec![Issue {
                avg: "AVG-1".into(),
                severity: Severity::Low,
                kind: String::new(),
                status: String::new(),
                fixed: None,
                cves: vec![],
                advisories: vec![],
                ignored: false,
            }],
        };
        ScanReport {
            scanned_at: now_secs(),
            packages_scanned: 10,
            alert_severity: Severity::High,
            feed: FeedInfo { source: "x".into(), updated_at: Some(now_secs()), groups: 1, error: None },
            stale,
            findings: if findings { vec![f] } else { vec![] },
        }
    }

    #[test]
    fn levels_and_status() {
        use ksni::Tray;
        assert_eq!(tray(None).level(), Level::Unknown);
        assert_eq!(tray(Some(report(false, false, false))).level(), Level::Ok);
        assert_eq!(tray(Some(report(false, true, false))).level(), Level::Warning);
        assert_eq!(tray(Some(report(false, false, true))).level(), Level::Unknown);
        let danger = tray(Some(report(true, true, true)));
        assert_eq!(danger.level(), Level::Danger);
        assert_eq!(danger.icon_name(), "gengar-danger");
        assert!(matches!(danger.status(), Status::NeedsAttention));
        assert!(matches!(tray(None).status(), Status::Active));
    }

    #[test]
    fn menu_lists_findings() {
        use ksni::Tray;
        let t = tray(Some(report(true, true, false)));
        let menu = t.menu();
        let has_submenu = menu.iter().any(|m| matches!(m, MenuItem::SubMenu(s) if s.label == "Vulnerable packages"));
        assert!(has_submenu);
        assert!(tray(Some(report(false, false, false)))
            .menu()
            .iter()
            .all(|m| !matches!(m, MenuItem::SubMenu(_))));
    }

    #[test]
    fn stock_icon_fallback() {
        let icons = Icons { theme_path: String::new(), own: false };
        assert_eq!(icons.name(Level::Danger), "security-low");
        assert_eq!(icons.name(Level::Ok), "security-high");
    }
}

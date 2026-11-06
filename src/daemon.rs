//! The background part: single instance, scheduler and notifications.
//!
//! The long-running process only holds the tray icon and the latest result.
//! Each scan runs as a short-lived child process (`gengar scan --json`), so
//! the memory used for parsing the vulnerability feed is returned to the
//! system as soon as the scan finishes.

use crate::config::Config;
use crate::pacman::local_db_dir;
use crate::scan::ScanReport;
use crate::tray::{Cmd, GengarTray, Icons, Level};
use crate::util::{cache_dir, lower_priority, now_secs, open, state_dir, write_atomic};
use crate::EXIT_ALERT;
use ksni::blocking::{Handle, TrayMethods};
use serde::{Deserialize, Serialize};
use std::fs::File;
use std::os::fd::AsRawFd;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::mpsc::{channel, Receiver, RecvTimeoutError};
use std::time::{Duration, SystemTime};

/// How often to check whether installed packages changed (one `stat` call).
const TICK: Duration = Duration::from_secs(120);
/// Retry delay after a failed scan or feed download.
const RETRY_SECS: u64 = 15 * 60;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Policy {
    /// Use the cached feed only (packages changed).
    Offline,
    /// Refresh the feed if it is older than this many seconds.
    MaxAge(u64),
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct State {
    /// Alert keys (`AVG:package`) the user was already notified about.
    notified: Vec<String>,
}

impl State {
    fn path() -> PathBuf {
        state_dir().join("state.json")
    }
    fn load() -> State {
        std::fs::read(Self::path())
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or_default()
    }
    fn save(&self) {
        if let Ok(data) = serde_json::to_vec_pretty(self) {
            let _ = write_atomic(&Self::path(), &data);
        }
    }
}

/// Exclusive lock so only one tray instance runs per user session.
/// `Err(true)` means another instance holds the lock.
fn acquire_lock() -> Result<File, bool> {
    let dir = std::env::var_os("XDG_RUNTIME_DIR").map(PathBuf::from).unwrap_or_else(state_dir);
    let _ = std::fs::create_dir_all(&dir);
    let file = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(dir.join("gengar.lock"))
        .map_err(|_| false)?;
    // SAFETY: flock on a file descriptor we own.
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0 {
        Ok(file)
    } else {
        Err(true)
    }
}

fn db_mtime() -> Option<SystemTime> {
    std::fs::metadata(local_db_dir()).and_then(|m| m.modified()).ok()
}

/// Run one scan in a child process and parse its JSON result.
fn run_scan_child(policy: Policy) -> Result<ScanReport, String> {
    // /proc/self/exe keeps working even if the binary was replaced by a
    // package upgrade while Gengar is running.
    let exe = if cfg!(target_os = "linux") {
        PathBuf::from("/proc/self/exe")
    } else {
        std::env::current_exe().map_err(|e| e.to_string())?
    };
    let mut cmd = Command::new(exe);
    cmd.args(["scan", "--json"]);
    match policy {
        Policy::Offline => {
            cmd.arg("--offline");
        }
        Policy::MaxAge(s) => {
            cmd.args(["--max-feed-age", &s.to_string()]);
        }
    }
    let out = cmd
        .stdin(Stdio::null())
        .output()
        .map_err(|e| format!("cannot start scanner: {e}"))?;
    match out.status.code() {
        Some(0) | Some(EXIT_ALERT) => {
            serde_json::from_slice(&out.stdout).map_err(|e| format!("invalid scanner output: {e}"))
        }
        _ => {
            let err = String::from_utf8_lossy(&out.stderr);
            let msg = err.lines().rev().find(|l| !l.trim().is_empty()).unwrap_or("scan failed");
            Err(msg.trim_start_matches("gengar: ").to_string())
        }
    }
}

/// Show a desktop notification for alert-level issues not seen before.
fn notify_new_alerts(report: &ScanReport, state: &mut State, cfg: &Config, icon: &str) {
    let keys = report.alert_keys();
    let new: Vec<&String> = keys.iter().filter(|k| !state.notified.contains(k)).collect();
    if !new.is_empty() && cfg.notify {
        let alerts: Vec<_> = report.alert_findings().collect();
        let summary = if alerts.len() == 1 {
            format!("Vulnerable package: {}", alerts[0].package)
        } else {
            format!("{} packages with dangerous vulnerabilities", alerts.len())
        };
        let mut body: Vec<String> = alerts
            .iter()
            .take(5)
            .map(|f| {
                let fix = f.fixed_in.as_deref().map(|v| format!("fixed in {v}")).unwrap_or_else(|| "no fix yet".into());
                format!("{} {} – {} ({fix})", f.package, f.installed, f.severity.as_str())
            })
            .collect();
        if alerts.len() > 5 {
            body.push(format!("… and {} more", alerts.len() - 5));
        }
        let result = notify_rust::Notification::new()
            .appname("Gengar")
            .summary(&summary)
            .body(&body.join("\n"))
            .icon(icon)
            .hint(notify_rust::Hint::DesktopEntry("gengar".into()))
            .urgency(notify_rust::Urgency::Critical)
            .action("default", "Open report")
            .action("report", "Open report")
            .show();
        match result {
            Ok(handle) => {
                std::thread::spawn(move || {
                    handle.wait_for_action(|action| {
                        if action == "default" || action == "report" {
                            open(&cache_dir().join("report.html").display().to_string());
                        }
                    })
                });
            }
            Err(e) => eprintln!("gengar: cannot show notification: {e}"),
        }
    }
    if state.notified != keys {
        state.notified = keys;
        state.save();
    }
}

fn scheduler(handle: &Handle<GengarTray>, rx: &Receiver<Cmd>, icons: &Icons) {
    let mut state = State::load();
    let mut pending = Some(Policy::MaxAge(Config::load().interval_secs()));
    let mut next_refresh = 0u64; // wall clock, survives suspend/resume correctly
    let mut last_db = db_mtime();

    loop {
        if let Some(policy) = pending.take() {
            let cfg = Config::load();
            let db_before = db_mtime();
            handle.update(|t| t.scanning = true);
            let result = run_scan_child(policy);
            let now = now_secs();
            match result {
                Ok(report) => {
                    if policy != Policy::Offline {
                        next_refresh = if report.feed.error.is_some() {
                            now + RETRY_SECS
                        } else {
                            now + cfg.interval_secs()
                        };
                    }
                    notify_new_alerts(&report, &mut state, &cfg, icons.name(Level::Danger));
                    handle.update(move |t| {
                        t.report = Some(report);
                        t.error = None;
                        t.scanning = false;
                    });
                }
                Err(e) => {
                    eprintln!("gengar: {e}");
                    next_refresh = now + RETRY_SECS;
                    handle.update(move |t| {
                        t.error = Some(e);
                        t.scanning = false;
                    });
                }
            }
            last_db = db_before;
        }

        let until_refresh = next_refresh.saturating_sub(now_secs());
        let wait = TICK.min(Duration::from_secs(until_refresh.max(1)));
        match rx.recv_timeout(wait) {
            Ok(Cmd::ScanNow) => pending = Some(Policy::MaxAge(0)),
            Ok(Cmd::Quit) | Err(RecvTimeoutError::Disconnected) => break,
            Err(RecvTimeoutError::Timeout) => {
                if now_secs() >= next_refresh {
                    // Slightly below the interval so the cached copy counts as due.
                    let interval = Config::load().interval_secs();
                    pending = Some(Policy::MaxAge(interval.saturating_sub(120)));
                } else if db_mtime() != last_db {
                    pending = Some(Policy::Offline);
                }
            }
        }
    }
}

/// Entry point of `gengar tray` (the default command).
pub fn run_tray() -> i32 {
    let _lock = match acquire_lock() {
        Ok(f) => Some(f),
        Err(true) => {
            eprintln!("gengar: already running");
            return 0;
        }
        Err(false) => None,
    };
    lower_priority();

    let icons = Icons::detect();
    let (tx, rx) = channel();
    let tray = GengarTray::new(tx, icons.clone());
    // Autostart may run before the panel is ready; keep waiting for it.
    let handle = match tray.assume_sni_available(true).spawn() {
        Ok(h) => h,
        Err(e) => {
            eprintln!("gengar: cannot create tray icon: {e}");
            return 1;
        }
    };

    scheduler(&handle, &rx, &icons);
    handle.shutdown().wait();
    0
}

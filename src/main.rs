//! Gengar: a lightweight, read-only vulnerability scanner for packages
//! installed with pacman (including AUR packages from paru/yay) on CachyOS
//! and other Arch-based systems.

mod config;
mod daemon;
mod feed;
mod pacman;
mod report;
mod scan;
mod tray;
mod util;
mod vercmp;

use config::Config;
use feed::FetchPolicy;
use scan::ScanReport;
use util::{cache_dir, write_atomic};

/// Exit code of `gengar scan` when vulnerabilities at or above the alert level were found.
pub const EXIT_ALERT: i32 = 3;

const HELP: &str = "\
Gengar – read-only vulnerability scanner for pacman/AUR packages

USAGE:
    gengar [tray]            Run in the background with a system tray icon (default)
    gengar scan [OPTIONS]    Scan once and print the results
    gengar report            Scan once and open the HTML report in the browser

SCAN OPTIONS:
    --json                   Print the result as JSON
    --offline                Only use the cached vulnerability feed
    --refresh                Always check for a newer feed
    --max-feed-age <SECS>    Refresh the feed if the cached copy is older than this
    --feed <URL|FILE>        Use another feed (Arch Security Tracker JSON format)
    --no-report              Do not write ~/.cache/gengar/report.html

Exit codes of `scan`: 0 = nothing at or above the alert level, 3 = dangerous
vulnerabilities found, 1 = error.

Gengar never installs, updates or removes packages; it only runs `pacman -Q`.
Configuration: ~/.config/gengar/config.toml
";

struct ScanOpts {
    json: bool,
    policy: Option<FetchPolicy>,
    feed: Option<String>,
    write_report: bool,
}

fn parse_scan_opts(args: &[String]) -> Result<ScanOpts, String> {
    let mut opts = ScanOpts { json: false, policy: None, feed: None, write_report: true };
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--json" => opts.json = true,
            "--offline" => opts.policy = Some(FetchPolicy::Offline),
            "--refresh" => opts.policy = Some(FetchPolicy::MaxAge(0)),
            "--max-feed-age" => {
                let v = it.next().ok_or("--max-feed-age needs a value")?;
                let secs = v.parse().map_err(|_| format!("invalid number: {v}"))?;
                opts.policy = Some(FetchPolicy::MaxAge(secs));
            }
            "--feed" => opts.feed = Some(it.next().ok_or("--feed needs a value")?.clone()),
            "--no-report" => opts.write_report = false,
            other => return Err(format!("unknown option: {other}")),
        }
    }
    Ok(opts)
}

fn perform_scan(opts: &ScanOpts) -> Result<ScanReport, String> {
    let cfg = Config::load();
    let source = opts.feed.clone().unwrap_or_else(|| cfg.feed_url.clone());
    let policy = opts.policy.unwrap_or(FetchPolicy::MaxAge(cfg.interval_secs()));

    let installed = pacman::installed_packages()?;
    let (avgs, info) = feed::load(&source, policy)?;
    let report = scan::scan(&installed, &avgs, &cfg, info);
    drop(avgs);

    if opts.write_report {
        let dir = cache_dir();
        let _ = write_atomic(&dir.join("report.html"), report::render_html(&report).as_bytes());
        if let Ok(json) = serde_json::to_vec(&report) {
            let _ = write_atomic(&dir.join("last-scan.json"), &json);
        }
    }
    Ok(report)
}

fn cmd_scan(args: &[String]) -> i32 {
    let opts = match parse_scan_opts(args) {
        Ok(o) => o,
        Err(e) => {
            eprintln!("gengar: {e}\n\n{HELP}");
            return 2;
        }
    };
    match perform_scan(&opts) {
        Ok(report) => {
            if opts.json {
                match serde_json::to_string(&report) {
                    Ok(s) => println!("{s}"),
                    Err(e) => {
                        eprintln!("gengar: {e}");
                        return 1;
                    }
                }
            } else {
                print!("{}", report::render_text(&report));
            }
            if report.has_alert() {
                EXIT_ALERT
            } else {
                0
            }
        }
        Err(e) => {
            eprintln!("gengar: {e}");
            1
        }
    }
}

fn cmd_report() -> i32 {
    let opts = ScanOpts { json: false, policy: None, feed: None, write_report: true };
    match perform_scan(&opts) {
        Ok(report) => {
            let path = cache_dir().join("report.html");
            println!("{}", report.summary());
            println!("Report: {}", path.display());
            util::open(&path.display().to_string());
            // Give xdg-open a moment to hand the file over before we exit.
            std::thread::sleep(std::time::Duration::from_millis(300));
            0
        }
        Err(e) => {
            eprintln!("gengar: {e}");
            1
        }
    }
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let code = match args.first().map(String::as_str).unwrap_or("tray") {
        "tray" => daemon::run_tray(),
        "scan" => cmd_scan(&args[1..]),
        "report" => cmd_report(),
        "-h" | "--help" | "help" => {
            print!("{HELP}");
            0
        }
        "-V" | "--version" | "version" => {
            println!("gengar {}", env!("CARGO_PKG_VERSION"));
            0
        }
        other => {
            eprintln!("gengar: unknown command: {other}\n\n{HELP}");
            2
        }
    };
    std::process::exit(code);
}

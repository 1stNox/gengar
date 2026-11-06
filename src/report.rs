//! Human readable output: a terminal table and a self-contained HTML report.

use crate::scan::{Finding, ScanReport, Severity};
use crate::util::{avg_url, cve_url, fmt_age, fmt_time, html_escape};
use std::fmt::Write;

const FIX_HINT: &str = "Gengar only reports; it never changes your system. \
Update with your usual tool (e.g. `sudo pacman -Syu` or `paru`) to install fixes.";

fn fixed_label(f: &Finding) -> String {
    f.fixed_in.clone().unwrap_or_else(|| "not fixed yet".to_string())
}

fn cve_label(f: &Finding) -> String {
    let cves: Vec<&str> = f
        .issues
        .iter()
        .filter(|i| !i.ignored || f.ignored)
        .flat_map(|i| i.cves.iter().map(String::as_str))
        .collect();
    match cves.len() {
        0 => "-".to_string(),
        1..=3 => cves.join(", "),
        n => format!("{} (+{} more)", cves[..2].join(", "), n - 2),
    }
}

fn feed_line(r: &ScanReport) -> String {
    let updated = r.feed.updated_at.map(fmt_age).unwrap_or_else(|| "unknown".to_string());
    format!("Feed: {} (updated {}, {} advisory groups)", r.feed.source, updated, r.feed.groups)
}

pub fn warnings(r: &ScanReport) -> Vec<String> {
    let mut w = Vec::new();
    if let Some(e) = &r.feed.error {
        w.push(format!("could not refresh the vulnerability feed ({e}); using the cached copy"));
    }
    if r.stale {
        w.push("the vulnerability feed is outdated; results may be incomplete".to_string());
    }
    w
}

pub fn render_text(r: &ScanReport) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "Gengar scan of {} installed packages, {}", r.packages_scanned, fmt_time(r.scanned_at));
    let _ = writeln!(out, "{}", feed_line(r));
    for w in warnings(r) {
        let _ = writeln!(out, "warning: {w}");
    }
    let _ = writeln!(out);

    if r.findings.is_empty() {
        let _ = writeln!(out, "No known vulnerabilities in installed packages.");
        return out;
    }

    let rows: Vec<[String; 6]> = r
        .findings
        .iter()
        .map(|f| {
            let mut name = f.package.clone();
            if f.foreign {
                name.push_str(" [AUR]");
            }
            let sev = if f.ignored { "ignored".to_string() } else { f.severity.as_str().to_string() };
            let avgs: Vec<&str> = f.issues.iter().map(|i| i.avg.as_str()).collect();
            [sev, name, f.installed.clone(), fixed_label(f), avgs.join(", "), cve_label(f)]
        })
        .collect();
    let header = ["SEVERITY", "PACKAGE", "INSTALLED", "FIXED IN", "ADVISORY", "CVEs"];
    let mut widths = header.map(str::len);
    for row in &rows {
        for (w, cell) in widths.iter_mut().zip(row) {
            *w = (*w).max(cell.chars().count());
        }
    }
    let line = |cells: &[String]| {
        let mut s = String::new();
        for (i, c) in cells.iter().enumerate() {
            if i + 1 == cells.len() {
                s.push_str(c);
            } else {
                let _ = write!(s, "{c:<w$}  ", w = widths[i]);
            }
        }
        s.trim_end().to_string()
    };
    let _ = writeln!(out, "{}", line(&header.map(String::from)));
    for row in &rows {
        let _ = writeln!(out, "{}", line(row));
    }
    let _ = writeln!(out);
    let _ = writeln!(out, "{}.", r.summary());
    let alerts = r.alert_findings().count();
    if alerts > 0 {
        let _ = writeln!(
            out,
            "{alerts} package(s) at or above the alert level ({}).",
            r.alert_severity.as_str()
        );
    }
    let _ = writeln!(out, "{FIX_HINT}");
    out
}

fn sev_class(s: Severity) -> &'static str {
    match s {
        Severity::Critical => "critical",
        Severity::High => "high",
        Severity::Medium => "medium",
        Severity::Low => "low",
        Severity::Unknown => "unknown",
    }
}

pub fn render_html(r: &ScanReport) -> String {
    let mut rows = String::new();
    for f in &r.findings {
        let mut issues = String::new();
        for i in &f.issues {
            let cves: Vec<String> = i
                .cves
                .iter()
                .map(|c| format!("<a href=\"{}\">{}</a>", html_escape(&cve_url(c)), html_escape(c)))
                .collect();
            let fixed = i
                .fixed
                .as_deref()
                .map(|v| format!("fixed in {}", html_escape(v)))
                .unwrap_or_else(|| "no fix yet".into());
            let _ = write!(
                issues,
                "<li{ign}><a href=\"{url}\">{avg}</a> <span class=\"badge {cls}\">{sev}</span> {kind} \
                 <span class=\"muted\">· {fixed}{ignored}</span><br><span class=\"cves\">{cves}</span></li>",
                ign = if i.ignored { " class=\"ignored\"" } else { "" },
                url = html_escape(&avg_url(&i.avg)),
                avg = html_escape(&i.avg),
                cls = sev_class(i.severity),
                sev = i.severity.as_str(),
                kind = html_escape(&i.kind),
                ignored = if i.ignored { " · ignored" } else { "" },
                cves = cves.join(", "),
            );
        }
        let _ = writeln!(
            rows,
            "<tr{rowcls}><td><span class=\"badge {cls}\">{sev}</span></td>\
             <td><strong>{pkg}</strong>{aur}</td><td data-label=\"Installed\"><code>{inst}</code></td>\
             <td data-label=\"Fixed in\"><code>{fixed}</code></td><td><ul>{issues}</ul></td></tr>",
            rowcls = if f.ignored { " class=\"ignored\"" } else { "" },
            cls = sev_class(f.severity),
            sev = if f.ignored { "Ignored" } else { f.severity.as_str() },
            pkg = html_escape(&f.package),
            aur = if f.foreign { " <span class=\"badge aur\">AUR</span>" } else { "" },
            inst = html_escape(&f.installed),
            fixed = html_escape(&fixed_label(f)),
        );
    }

    let body = if r.findings.is_empty() {
        "<p class=\"ok\">No known vulnerabilities in installed packages.</p>".to_string()
    } else {
        format!(
            "<table><thead><tr><th>Severity</th><th>Package</th><th>Installed</th><th>Fixed in</th>\
             <th>Advisories</th></tr></thead><tbody>\n{rows}</tbody></table>"
        )
    };
    let warn: String = warnings(r)
        .iter()
        .map(|w| format!("<p class=\"warn\">⚠ {}</p>", html_escape(w)))
        .collect();

    format!(
        r#"<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Gengar report</title>
<style>
:root {{ --bg:#fafafa; --fg:#1d1d1f; --muted:#6b6b70; --line:#e2e2e6; --card:#fff;
  --critical:#c62828; --high:#e65100; --medium:#b38600; --low:#2e7d32; --unknown:#6b6b70; --link:#3d5afe; }}
@media (prefers-color-scheme: dark) {{ :root {{ --bg:#16161a; --fg:#ececf1; --muted:#9a9aa3; --line:#2c2c33;
  --card:#1e1e24; --critical:#ff6b6b; --high:#ffa94d; --medium:#ffd43b; --low:#69db7c; --unknown:#adb5bd; --link:#8c9eff; }} }}
body {{ margin:0; padding:24px 16px; background:var(--bg); color:var(--fg);
  font:15px/1.5 system-ui, sans-serif; }}
main {{ max-width:1100px; margin:0 auto; }}
h1 {{ font-size:22px; margin:0 0 4px; }}
.muted, .meta {{ color:var(--muted); }}
.meta {{ margin:0 0 16px; font-size:13px; }}
.summary {{ font-size:17px; font-weight:600; margin:12px 0; }}
.warn {{ border-left:4px solid var(--medium); padding:6px 10px; background:var(--card); }}
.ok {{ font-size:17px; color:var(--low); }}
table {{ width:100%; border-collapse:collapse; background:var(--card); border:1px solid var(--line); }}
th, td {{ text-align:left; vertical-align:top; padding:8px 10px; border-bottom:1px solid var(--line); }}
th {{ font-size:12px; text-transform:uppercase; letter-spacing:.04em; color:var(--muted); }}
ul {{ margin:0; padding-left:16px; }} li {{ margin-bottom:4px; }}
a {{ color:var(--link); }} code {{ font-size:13px; }}
.cves {{ font-size:13px; }}
.badge {{ display:inline-block; padding:0 7px; border-radius:9px; font-size:12px; font-weight:600;
  border:1px solid currentColor; white-space:nowrap; }}
.critical {{ color:var(--critical); }} .high {{ color:var(--high); }} .medium {{ color:var(--medium); }}
.low {{ color:var(--low); }} .unknown, .aur {{ color:var(--unknown); }}
.ignored {{ opacity:.55; }}
footer {{ margin-top:16px; font-size:13px; color:var(--muted); }}
@media (max-width:700px) {{ table, thead, tbody, tr, td {{ display:block; }} thead {{ display:none; }}
  tr {{ border-bottom:1px solid var(--line); padding:6px 0; }} td {{ border:0; padding:3px 10px; }}
  td[data-label]::before {{ content:attr(data-label) ": "; color:var(--muted); font-size:13px; }} }}
</style></head>
<body><main>
<h1>Gengar vulnerability report</h1>
<p class="meta">Scanned {pkgs} installed packages on {time} · {feed}</p>
{warn}
<p class="summary">{summary}</p>
{body}
<footer>CVE details link to cve.org; advisory groups link to the Arch Linux Security Tracker.
Gengar only reports; it never changes your system. Update with your usual tool
(e.g. <code>sudo pacman -Syu</code> or <code>paru</code>) to install fixes.</footer>
</main></body></html>
"#,
        pkgs = r.packages_scanned,
        time = html_escape(&fmt_time(r.scanned_at)),
        feed = html_escape(&feed_line(r)),
        summary = html_escape(&r.summary()),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::feed::FeedInfo;
    use crate::scan::{Finding, Issue};

    fn report() -> ScanReport {
        ScanReport {
            scanned_at: 1_700_000_000,
            packages_scanned: 3,
            alert_severity: Severity::High,
            feed: FeedInfo { source: "test".into(), updated_at: Some(1_700_000_000), groups: 2, error: None },
            stale: false,
            findings: vec![Finding {
                package: "open<ssl>".into(),
                installed: "3.0.7-1".into(),
                foreign: true,
                severity: Severity::Critical,
                fixed_in: None,
                alert: true,
                ignored: false,
                issues: vec![Issue {
                    avg: "AVG-10".into(),
                    severity: Severity::Critical,
                    kind: "arbitrary code execution".into(),
                    status: "Vulnerable".into(),
                    fixed: None,
                    cves: vec!["CVE-2026-0001".into()],
                    advisories: vec![],
                    ignored: false,
                }],
            }],
        }
    }

    #[test]
    fn text_contains_findings() {
        let t = render_text(&report());
        assert!(t.contains("Critical  open<ssl> [AUR]"));
        assert!(t.contains("not fixed yet"));
        assert!(t.contains("CVE-2026-0001"));
        assert!(t.contains("1 vulnerable package (1 Critical)"));
    }

    #[test]
    fn html_is_escaped_and_linked() {
        let h = render_html(&report());
        assert!(h.contains("open&lt;ssl&gt;"));
        assert!(!h.contains("open<ssl>"));
        assert!(h.contains("https://www.cve.org/CVERecord?id=CVE-2026-0001"));
        assert!(h.contains("https://security.archlinux.org/AVG-10"));
    }
}

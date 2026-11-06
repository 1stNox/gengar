//! Small helpers shared by the scanner and the tray.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

pub fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn dir_from_env(var: &str, fallback: Option<PathBuf>) -> PathBuf {
    std::env::var_os(var)
        .map(PathBuf::from)
        .unwrap_or_else(|| fallback.unwrap_or_else(std::env::temp_dir).join("gengar"))
}

/// `~/.cache/gengar` (feed cache, last report).
pub fn cache_dir() -> PathBuf {
    dir_from_env("GENGAR_CACHE_DIR", dirs::cache_dir())
}

/// `~/.local/state/gengar` (which alerts were already shown).
pub fn state_dir() -> PathBuf {
    dir_from_env("GENGAR_STATE_DIR", dirs::state_dir().or_else(dirs::cache_dir))
}

/// Write a file via a temporary file + rename so readers never see half a file.
pub fn write_atomic(path: &Path, data: &[u8]) -> std::io::Result<()> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let tmp = path.with_extension(format!("tmp{}", std::process::id()));
    {
        let mut f = std::fs::File::create(&tmp)?;
        f.write_all(data)?;
    }
    std::fs::rename(&tmp, path)
}

/// Format a unix timestamp in local time as `YYYY-MM-DD HH:MM`.
pub fn fmt_time(ts: u64) -> String {
    let t = ts as libc::time_t;
    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    // SAFETY: localtime_r only writes into the provided struct.
    if unsafe { libc::localtime_r(&t, &mut tm) }.is_null() {
        return ts.to_string();
    }
    format!(
        "{:04}-{:02}-{:02} {:02}:{:02}",
        tm.tm_year + 1900,
        tm.tm_mon + 1,
        tm.tm_mday,
        tm.tm_hour,
        tm.tm_min
    )
}

/// Human friendly age like "just now", "5 min ago", "3 h ago", "2 days ago".
pub fn fmt_age(ts: u64) -> String {
    let secs = now_secs().saturating_sub(ts);
    match secs {
        0..=59 => "just now".to_string(),
        60..=3599 => format!("{} min ago", secs / 60),
        3600..=172_799 => format!("{} h ago", secs / 3600),
        _ => format!("{} days ago", secs / 86400),
    }
}

/// Open a URL or file with the desktop's default handler, without blocking.
pub fn open(target: &str) {
    match Command::new("xdg-open")
        .arg(target)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
    {
        // Reap the child in the background so it never lingers as a zombie.
        Ok(mut child) => {
            std::thread::spawn(move || child.wait());
        }
        Err(e) => eprintln!("gengar: cannot run xdg-open: {e}"),
    }
}

/// Lowest CPU and I/O priority for this process and every child it starts.
pub fn lower_priority() {
    // SAFETY: plain syscalls on the calling process, no memory involved.
    unsafe {
        libc::setpriority(libc::PRIO_PROCESS, 0, 19);
        const IOPRIO_WHO_PROCESS: libc::c_long = 1;
        const IOPRIO_CLASS_IDLE: libc::c_long = 3;
        const IOPRIO_CLASS_SHIFT: libc::c_long = 13;
        libc::syscall(
            libc::SYS_ioprio_set,
            IOPRIO_WHO_PROCESS,
            0 as libc::c_long,
            IOPRIO_CLASS_IDLE << IOPRIO_CLASS_SHIFT,
        );
    }
}

pub fn html_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(c),
        }
    }
    out
}

pub fn avg_url(avg: &str) -> String {
    format!("https://security.archlinux.org/{avg}")
}

pub fn cve_url(id: &str) -> String {
    if id.starts_with("CVE-") {
        format!("https://www.cve.org/CVERecord?id={id}")
    } else {
        format!("https://security.archlinux.org/{id}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escaping_and_urls() {
        assert_eq!(html_escape("<a href=\"x\">&'"), "&lt;a href=&quot;x&quot;&gt;&amp;&#39;");
        assert_eq!(cve_url("CVE-2024-3094"), "https://www.cve.org/CVERecord?id=CVE-2024-3094");
        assert_eq!(avg_url("AVG-1"), "https://security.archlinux.org/AVG-1");
    }

    #[test]
    fn ages() {
        assert_eq!(fmt_age(now_secs()), "just now");
        assert_eq!(fmt_age(now_secs() - 7200), "2 h ago");
        assert_eq!(fmt_age(now_secs() - 3 * 86400), "3 days ago");
    }
}

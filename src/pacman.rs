//! Read-only access to the list of installed packages.
//!
//! Gengar only ever *queries* pacman. The argument lists below are the only
//! pacman invocations in the whole program; they never sync, install,
//! upgrade or remove anything and need no root privileges.

use std::collections::HashSet;
use std::path::PathBuf;
use std::process::Command;

/// `pacman -Q`: every installed package (repo + AUR/paru/yay) with its version.
pub const QUERY_ALL: &[&str] = &["-Q"];
/// `pacman -Qm`: "foreign" packages that are not in any sync repo (AUR, local builds).
pub const QUERY_FOREIGN: &[&str] = &["-Qm"];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Installed {
    pub name: String,
    pub version: String,
    /// Not from a configured repository (AUR via paru/yay, or a local build).
    pub foreign: bool,
}

fn pacman_bin() -> String {
    std::env::var("GENGAR_PACMAN").unwrap_or_else(|_| "pacman".to_string())
}

/// Directory whose modification time changes whenever packages are
/// installed, upgraded or removed.
pub fn local_db_dir() -> PathBuf {
    std::env::var_os("GENGAR_PACMAN_DB")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/var/lib/pacman/local"))
}

fn run_query(args: &[&str]) -> Result<(bool, String), String> {
    let out = Command::new(pacman_bin())
        .args(args)
        .env("LC_ALL", "C")
        .output()
        .map_err(|e| format!("could not run pacman: {e}"))?;
    Ok((out.status.success(), String::from_utf8_lossy(&out.stdout).into_owned()))
}

/// List installed packages, marking foreign (AUR) ones.
pub fn installed_packages() -> Result<Vec<Installed>, String> {
    let (ok, all) = run_query(QUERY_ALL)?;
    if !ok {
        return Err("`pacman -Q` failed".to_string());
    }
    // `pacman -Qm` exits non-zero when there are no foreign packages; that is fine.
    let foreign_out = run_query(QUERY_FOREIGN).map(|(_, s)| s).unwrap_or_default();
    let foreign: HashSet<String> = parse_query(&foreign_out).into_iter().map(|(n, _)| n).collect();

    let pkgs: Vec<Installed> = parse_query(&all)
        .into_iter()
        .map(|(name, version)| Installed { foreign: foreign.contains(&name), name, version })
        .collect();
    if pkgs.is_empty() {
        return Err("pacman reported no installed packages".to_string());
    }
    Ok(pkgs)
}

/// Parse `name version` lines as printed by `pacman -Q`.
pub fn parse_query(text: &str) -> Vec<(String, String)> {
    text.lines()
        .filter_map(|line| {
            let mut it = line.split_whitespace();
            let name = it.next()?;
            let version = it.next()?;
            if it.next().is_some() {
                return None; // not a package line
            }
            Some((name.to_string(), version.to_string()))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_read_only_queries() {
        // Every pacman operation Gengar performs must be a query (-Q...).
        // Sync (-S), upgrade (-U), remove (-R), database (-D) or file (-F)
        // operations must never appear here.
        for args in [QUERY_ALL, QUERY_FOREIGN] {
            assert!(!args.is_empty());
            let op = args[0];
            assert!(op.starts_with("-Q"), "{op} is not a query");
            for a in args {
                for forbidden in ['S', 'U', 'R', 'D', 'F', 'y', 'u'] {
                    assert!(!a.contains(forbidden), "forbidden flag {forbidden} in {a}");
                }
            }
        }
    }

    #[test]
    fn parses_pacman_output() {
        let out = "openssl 3.0.7-1\nlinux-cachyos 6.17.7-2\n\nwarning: something odd here\nparu-bin 2.0.4-1\n";
        let parsed = parse_query(out);
        assert_eq!(
            parsed,
            vec![
                ("openssl".to_string(), "3.0.7-1".to_string()),
                ("linux-cachyos".to_string(), "6.17.7-2".to_string()),
                ("paru-bin".to_string(), "2.0.4-1".to_string()),
            ]
        );
    }
}

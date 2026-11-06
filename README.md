# gengar
Vulnerability Scanning for CachyOS

Gengar runs in the background and checks every package installed with
**pacman**, including AUR packages installed with **paru** or **yay**, for
known security vulnerabilities (CVEs). It shows a small shield icon in the
system tray (bottom right). When a dangerous vulnerability is found, the icon
turns red and a desktop notification pops up.

Gengar is **read-only**. It never installs, updates, downgrades or removes
anything, and it needs no root privileges. The only package-manager commands
it runs are `pacman -Q` and `pacman -Qm`.

| Icon | Meaning |
|---|---|
| <img src="assets/icons/hicolor/scalable/apps/gengar-ok.svg" width="24"> | No known vulnerabilities in installed packages |
| <img src="assets/icons/hicolor/scalable/apps/gengar-warning.svg" width="24"> | Vulnerable packages below the alert level (e.g. Low/Medium) |
| <img src="assets/icons/hicolor/scalable/apps/gengar-danger.svg" width="24"> | Dangerous vulnerability (High/Critical by default): notification + icon is forced visible |
| <img src="assets/icons/hicolor/scalable/apps/gengar-unknown.svg" width="24"> | No result yet, or the vulnerability feed is outdated |

Clicking the icon opens a menu with:
- a summary,
- the list of vulnerable packages (each entry opens its advisory),
- "Open full report", which is an HTML page with links to every CVE on
  [cve.org](https://www.cve.org/),
- "Scan now", "Settings…" and "Quit".

## How it works

- **Installed packages:** `pacman -Q` lists everything in the local pacman
  database. That includes AUR packages built by paru/yay. `pacman -Qm`
  identifies which of them are AUR or other foreign packages.
- **Vulnerability data:** the
  [Arch Linux Security Tracker](https://security.archlinux.org/) feed
  (`https://security.archlinux.org/all.json`), the same feed `arch-audit` uses.
  It maps pacman package names and versions to CVE IDs, with the version that
  fixes each issue and its severity. CachyOS packages use the same names as
  their Arch counterparts, so they match directly. CVE IDs link to cve.org.
  (cve.org itself cannot answer "which CVEs affect package X at version Y",
  so a distribution tracker is needed for the matching.)
- **Matching:** a package is vulnerable when it is listed in an advisory
  group that is not marked "Not affected", and either no fix exists yet or the
  installed version is older than the fixed version. Versions are compared
  with a built-in port of pacman's own `vercmp`, so CachyOS rebuilds such as
  `2.40-1.1` count as including the fix from `2.40-1`.

## Resource usage

- The tray process idles at about **5 MB RSS and 0% CPU**. It wakes every
  2 minutes for a single `stat()` of `/var/lib/pacman/local`, to notice
  package changes.
- Each scan runs as a short-lived child process at the lowest CPU and I/O
  priority (nice 19, idle I/O class). Matching about 6,000 advisory groups
  against 1,800 packages takes about **50 ms and 13 MB**. That memory goes
  back to the system as soon as the scan ends.
- **Network:** the feed is downloaded at most every 6 hours, with
  `ETag`/`If-Modified-Since` and gzip, so an unchanged feed costs one tiny
  `304` response.
- When you install or upgrade packages, Gengar re-checks against the cached
  feed without downloading anything. The red icon clears by itself after you
  update.

## Installation

### With makepkg (recommended)

```bash
git clone https://github.com/1stNox/gengar.git
cd gengar/packaging
makepkg -si
```

This installs:
- `/usr/bin/gengar`,
- the icons,
- an application menu entry,
- an **autostart entry** (`/etc/xdg/autostart/gengar.desktop`).

Gengar starts automatically at your next login. To start it right away:

```bash
gengar &
```

The PKGBUILD builds from the `main` branch on GitHub.

### Without root (current user only)

```bash
make install-user
```

This installs to `~/.local/bin` and adds `~/.config/autostart/gengar.desktop`.
Remove it again with `make uninstall-user`.

### systemd user service (optional)

The XDG autostart entry starts Gengar. If you prefer systemd, which also
enforces hard limits (`MemoryMax=128M`, `CPUQuota=10%`), use the service
instead:

```bash
systemctl --user enable --now gengar.service
```

Only one instance can run at a time, so enabling both is harmless.

### Desktop support

The tray icon uses the freedesktop StatusNotifierItem protocol. It works out of
the box on **KDE Plasma** (the CachyOS default), XFCE, Cinnamon, LXQt, Budgie,
Hyprland/Sway bars with a tray module (e.g. waybar), and others. On **GNOME**,
install and enable the AppIndicator extension
(`gnome-shell-extension-appindicator`).

## Command line

```
gengar [tray]            Run in the background with a tray icon (default)
gengar scan [OPTIONS]    Scan once and print a table
gengar report            Scan once and open the HTML report

scan options:
  --json                 JSON output
  --offline              Only use the cached feed
  --refresh              Always check for a newer feed
  --max-feed-age <SECS>  Refresh when the cached feed is older than this
  --feed <URL|FILE>      Use another feed in Arch Security Tracker format
  --no-report            Do not write ~/.cache/gengar/report.html
```

`gengar scan` exits with `0` when nothing reaches the alert level, `3` when it
finds dangerous vulnerabilities and `1` on errors. That makes it usable in
scripts.

Example:

```
$ gengar scan
Gengar scan of 1432 installed packages, 2026-11-06 12:16
Feed: https://security.archlinux.org/all.json (updated 2 h ago, 5123 advisory groups)

SEVERITY  PACKAGE                       INSTALLED  FIXED IN       ADVISORY  CVEs
Critical  openssl                       3.3.1-1.1  3.3.2-1        AVG-9001  CVE-2026-10001, CVE-2026-10002
High      curl                          8.10.1-1   not fixed yet  AVG-9002  CVE-2026-10003
Medium    visual-studio-code-bin [AUR]  1.95.1-1   not fixed yet  AVG-9007  CVE-2026-10011

3 vulnerable packages (1 Critical, 1 High, 1 Medium).
```

(The output above uses made-up sample data.)

## Configuration

`~/.config/gengar/config.toml` is optional. The "Settings…" menu entry creates
it with these defaults:

```toml
scan_interval_hours = 6      # how often to refresh the vulnerability feed
alert_severity = "high"      # low | medium | high | critical: what counts as dangerous
notify = true                # desktop notification for new dangerous findings
stale_after_days = 7         # grey icon if the feed could not be refreshed for this long
feed_url = "https://security.archlinux.org/all.json"
ignore = []                  # acknowledged AVG IDs, CVE IDs or package names
```

Changes take effect on the next scan; no restart needed. A notification is
shown only once per new issue, never again for the same issue.

Files Gengar writes:
- `~/.cache/gengar/`: feed cache and the latest `report.html` / `last-scan.json`
- `~/.local/state/gengar/state.json`: which alerts were already notified

## Limitations

- Coverage is only as good as the Arch Security Tracker. Its maintenance has
  slowed down, so very recent CVEs may be missing. The tray shows how old the
  feed is, and `feed_url` can point to another feed in the same format.
- AUR packages and CachyOS-only packages (for example `linux-cachyos`) are
  matched only when their name is also a tracked Arch package. AUR packages
  are labelled as such in the report.
- Gengar reports known vulnerabilities in packaged software. It does not
  detect malware or misconfiguration.

## Development

```bash
cargo test                                    # unit tests, incl. pacman's vercmp test vectors
GENGAR_PACMAN=tests/fixtures/fake-pacman \
  cargo run -- scan --feed tests/fixtures/all.json
```

Environment overrides used in tests:
- `GENGAR_PACMAN`: pacman binary
- `GENGAR_PACMAN_DB`: directory watched for package changes
- `GENGAR_CONFIG`: config file
- `GENGAR_CACHE_DIR`, `GENGAR_STATE_DIR`: where Gengar writes its files

## License

MIT, see [LICENSE](LICENSE).

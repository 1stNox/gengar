PREFIX ?= /usr/local
SYSCONFDIR ?= /etc
DESTDIR ?=
BINDIR := $(PREFIX)/bin
DATADIR := $(PREFIX)/share
ICONS := $(wildcard assets/icons/hicolor/scalable/apps/*.svg)
BIN := target/release/gengar

.PHONY: all build test install uninstall install-user uninstall-user

all: build

build:
	cargo build --release --locked

test:
	cargo test --locked

# System-wide install (used by the PKGBUILD): make PREFIX=/usr DESTDIR=... install
install:
	install -Dm755 $(BIN) "$(DESTDIR)$(BINDIR)/gengar"
	install -Dm644 assets/gengar.desktop "$(DESTDIR)$(DATADIR)/applications/gengar.desktop"
	install -Dm644 assets/gengar.desktop "$(DESTDIR)$(SYSCONFDIR)/xdg/autostart/gengar.desktop"
	install -dm755 "$(DESTDIR)$(PREFIX)/lib/systemd/user"
	sed 's|@BINDIR@|$(BINDIR)|' assets/gengar.service > "$(DESTDIR)$(PREFIX)/lib/systemd/user/gengar.service"
	for f in $(ICONS); do install -Dm644 "$$f" "$(DESTDIR)$(DATADIR)/icons/hicolor/scalable/apps/$$(basename $$f)"; done
	install -Dm644 LICENSE "$(DESTDIR)$(DATADIR)/licenses/gengar/LICENSE"

uninstall:
	rm -f "$(DESTDIR)$(BINDIR)/gengar"
	rm -f "$(DESTDIR)$(DATADIR)/applications/gengar.desktop"
	rm -f "$(DESTDIR)$(SYSCONFDIR)/xdg/autostart/gengar.desktop"
	rm -f "$(DESTDIR)$(PREFIX)/lib/systemd/user/gengar.service"
	rm -f "$(DESTDIR)$(DATADIR)/licenses/gengar/LICENSE"
	for f in $(ICONS); do rm -f "$(DESTDIR)$(DATADIR)/icons/hicolor/scalable/apps/$$(basename $$f)"; done

# Install for the current user only, without root: make install-user
USER_BIN := $(HOME)/.local/bin
USER_DATA := $(HOME)/.local/share
USER_AUTOSTART := $(HOME)/.config/autostart

install-user: build
	install -Dm755 $(BIN) "$(USER_BIN)/gengar"
	install -dm755 "$(USER_DATA)/applications" "$(USER_AUTOSTART)"
	sed 's|^Exec=gengar|Exec=$(USER_BIN)/gengar|' assets/gengar.desktop > "$(USER_DATA)/applications/gengar.desktop"
	sed 's|^Exec=gengar|Exec=$(USER_BIN)/gengar|' assets/gengar.desktop > "$(USER_AUTOSTART)/gengar.desktop"
	for f in $(ICONS); do install -Dm644 "$$f" "$(USER_DATA)/icons/hicolor/scalable/apps/$$(basename $$f)"; done

uninstall-user:
	rm -f "$(USER_BIN)/gengar"
	rm -f "$(USER_DATA)/applications/gengar.desktop"
	rm -f "$(USER_AUTOSTART)/gengar.desktop"
	for f in $(ICONS); do rm -f "$(USER_DATA)/icons/hicolor/scalable/apps/$$(basename $$f)"; done

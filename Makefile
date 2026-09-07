.PHONY: all build release debug install uninstall test check strict clean completions man run-daemon

all: release

# Debug build of all crates.
debug:
	cargo build --workspace

# Release build of daemon and CLI.
release:
	cargo build --release -p ingotd -p ingot-cli

# Install release binaries to /usr/local (or PREFIX=...).
install: release
	./scripts/install.sh --prefix=$(or $(PREFIX),/usr/local)

# Uninstall binaries and systemd unit.
uninstall:
	rm -f $(or $(PREFIX),/usr/local)/bin/ingotd
	rm -f $(or $(PREFIX),/usr/local)/bin/ingot
	rm -f $(or $(PREFIX),/usr/local)/share/man/man1/ingot.1
	rm -f $(or $(PREFIX),/usr/local)/share/man/man8/ingotd.8
	rm -f /etc/systemd/system/ingotd.service
	systemctl daemon-reload 2>/dev/null || true

# Tier-1 gates: fmt, clippy, tests.
check:
	./scripts/check.sh

# Strict gates: deny all clippy warnings.
strict:
	./scripts/check.sh --strict

# Alias.
test: check

# Clean build artifacts.
clean:
	cargo clean

# Generate shell completions into target/completions/.
completions: release
	@mkdir -p target/completions
	./target/release/ingot completions bash > target/completions/ingot
	./target/release/ingot completions zsh  > target/completions/_ingot
	./target/release/ingot completions fish > target/completions/ingot.fish
	@echo "Completions in target/completions/"

# Validate the static man pages render without warnings.
man:
	@command -v groff >/dev/null || (echo "groff not installed; skipping man render check" && exit 0)
	groff -man -Tascii docs/man/ingot.1 > /dev/null
	groff -man -Tascii docs/man/ingotd.8 > /dev/null
	@echo "Man pages render clean."

# Start the daemon in debug mode (requires root).
run-daemon: debug
	sudo ./target/debug/ingotd --debug

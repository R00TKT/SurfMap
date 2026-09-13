#!/usr/bin/env bash
# Set up surfmap after cloning: check the toolchain, build, test, install.
#
#   ./scripts/install.sh                 # build, test, install onto PATH
#   ./scripts/install.sh --no-install    # build and test only
#   ./scripts/install.sh --skip-tests    # skip the test suite
#   ./scripts/install.sh --yes           # never prompt (for CI / scripted setup)
#
# Nothing here contacts a network host except cargo's crate registry, and
# rustup's installer if you ask for it.
set -euo pipefail

MIN_RUST="1.88"
ASSUME_YES=0
RUN_TESTS=1
DO_INSTALL=1

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

# Colour only when stdout is a terminal, so piping to a log stays clean.
if [ -t 1 ]; then
    B=$'\033[1m'; G=$'\033[32m'; Y=$'\033[33m'; R=$'\033[31m'; N=$'\033[0m'
else
    B=""; G=""; Y=""; R=""; N=""
fi
say()  { printf '%s==>%s %s\n' "$B" "$N" "$*"; }
ok()   { printf '  %s+%s %s\n' "$G" "$N" "$*"; }
warn() { printf '  %s!%s %s\n' "$Y" "$N" "$*"; }
die()  { printf '  %sx%s %s\n' "$R" "$N" "$*" >&2; exit 1; }

usage() {
    # The header comment block is the help text; print it, minus the shebang.
    awk 'NR>1 && /^#/ { sub(/^# ?/, ""); print; next } NR>1 { exit }' "$0"
    exit 0
}

for arg in "$@"; do
    case "$arg" in
        --yes|-y)     ASSUME_YES=1 ;;
        --skip-tests) RUN_TESTS=0 ;;
        --no-install) DO_INSTALL=0 ;;
        -h|--help)    usage ;;
        *)            die "unknown option: $arg (try --help)" ;;
    esac
done

# Ask a yes/no question. Non-interactive or --yes answers itself.
confirm() {
    [ "$ASSUME_YES" = 1 ] && return 0
    [ -t 0 ] || return 1
    printf '  %s?%s %s [y/N] ' "$Y" "$N" "$1"
    read -r reply
    [[ "$reply" =~ ^[Yy] ]]
}

# Is $1 >= $2, comparing dotted version numbers?
version_ge() {
    [ "$(printf '%s\n%s\n' "$2" "$1" | sort -V | head -1)" = "$2" ]
}

# --- 1. Rust toolchain ----------------------------------------------------
say "Checking the Rust toolchain"

if ! command -v cargo >/dev/null 2>&1; then
    # rustup may be installed but not yet on this shell's PATH.
    if [ -f "${CARGO_HOME:-$HOME/.cargo}/env" ]; then
        # shellcheck disable=SC1091
        . "${CARGO_HOME:-$HOME/.cargo}/env"
    fi
fi

if ! command -v cargo >/dev/null 2>&1; then
    warn "cargo not found."
    if confirm "Install Rust now via rustup (https://sh.rustup.rs)?"; then
        curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
        # shellcheck disable=SC1091
        . "${CARGO_HOME:-$HOME/.cargo}/env"
    else
        die "Rust is required. Install it from https://rustup.rs and re-run."
    fi
fi

RUSTC_VERSION="$(rustc --version | awk '{print $2}')"
if ! version_ge "$RUSTC_VERSION" "$MIN_RUST"; then
    warn "rustc $RUSTC_VERSION is older than the required $MIN_RUST (edition 2024)."
    if command -v rustup >/dev/null 2>&1; then
        if confirm "Run 'rustup update stable'?"; then
            rustup update stable
            RUSTC_VERSION="$(rustc --version | awk '{print $2}')"
            version_ge "$RUSTC_VERSION" "$MIN_RUST" \
                || die "still on rustc $RUSTC_VERSION; surfmap needs $MIN_RUST+."
        else
            die "surfmap needs rustc $MIN_RUST or newer."
        fi
    else
        die "rustc $RUSTC_VERSION is too old and rustup is not installed.
     Distribution Rust packages are often behind; install from https://rustup.rs."
    fi
fi
ok "rustc $RUSTC_VERSION"

# --- 2. C toolchain -------------------------------------------------------
# The only non-Rust requirement: rusqlite's `bundled` feature compiles SQLite
# from source. TLS is rustls, so there is no OpenSSL dependency.
say "Checking the C toolchain (SQLite is compiled from source)"
if command -v cc >/dev/null 2>&1 || command -v gcc >/dev/null 2>&1 || command -v clang >/dev/null 2>&1; then
    ok "C compiler present"
else
    warn "No C compiler found. Install one, then re-run:"
    case "$(uname -s)" in
        Linux)
            if   command -v apt    >/dev/null 2>&1; then echo "      sudo apt install -y build-essential"
            elif command -v dnf    >/dev/null 2>&1; then echo "      sudo dnf install -y gcc make"
            elif command -v pacman >/dev/null 2>&1; then echo "      sudo pacman -S --needed base-devel"
            else echo "      install your distribution's C build tools"
            fi ;;
        Darwin) echo "      xcode-select --install" ;;
        *)      echo "      install a C compiler for your platform" ;;
    esac
    die "C compiler required."
fi

# --- 3. Build -------------------------------------------------------------
# --locked builds against the committed Cargo.lock exactly, so what you get is
# what was tested.
say "Building surfmap (release, --locked)"
cargo build --release --locked
ok "target/release/surfmap"

# --- 4. Test --------------------------------------------------------------
if [ "$RUN_TESTS" = 1 ]; then
    say "Running the test suite (loopback only, no external network)"
    cargo test --locked --quiet
    ok "tests passed"
else
    warn "skipping tests (--skip-tests)"
fi

# --- 5. Install -----------------------------------------------------------
if [ "$DO_INSTALL" = 1 ]; then
    say "Installing surfmap onto your PATH"
    cargo install --path . --locked --force
    BIN_DIR="${CARGO_HOME:-$HOME/.cargo}/bin"
    ok "installed to $BIN_DIR/surfmap"

    if ! command -v surfmap >/dev/null 2>&1; then
        warn "$BIN_DIR is not on your PATH. Add it:"
        echo "      echo 'export PATH=\"$BIN_DIR:\$PATH\"' >> ~/.bashrc"
        echo "      export PATH=\"$BIN_DIR:\$PATH\""
    fi

    # --- man page ---------------------------------------------------------
    # Installed per-user, so this never needs sudo. Most man implementations
    # search ~/.local/share/man automatically; macOS generally does not, so
    # check rather than assume and tell the operator only when it is needed.
    MAN_DIR="${XDG_DATA_HOME:-$HOME/.local/share}/man/man1"
    if mkdir -p "$MAN_DIR" 2>/dev/null && cp man/surfmap.1 "$MAN_DIR/surfmap.1" 2>/dev/null; then
        ok "man page installed to $MAN_DIR/surfmap.1"
        if ! man -w surfmap >/dev/null 2>&1; then
            warn "\`man surfmap\` will not find it until that directory is searched:"
            echo "      echo 'export MANPATH=\"${XDG_DATA_HOME:-\$HOME/.local/share}/man:\$MANPATH\"' >> ~/.bashrc"
            echo "      (or read it directly: man $MAN_DIR/surfmap.1)"
        fi
    else
        warn "could not install the man page; read it with: man ./man/surfmap.1"
    fi
else
    warn "skipping install (--no-install); binary is at target/release/surfmap"
    warn "read the man page without installing: man ./man/surfmap.1"
fi

# --- Done -----------------------------------------------------------------
echo
say "Ready"
if command -v surfmap >/dev/null 2>&1; then
    echo "  $(surfmap --version)"
    SURFMAP=surfmap
else
    SURFMAP=./target/release/surfmap
fi
cat <<EOF

  Try it against the bundled local fixture (needs python3):
    ./scripts/demo.sh

  Against a target you are authorized to test:
    $SURFMAP crawl https://target.example.com/ --depth 3 --rate-limit 2
    $SURFMAP report summary
    $SURFMAP report forms

  surfmap sends real traffic. Only point it at systems you have written
  permission to test.
EOF

#!/bin/bash

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUILD_DIR="$PROJECT_DIR/build"
PAM_BUILD_DIR="$BUILD_DIR/pam"


INSTALL_DIR="/usr/lib/security"

DO_INSTALL=0
if [ "${1:-}" = "--install" ]; then
    DO_INSTALL=1
fi

echo "=== Building Authenticator for PAM Integration ==="
need_cmd() {
    local cmd="$1"
    local hint="$2"
    if ! command -v "$cmd" >/dev/null 2>&1; then
        echo "Error: required tool '$cmd' not found. $hint"
        exit 1
    fi
}

need_cmd cmake "Install cmake package."
need_cmd make "Install make package."

echo ""
echo "Step 1: Preparing build directory..."
mkdir -p "$BUILD_DIR"
cmake -S "$PROJECT_DIR" -B "$BUILD_DIR"


echo "Building main Authenticator..."
cmake --build "$BUILD_DIR"
echo "Authenticator built"

echo "Step 2: Creating PAM module build..."
mkdir -p "$PAM_BUILD_DIR"

echo "Step 3: Compiling PAM module..."
cmake --build "$BUILD_DIR" --target pam_authenticator
echo "PAM module built: $PAM_BUILD_DIR/pam_authenticator.so"

echo "Step 4: Creating test PAM configuration..."
mkdir -p "$PROJECT_DIR/pam_config"
cat > "$PROJECT_DIR/pam_config/authenticator-test" << 'EOF'
#%PAM-1.0
# Test PAM configuration for device authenticator
auth       required pam_authenticator.so
account    required pam_permit.so
session    required pam_permit.so
EOF
echo "Created: $PROJECT_DIR/pam_config/authenticator-test"


echo "=== Build Complete ==="
echo "PAM Module Location:"
echo "  $PAM_BUILD_DIR/pam_authenticator.so"

if [ "$DO_INSTALL" -eq 1 ]; then
    echo "=== Installing PAM Authenticator Module ==="
    sudo install -m 0644 "$PAM_BUILD_DIR/pam_authenticator.so" "$INSTALL_DIR/pam_authenticator.so"
    echo "PAM module installed: $INSTALL_DIR/pam_authenticator.so"
    echo ""
    echo "Exported PAM symbols:"
    nm -D "$INSTALL_DIR/pam_authenticator.so" | grep "pam_sm" || true
    sudo cp build/pam/pam_authenticator.so /usr/lib/security/
    sudo cp pam_config/authenticator-test /etc/pam.d/
else
    echo "Skipping install. Use '--install' to install to $INSTALL_DIR."
fi
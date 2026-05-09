#!/usr/bin/env bash

set -e

RED='\033[0;31m'; GREEN='\033[0;32m'; CYAN='\033[0;36m'
YELLOW='\033[1;33m'; BOLD='\033[1m'; NC='\033[0m'

INSTALL_DIR="$HOME/.local/bin"
TOOL_DIR="$HOME/.cryptoforensics"

echo -e "${CYAN}"
echo "  ╔══════════════════════════════════════════════════╗"
echo "  ║       CRYPTOFORENSICS SUITE — INSTALLER         ║"
echo "  ║       Hash · Steganography · Entropy             ║"
echo "  ╚══════════════════════════════════════════════════╝"
echo -e "${NC}"


echo -e "${BOLD}[1/5] Checking Python version...${NC}"
if command -v python3 &>/dev/null; then
    PYTHON=$(command -v python3)
    PY_VER=$($PYTHON --version 2>&1)
    echo -e "  ${GREEN}✓${NC} Found: $PY_VER"
else
    echo -e "  ${RED}✗ Python 3 not found. Install with:${NC}"
    echo -e "    sudo apt install python3 python3-pip"
    exit 1
fi


echo -e "${BOLD}[2/5] Checking pip...${NC}"
if $PYTHON -m pip --version &>/dev/null; then
    echo -e "  ${GREEN}✓${NC} pip available"
else
    echo -e "  ${YELLOW}Installing pip...${NC}"
    $PYTHON -m ensurepip --upgrade 2>/dev/null || {
        sudo apt-get install -y python3-pip 2>/dev/null || true
    }
fi


echo -e "${BOLD}[3/5] Installing dependencies...${NC}"

echo -e "  Installing [rich] — Beautiful terminal output..."
$PYTHON -m pip install rich --quiet --break-system-packages 2>/dev/null \
    || $PYTHON -m pip install rich --quiet 2>/dev/null \
    || { echo -e "  ${YELLOW}⚠ rich install failed (will use plain output)${NC}"; }
echo -e "  ${GREEN}✓${NC} rich"

echo -e "  Installing [Pillow] — Image processing for steganography..."
$PYTHON -m pip install Pillow --quiet --break-system-packages 2>/dev/null \
    || $PYTHON -m pip install Pillow --quiet 2>/dev/null \
    || { echo -e "  ${YELLOW}⚠ Pillow install failed (stego module unavailable)${NC}"; }
echo -e "  ${GREEN}✓${NC} Pillow"


echo -e "${BOLD}[4/5] Installing tool files...${NC}"

mkdir -p "$TOOL_DIR" "$INSTALL_DIR"

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cp "$SCRIPT_DIR/cryptoforensics.py" "$TOOL_DIR/cryptoforensics.py"
chmod +x "$TOOL_DIR/cryptoforensics.py"


cat > "$INSTALL_DIR/cryptoforensics" << EOF
#!/usr/bin/env bash
exec $PYTHON "$TOOL_DIR/cryptoforensics.py" "\$@"
EOF
chmod +x "$INSTALL_DIR/cryptoforensics"

echo -e "  ${GREEN}✓${NC} Installed to: $TOOL_DIR"
echo -e "  ${GREEN}✓${NC} Launcher:     $INSTALL_DIR/cryptoforensics"


echo -e "${BOLD}[5/5] Configuring PATH...${NC}"

SHELL_RC=""
if [[ "$SHELL" == *"zsh"* ]]; then SHELL_RC="$HOME/.zshrc"
elif [[ "$SHELL" == *"bash"* ]]; then SHELL_RC="$HOME/.bashrc"
else SHELL_RC="$HOME/.profile"; fi

if [[ ":$PATH:" != *":$INSTALL_DIR:"* ]]; then
    echo "" >> "$SHELL_RC"
    echo "# CryptoForensics Suite" >> "$SHELL_RC"
    echo "export PATH=\"\$HOME/.local/bin:\$PATH\"" >> "$SHELL_RC"
    echo -e "  ${GREEN}✓${NC} Added to PATH in $SHELL_RC"
    echo -e "  ${YELLOW}→  Run: source $SHELL_RC${NC}"
else
    echo -e "  ${GREEN}✓${NC} PATH already includes $INSTALL_DIR"
fi

echo ""
echo -e "${GREEN}${BOLD}╔══════════════════════════════════════════╗${NC}"
echo -e "${GREEN}${BOLD}║  Installation complete!                  ║${NC}"
echo -e "${GREEN}${BOLD}╚══════════════════════════════════════════╝${NC}"
echo ""
echo -e "${CYAN}QUICK START:${NC}"
echo ""
echo -e "  ${BOLD}Hash identification:${NC}"
echo -e "  ${YELLOW}cryptoforensics hash identify 5f4dcc3b5aa765d61d8327deb882cf99${NC}"
echo ""
echo -e "  ${BOLD}Generate hashes:${NC}"
echo -e "  ${YELLOW}cryptoforensics hash generate \"mypassword\"${NC}"
echo ""
echo -e "  ${BOLD}Hash cracking:${NC}"
echo -e "  ${YELLOW}cryptoforensics hash crack <hash> --wordlist rockyou.txt${NC}"
echo ""
echo -e "  ${BOLD}Steganography analysis:${NC}"
echo -e "  ${YELLOW}cryptoforensics stego analyze image.png --save-vis${NC}"
echo ""
echo -e "  ${BOLD}Entropy analysis:${NC}"
echo -e "  ${YELLOW}cryptoforensics entropy file suspicious.bin${NC}"
echo ""
echo -e "  ${BOLD}Full help:${NC}"
echo -e "  ${YELLOW}cryptoforensics --help${NC}"
echo ""

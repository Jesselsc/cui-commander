#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
VENV_DIR="${REPO_ROOT}/.venv"
PYTHON_BIN="python3"

cd "${REPO_ROOT}"
export PATH="/opt/homebrew/bin:/usr/local/bin:${PATH}"

echo "== MSTechAlpine Fleet Commander Bootstrap =="

auto_install() {
  local pkg="$1"
  # macOS — Homebrew
  if command -v brew >/dev/null 2>&1; then
    echo "Installing ${pkg} via Homebrew..."
    brew install "${pkg}" || true
  # Debian/Ubuntu
  elif command -v apt-get >/dev/null 2>&1; then
    echo "Installing ${pkg} via apt-get..."
    sudo apt-get install -y "${pkg}" || true
  # RHEL/Fedora/CentOS
  elif command -v dnf >/dev/null 2>&1; then
    echo "Installing ${pkg} via dnf..."
    sudo dnf install -y "${pkg}" || true
  elif command -v yum >/dev/null 2>&1; then
    echo "Installing ${pkg} via yum..."
    sudo yum install -y "${pkg}" || true
  else
    echo "WARNING: Cannot auto-install ${pkg} — no supported package manager found."
    echo "  macOS:  brew install ${pkg}"
    echo "  Ubuntu: sudo apt-get install -y ${pkg}"
    echo "  RHEL:   sudo dnf install -y ${pkg}"
    echo "  NOTE: Network discovery will be skipped until nmap is installed."
    echo "        Local diagnostic checks still run without it."
  fi
}

if ! command -v "${PYTHON_BIN}" >/dev/null 2>&1; then
  echo "ERROR: python3 is not installed. Install Python 3.10+ and rerun."
  exit 1
fi

if [[ ! -d "${VENV_DIR}" ]]; then
  echo "Creating virtual environment..."
  "${PYTHON_BIN}" -m venv "${VENV_DIR}"
fi

# shellcheck source=/dev/null
source "${VENV_DIR}/bin/activate"

echo "Upgrading pip..."
python -m pip install --upgrade pip >/dev/null

echo "Installing Python dependencies..."
pip install -r "${REPO_ROOT}/requirements.txt" >/dev/null
pip install -e "${REPO_ROOT}" >/dev/null

if ! command -v nmap >/dev/null 2>&1; then
  echo "nmap not found. Attempting install..."
  auto_install nmap
fi

if ! command -v dot >/dev/null 2>&1; then
  echo "graphviz (dot) not found. Attempting install..."
  auto_install graphviz
fi

mkdir -p "${REPO_ROOT}/evidence"
if [[ ! -f "${REPO_ROOT}/evidence/asset-tags.json" ]]; then
  cat > "${REPO_ROOT}/evidence/asset-tags.json" <<'JSON'
{
  "192.168.1.10": "CUI Asset",
  "192.168.1.20": "Security Protection Asset",
  "192.168.1.30": "Contractor Risk Managed Asset",
  "192.168.1.40": "Out-of-Scope"
}
JSON
fi

echo
echo "Environment ready."
echo "Python: $(python --version)"
echo "Venv: ${VENV_DIR}"
echo "nmap: $(command -v nmap || echo 'not installed')"
echo "dot: $(command -v dot || echo 'not installed')"
echo
echo "Choose run mode:"
echo "  1) Local diagnostic only (this machine)"
echo "  2) Full C3PAO evidence package — auto-detect subnet (recommended)"
echo "  3) Discovery scan — specify CIDR manually"
echo "  4) Discovery + fleet orchestration"
echo "  5) Exit"
choice="5"
if ! read -r -p "Selection [1-5]: " choice; then
  choice="5"
fi

case "${choice}" in
  1)
    fleet-commander \
      --json-output "${REPO_ROOT}/evidence/diagnostic.json"
    ;;
  2)
    sudo fleet-commander \
      --discover-network auto \
      --auto-tag \
      --asset-tags "${REPO_ROOT}/evidence/asset-tags.json" \
      --discovery-output "${REPO_ROOT}/evidence/fleet-discovery.json" \
      --diagram-output "${REPO_ROOT}/evidence/network-architecture.svg" \
      --sbom-output "${REPO_ROOT}/evidence/sbom.json" \
      --srm "${REPO_ROOT}/evidence/srm.xlsx" \
      --vuln-scan \
      --vuln-output "${REPO_ROOT}/evidence/vulns.json" \
      --html-output "${REPO_ROOT}/evidence/report.html" \
      --cloud-api \
      --sanitize \
      --json-output "${REPO_ROOT}/evidence/diagnostic-c3pao.json"
    ;;
  3)
    target=""
    if ! read -r -p "Enter CIDR/range (example 192.168.1.0/24): " target; then
      echo "No input provided. Exit."
      exit 0
    fi
    sudo fleet-commander \
      --discover-network "${target}" \
      --auto-tag \
      --asset-tags "${REPO_ROOT}/evidence/asset-tags.json" \
      --discovery-output "${REPO_ROOT}/evidence/fleet-discovery.json" \
      --diagram-output "${REPO_ROOT}/evidence/network-architecture.svg" \
      --json-output "${REPO_ROOT}/evidence/diagnostic.json"
    ;;
  4)
    target=""
    fleet_user=""
    fleet_key=""
    if ! read -r -p "Enter CIDR/range (example 192.168.1.0/24): " target; then
      echo "No target provided. Exit."
      exit 0
    fi
    if ! read -r -p "Fleet SSH user: " fleet_user; then
      echo "No fleet user provided. Exit."
      exit 0
    fi
    if ! read -r -p "SSH key path (blank for default key agent): " fleet_key; then
      fleet_key=""
    fi

    cmd=(
      fleet-commander
      --discover-network "${target}"
      --auto-tag
      --asset-tags "${REPO_ROOT}/evidence/asset-tags.json"
      --discovery-output "${REPO_ROOT}/evidence/fleet-discovery.json"
      --diagram-output "${REPO_ROOT}/evidence/network-architecture.svg"
      --fleet-run
      --fleet-user "${fleet_user}"
      --json-output "${REPO_ROOT}/evidence/diagnostic.json"
    )

    if [[ -n "${fleet_key}" ]]; then
      cmd+=(--fleet-ssh-key "${fleet_key}")
    fi

    "${cmd[@]}"
    ;;
  *)
    echo "Exit."
    ;;
esac

echo
echo "Done. Evidence artifacts are in ${REPO_ROOT}/evidence"

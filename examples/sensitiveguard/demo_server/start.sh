#!/usr/bin/env bash
# One-shot setup and launch for the SensitiveGuard demo on a fresh server.
#
#   ./start.sh                     # 127.0.0.1:8080, no token
#   HOST=0.0.0.0 PORT=8080 ./start.sh
#   SG_DEMO_TOKEN=$(openssl rand -hex 16) HOST=0.0.0.0 ./start.sh
#
# Creates .venv next to the repository, installs the package, runs the whole
# test corpus, and only starts serving if every case passes.
set -euo pipefail

HOST="${HOST:-127.0.0.1}"
PORT="${PORT:-8080}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "${HERE}/../../.." && pwd)"
VENV="${VENV:-${REPO}/.venv}"

if [ ! -x "${VENV}/bin/python" ]; then
  echo "==> 创建虚拟环境 ${VENV}"
  python3 -m venv "${VENV}"
fi

echo "==> 安装 smolagents + sensitiveguard"
"${VENV}/bin/pip" install --quiet --upgrade pip
"${VENV}/bin/pip" install --quiet -e "${REPO}"

echo "==> 运行全部用例（不通过就不启动服务）"
"${VENV}/bin/python" "${HERE}/run_cases.py"

echo "==> 启动服务 http://${HOST}:${PORT}/"
if [ "${HOST}" != "127.0.0.1" ] && [ "${HOST}" != "localhost" ] && [ -z "${SG_DEMO_TOKEN:-}" ]; then
  echo "    警告：对外监听但未设置 SG_DEMO_TOKEN，控制台将无鉴权。" >&2
fi
exec "${VENV}/bin/python" "${HERE}/server.py" --host "${HOST}" --port "${PORT}"

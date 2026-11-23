#!/usr/bin/env bash
# Gera o projeto Android do Tauri e aplica o overlay versionado (apps/desktop/android/overlay).
#
# O diretório apps/desktop/src-tauri/gen/ é ignorado pelo git: ele é recriado a cada preparação.
# Tudo que é específico do URE (versões Gradle, Chaquopy, MainActivity, rede) fica no overlay.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../../../.." && pwd)"
SRC_TAURI="$ROOT/apps/desktop/src-tauri"
OVERLAY="$ROOT/apps/desktop/android/overlay"

cd "$SRC_TAURI"
cargo tauri android init --ci --skip-targets-install
cp -R "$OVERLAY/." "$SRC_TAURI/gen/android/"
echo "overlay aplicado em $SRC_TAURI/gen/android"

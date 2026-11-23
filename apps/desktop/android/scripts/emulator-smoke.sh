#!/usr/bin/env bash
# Teste de instalação no emulador: instala o APK, abre o aplicativo e confirma que a interface
# do URE ficou online (token aceito pelo backend embutido). Falha se houver crash ou erro de início.
#
# Uso: emulator-smoke.sh <apk> [pasta_de_saida]
set -euo pipefail

APK="$1"
OUT="${2:-${RUNNER_TEMP:-/tmp}/emulator-smoke}"
PKG="dev.ure.desktop"
mkdir -p "$OUT"

adb wait-for-device
until [ "$(adb shell getprop sys.boot_completed 2>/dev/null | tr -d '\r')" = "1" ]; do sleep 2; done
adb install -r "$APK"
adb logcat -c
adb logcat -v threadtime > "$OUT/logcat-live.txt" 2>&1 &
LOGCAT_PID=$!
adb shell am start -n "$PKG/.MainActivity"
seen_pid=""

online=0
for _ in $(seq 1 75); do
  p="$(adb shell pidof "$PKG" 2>/dev/null | tr -d '\r' || true)"
  if [ -n "$p" ]; then seen_pid="$p"; fi
  adb shell uiautomator dump /sdcard/ui.xml >/dev/null 2>&1 || true
  adb pull /sdcard/ui.xml "$OUT/ui.xml" >/dev/null 2>&1 || true
  if [ -f "$OUT/ui.xml" ] && grep -q "Não foi possível iniciar" "$OUT/ui.xml"; then
    break
  fi
  if [ -f "$OUT/ui.xml" ] && grep -q "online ·" "$OUT/ui.xml"; then
    online=1
    break
  fi
  sleep 2
done

adb exec-out screencap -p > "$OUT/screen.png" || true
kill "$LOGCAT_PID" 2>/dev/null || true
cp "$OUT/logcat-live.txt" "$OUT/logcat.txt" 2>/dev/null || true
adb shell am force-stop "$PKG" || true

# Diagnóstico visível no próprio log do passo (os artefatos exigem login para baixar).
diagnose() {
  echo "--- PID visto durante o teste: ${seen_pid:-nenhum} ---"
  echo "--- término, sinais nativos, memória e erros do app ---"
  grep -iE "dev\.ure|ure_desktop|Fatal signal|tombstone|panicked|RustStdout|died|lowmemory|Killing|am_proc|am_kill|am_crash|ActivityManager|AndroidRuntime|FATAL|DEBUG *:" "$OUT/logcat.txt" | grep -viE "AiAiEcho|nativeloader|GestureNavBar|NGA disabled" | tail -200 || true
  if [ -n "${seen_pid:-}" ]; then
    echo "--- linhas do processo $seen_pid ---"
    grep " ${seen_pid} " "$OUT/logcat.txt" | grep -viE "AiAiEcho|nativeloader|GestureNavBar|NGA disabled" | tail -250 || true
  fi
  echo "--- crash buffer ---"
  adb logcat -b crash -d 2>/dev/null | tail -60 || true
}

if grep -q "FATAL EXCEPTION" "$OUT/logcat.txt"; then
  diagnose; echo "::error::o aplicativo travou"; exit 1
fi
if [ -f "$OUT/ui.xml" ] && grep -q "Não foi possível iniciar" "$OUT/ui.xml"; then
  diagnose; echo "::error::o aplicativo mostrou erro ao iniciar o backend"; exit 1
fi
if [ "$online" != 1 ]; then
  diagnose; echo "::error::a interface não ficou online em 150 s"; exit 1
fi
echo "teste de instalação no emulador: interface online"

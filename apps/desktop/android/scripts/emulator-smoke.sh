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
adb shell am start -n "$PKG/.MainActivity"

online=0
for _ in $(seq 1 75); do
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
adb logcat -d > "$OUT/logcat.txt" || true
adb shell am force-stop "$PKG" || true

# Diagnóstico visível no próprio log do passo (os artefatos exigem login para baixar).
diagnose() {
  pid="$(adb shell pidof "$PKG" 2>/dev/null | tr -d '\r' || true)"
  echo "--- processo: pid='${pid:-ausente}' ---"
  echo "--- atividade (dumpsys) ---"
  adb shell dumpsys activity activities 2>/dev/null | grep -iE "dev.ure|mResumedActivity|topResumed" | head -12 || true
  echo "--- buffer de crash ---"
  adb logcat -b crash -d 2>/dev/null | tail -60 || true
  if [ -n "${pid:-}" ]; then
    echo "--- logcat do processo $pid ---"
    grep -E " ${pid} " "$OUT/logcat.txt" | tail -200 || true
  fi
  echo "--- logcat (URE, Tauri/Wry, Python, WebView, erros) ---"
  grep -iE "URE|tauri|wry|chaquo|python|webview|chromium|FATAL|Exception|AndroidRuntime" "$OUT/logcat.txt" | tail -120 || true
  echo "--- textos visíveis na tela ---"
  if [ -f "$OUT/ui.xml" ]; then grep -o 'text="[^"]*"' "$OUT/ui.xml" | sort -u | head -60 || true; fi
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

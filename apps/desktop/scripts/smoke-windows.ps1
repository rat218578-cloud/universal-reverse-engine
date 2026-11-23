# Teste de instalação e funcionamento do aplicativo Windows (NSIS) e da análise pelo backend instalado.
#
# Uso (PowerShell, num Windows com Python 3.11+ no PATH e o instalador gerado pelo cargo tauri build):
#   pwsh apps/desktop/scripts/smoke-windows.ps1 -Installer "...\Universal Reverse Engine_1.0.0_x64-setup.exe" -RepoRoot "...\universal-reverse-engine"
#
# Cada verificação grava um resultado em smoke-results.json. Qualquer falha encerra com erro.
# Não usa token fixo: o token do aplicativo é gerado a cada execução e não é lido de fora.

param(
    [Parameter(Mandatory = $true)][string]$Installer,
    [Parameter(Mandatory = $true)][string]$RepoRoot,
    [string]$Work = (Join-Path $env:RUNNER_TEMP "ure-smoke"),
    [string]$Python = "python"
)

$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"
$results = [ordered]@{}
function Record([string]$name, $value) { $script:results[$name] = $value; Write-Host "OK  $name" }
function Free-Port {
    $l = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, 0)
    $l.Start(); $p = $l.LocalEndpoint.Port; $l.Stop(); return $p
}
function Wait-Until([scriptblock]$cond, [int]$seconds, [string]$what) {
    $deadline = (Get-Date).AddSeconds($seconds)
    while ((Get-Date) -lt $deadline) { if (& $cond) { return }; Start-Sleep -Milliseconds 500 }
    throw "tempo esgotado: $what"
}
function Invoke-Timed([string]$file, [string[]]$arguments, [int]$seconds) {
    # Processo externo com prazo: instaladores podem travar, e um travamento não pode consumir o job.
    $p = Start-Process -FilePath $file -ArgumentList $arguments -PassThru
    if (-not $p.WaitForExit($seconds * 1000)) {
        Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue
        throw "tempo esgotado ($seconds s): $file $($arguments -join ' ')"
    }
    return $p.ExitCode
}
function Port-Open([int]$port) {
    try { Invoke-RestMethod "http://127.0.0.1:$port/api/v1/health" -TimeoutSec 2 | Out-Null; return $true }
    catch { return $false }
}

New-Item -ItemType Directory -Force -Path $Work | Out-Null

# Ambiente limpo de Python: o aplicativo deve funcionar sem Python instalado no computador.
# Remove do PATH qualquer diretório de Python e as variáveis que influenciam o interpretador.
$cleanPath = ($env:PATH -split ";" | Where-Object { $_ -and ($_ -notmatch "(?i)python|setup-python|hostedtoolcache\\python") }) -join ";"
$env:PATH = $cleanPath
foreach ($v in @("URE_PYTHON", "PYTHONHOME", "PYTHONPATH", "PYTHONSTARTUP")) { Remove-Item "env:$v" -ErrorAction SilentlyContinue }
$pythonVisible = [bool](Get-Command python -ErrorAction SilentlyContinue)
if ($pythonVisible) { throw "não foi possível remover Python do PATH deste teste" }

Start-Transcript -Path (Join-Path $Work "smoke-transcript.txt") -Force | Out-Null
# Qualquer erro vira anotação com a linha, e os resultados parciais são gravados.
trap {
    Write-Output "::error title=smoke-windows::$($_.Exception.Message) (linha $($_.InvocationInfo.ScriptLineNumber))"
    try { $results | ConvertTo-Json -Depth 8 | Set-Content -Path (Join-Path $Work "smoke-results.json") -Encoding utf8 } catch { }
    try { Stop-Transcript | Out-Null } catch { }
    exit 1
}
$install = Join-Path $Work "app"
if (Test-Path $install) { Remove-Item -Recurse -Force $install }

# 1. Instalação silenciosa (NSIS)
$code = Invoke-Timed $Installer @("/S", "/D=$install") 300
if ($code -ne 0) { throw "instalador NSIS terminou com código $code" }
$exe = Join-Path $install "ure-desktop.exe"
Wait-Until { Test-Path $exe } 60 "instalação do NSIS"
Record "nsis_installed" $exe
Record "python_on_path_during_test" $pythonVisible
$bundledPy = Join-Path $install "python\python.exe"
Wait-Until { Test-Path $bundledPy } 10 "runtime Python instalado"
Record "bundled_python_installed" $bundledPy
# Os passos seguintes usam somente o runtime instalado.
$Python = $bundledPy
Wait-Until { Test-Path (Join-Path $install "backend\ure\server.py") } 10 "backend instalado"
Wait-Until { Test-Path (Join-Path $install "backend\ure\web\index.html") } 10 "interface instalada"
Record "backend_package_installed" $true
Record "web_ui_installed" $true

# 2. Abrir o aplicativo: backend sobe, responde à saúde e a janela aparece
$appData = Join-Path $env:APPDATA "dev.ure.desktop"
$log = Join-Path $appData "data\logs\backend.log"
$app = Start-Process -FilePath $exe -PassThru
function Current-Port {
    if (-not (Test-Path $log)) { return $null }
    $m = Select-String -Path $log -Pattern 'http://127\.0\.0\.1:(\d+)' | Select-Object -Last 1
    if ($m) { return [int]$m.Matches[0].Groups[1].Value } else { return $null }
}
Wait-Until { $null -ne (Current-Port) } 90 "backend anunciar a porta"
$port = Current-Port
Wait-Until { Port-Open $port } 90 "saúde do backend"
Record "backend_health_port" $port
# O processo do backend deve ser o runtime instalado, não um Python do sistema.
$backendProc = Get-CimInstance Win32_Process -Filter "Name='python.exe'" -ErrorAction SilentlyContinue |
    Where-Object { $_.CommandLine -like "*ure.server*" } | Select-Object -First 1
if (-not $backendProc) { throw "processo do backend não encontrado" }
if ($backendProc.ExecutablePath -notlike "$install\python\*") { throw "backend usa outro Python: $($backendProc.ExecutablePath)" }
Record "backend_runs_bundled_python" $backendProc.ExecutablePath
try {
    # MainWindowTitle é cacheado no objeto Process: consulta o processo de novo a cada verificação.
    Wait-Until {
        $live = Get-Process -Id $app.Id -ErrorAction SilentlyContinue
        $null -ne $live -and $live.MainWindowTitle -eq "Universal Reverse Engine"
    } 90 "janela principal"
} catch {
    # Diagnóstico: o que existe de fato na sessão quando a janela não é encontrada.
    Write-Host "DIAG app.HasExited=$($app.HasExited) app.MainWindowTitle='$($app.MainWindowTitle)' app.MainWindowHandle=$($app.MainWindowHandle)"
    Get-Process | Where-Object { $_.MainWindowTitle } | ForEach-Object { Write-Host "DIAG window pid=$($_.Id) name=$($_.ProcessName) title='$($_.MainWindowTitle)'" }
    Get-Process -Name "ure-desktop", "msedgewebview2" -ErrorAction SilentlyContinue | ForEach-Object { Write-Host "DIAG proc $($_.ProcessName) pid=$($_.Id) title='$($_.MainWindowTitle)'" }
    if (Test-Path $log) { Write-Host "DIAG backend.log (cauda):"; Get-Content $log -Tail 30 | ForEach-Object { Write-Host "  $_" } }
    throw
}
Record "window_opened" (Get-Process -Id $app.Id).MainWindowTitle
$webview = @(Get-Process -Name "msedgewebview2" -ErrorAction SilentlyContinue).Count
Record "webview2_processes" $webview

# 3. Encerramento gracioso ao fechar a janela
$null = $app.CloseMainWindow()
Wait-Until { $app.HasExited } 30 "encerramento do aplicativo"
Wait-Until { -not (Port-Open $port) } 30 "backend encerrado após fechar a janela"
Record "closed_window_stops_backend" $true

# 4. Morte forçada do aplicativo: o backend deve sair sozinho pelo pipe de controle
$app2 = Start-Process -FilePath $exe -PassThru
Wait-Until { $null -ne (Current-Port) -and (Port-Open (Current-Port)) } 90 "segunda execução"
$port2 = Current-Port
Stop-Process -Id $app2.Id -Force
Wait-Until { -not (Port-Open $port2) } 30 "backend encerrado após morte forçada"
Record "killed_app_stops_backend" $true

# 5. Análise real pelo backend instalado: APK sintético, EXE sintético e binários Windows reais
$pyBackend = Join-Path $install "backend"
$samples = Join-Path $Work "samples"
New-Item -ItemType Directory -Force -Path $samples | Out-Null
$gen = @"
import sys
from pathlib import Path
sys.path.insert(0, r'$RepoRoot\apps\backend')
from tests.helpers import synthetic_apk, synthetic_pe32
synthetic_apk(Path(r'$samples\app.apk'))
synthetic_pe32(Path(r'$samples\synthetic.exe'))
"@
& $Python -c $gen
if ($LASTEXITCODE -ne 0) { throw "falha ao gerar amostras sintéticas" }
# Binários reais: o próprio interpretador Python (PE32+) e a DLL que ele carrega
$pyExe = (& $Python -c "import sys; print(sys.executable)").Trim()
$pyDir = Split-Path $pyExe
Copy-Item $pyExe (Join-Path $samples "real.exe")
$pyDll = Get-ChildItem -Path $pyDir -Filter "python3*.dll" | Select-Object -First 1
if (-not $pyDll) { $pyDll = Get-ChildItem -Path $pyDir -Filter "python*.dll" | Select-Object -First 1 }
if (-not $pyDll) { throw "nenhuma DLL do Python encontrada em $pyDir" }
Copy-Item $pyDll.FullName (Join-Path $samples "real.dll")

$token = ([guid]::NewGuid().ToString("N") + [guid]::NewGuid().ToString("N"))
$apiPort = Free-Port
$dataDir = Join-Path $Work "api-data"
$env:URE_TOKEN = $token; $env:URE_PORT = "$apiPort"; $env:URE_DATA_DIR = $dataDir
$env:URE_HOST = "127.0.0.1"; $env:URE_CONFIG = (Join-Path $Work "none.env"); $env:URE_PARENT_WATCH = "0"
$apiLog = Join-Path $Work "api-backend.log"
$api = Start-Process -FilePath $Python -ArgumentList @("-m", "ure.server") -WorkingDirectory $pyBackend `
    -PassThru -RedirectStandardOutput $apiLog -RedirectStandardError (Join-Path $Work "api-backend.err")
Wait-Until { Port-Open $apiPort } 90 "backend instalado responder"
$base = "http://127.0.0.1:$apiPort/api/v1"
$auth = @{ Authorization = "Bearer $token" }

function Api([string]$method, [string]$path, $body = $null) {
    $params = @{ Method = $method; Uri = "$base$path"; Headers = $auth; TimeoutSec = 60 }
    if ($null -ne $body) { $params.Body = ($body | ConvertTo-Json -Depth 8); $params.ContentType = "application/json" }
    return Invoke-RestMethod @params
}
function Analyze-File([string]$projectId, [string]$file, [string]$expectKind) {
    $name = Split-Path $file -Leaf
    $up = Invoke-RestMethod -Method Post -Uri "$base/projects/$projectId/artifacts" -Headers ($auth + @{
        "X-Filename" = $name; "Content-Type" = "application/octet-stream" }) -InFile $file -TimeoutSec 120
    if ($up.kind -ne $expectKind) { throw "${name}: tipo detectado '$($up.kind)', esperado '$expectKind'" }
    $job = Api "POST" "/projects/$projectId/artifacts/$($up.id)/analyze" @{}
    $deadline = (Get-Date).AddSeconds(600)
    do {
        Start-Sleep -Milliseconds 500
        $job = Api "GET" "/jobs/$($job.id)"
    } while ($job.status -in @("queued", "running") -and (Get-Date) -lt $deadline)
    if ($job.status -ne "done") { throw "${name}: análise terminou com '$($job.status)': $($job.error)" }
    $report = Api "GET" "/projects/$projectId/artifacts/$($up.id)/report"
    if ($report.integrity -ne "ok") { throw "${name}: integridade '$($report.integrity)'" }
    return @{ artifact = $up.id; report = $report }
}

$project = Api "POST" "/projects" @{ name = "Smoke Windows" }
Record "project_created" $project.id
$apk = Analyze-File $project.id (Join-Path $samples "app.apk") "apk"
if (-not $apk.report.dependencies.has_android_manifest) { throw "APK sem AndroidManifest no relatório" }
if (-not ($apk.report.dependencies.dex_files -contains "classes.dex")) { throw "APK sem classes.dex no relatório" }
$tree = Api "GET" "/projects/$($project.id)/artifacts/$($apk.artifact)/tree?root=original"
Record "apk_analysis" @{ integrity = "ok"; manifest = $true; dex = "classes.dex"; tree_entries = @($tree.entries).Count }

$syn = Analyze-File $project.id (Join-Path $samples "synthetic.exe") "pe"
Record "synthetic_pe_analysis" @{ integrity = "ok"; imported_dlls = $syn.report.dependencies.imported_dlls }
$real = Analyze-File $project.id (Join-Path $samples "real.exe") "pe"
Record "real_pe_analysis" @{ integrity = "ok"; ghidra = $real.report.engines.ghidra.status }
$realDll = Analyze-File $project.id (Join-Path $samples "real.dll") "pe"
Record "real_dll_analysis" @{ integrity = "ok" }

# Persistência: o projeto sobrevive a reinício do backend
Stop-Process -Id $api.Id -Force
Wait-Until { -not (Port-Open $apiPort) } 30 "backend de teste encerrado"
$env:URE_PORT = "$apiPort"
$api2 = Start-Process -FilePath $Python -ArgumentList @("-m", "ure.server") -WorkingDirectory $pyBackend -PassThru `
    -RedirectStandardOutput (Join-Path $Work "api-backend2.log") -RedirectStandardError (Join-Path $Work "api-backend2.err")
Wait-Until { Port-Open $apiPort } 90 "backend reiniciado"
$listed = (Api "GET" "/projects").projects | Where-Object { $_.id -eq $project.id }
if (-not $listed) { throw "projeto não persistiu após reinício" }
Record "project_persisted_after_restart" $true
Stop-Process -Id $api2.Id -Force

# 6. Desinstalação
$uninstaller = Join-Path $install "uninstall.exe"
if (Test-Path $uninstaller) {
    $code = Invoke-Timed $uninstaller @("/S") 300
    if ($code -ne 0) { throw "desinstalador terminou com código $code" }
    Wait-Until { -not (Test-Path $exe) } 60 "desinstalação"
    Record "uninstalled" $true
}

$results | ConvertTo-Json -Depth 8 | Set-Content -Path (Join-Path $Work "smoke-results.json") -Encoding utf8
Stop-Transcript | Out-Null
Write-Host "SMOKE OK: $($results.Count) verificações"

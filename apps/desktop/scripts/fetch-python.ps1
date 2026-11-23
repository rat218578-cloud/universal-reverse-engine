# Baixa e prepara o runtime Python 3.12 embutível usado pelo instalador Windows.
#
# Resultado: apps/desktop/src-tauri/python/python.exe, com um arquivo ._pth que coloca
# o pacote do backend ("..\backend") no sys.path. O backend não tem dependências de terceiros,
# então nenhum pip é necessário. O script valida o runtime antes de terminar.
#
# Uso:
#   pwsh apps/desktop/scripts/fetch-python.ps1                  # exige sha256 fixado em python-runtime.json
#   pwsh apps/desktop/scripts/fetch-python.ps1 -AcceptNewHash   # primeira obtenção: imprime o sha256

param([switch]$AcceptNewHash)

$ErrorActionPreference = "Stop"
$desktop = Split-Path -Parent $PSScriptRoot
$lock = Get-Content (Join-Path $desktop "python-runtime.json") -Raw | ConvertFrom-Json
$target = Join-Path $desktop "src-tauri\python"
$tmp = Join-Path ([System.IO.Path]::GetTempPath()) ("ure-python-" + [guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Force -Path $tmp | Out-Null
$zip = Join-Path $tmp "python-embed.zip"

Write-Host "Baixando Python $($lock.version) embutível de python.org..."
Invoke-WebRequest -Uri $lock.url -OutFile $zip -UseBasicParsing
$actual = (Get-FileHash -Algorithm SHA256 $zip).Hash.ToLowerInvariant()
Write-Host "sha256 obtido: $actual"
if (-not $lock.sha256) {
    if (-not $AcceptNewHash) { throw "python-runtime.json sem sha256 fixado. Confira $actual e fixe o valor (ou use -AcceptNewHash na primeira obtenção)." }
    Write-Host "::notice title=Python runtime::sha256 a fixar em python-runtime.json: $actual"
} elseif ($actual -ne $lock.sha256.ToLowerInvariant()) {
    throw "sha256 divergente: esperado $($lock.sha256), obtido $actual"
}

if (Test-Path $target) { Remove-Item -Recurse -Force $target }
Expand-Archive -Path $zip -DestinationPath $target
Remove-Item -Force $zip

# Caminho do backend relativo à pasta do python.exe: no instalador, $INSTDIR\backend.
$pth = Get-ChildItem $target -Filter "python*._pth" | Select-Object -First 1
if (-not $pth) { throw "arquivo ._pth ausente no pacote embutível" }
$stdlibZip = (Get-ChildItem $target -Filter "python*.zip" | Select-Object -First 1).Name
@(
    $stdlibZip,
    ".",
    "..\backend",
    "import site"
) | Set-Content -Path $pth.FullName -Encoding ascii

# Validação: o runtime precisa rodar em modo isolado e importar o backend sem nada do sistema.
$py = Join-Path $target "python.exe"
$version = & $py -I -c "import sys; print('%d.%d.%d' % sys.version_info[:3])"
if ($LASTEXITCODE -ne 0) { throw "python.exe não executou" }
$parts = $version.Split(".") | ForEach-Object { [int]$_ }
if ($parts[0] -ne 3 -or $parts[1] -lt 11) { throw "versão inválida do runtime: $version" }
$backendRepo = Join-Path $desktop "..\backend"
& $py -I -c "import sys; sys.path.insert(0, r'$((Resolve-Path $backendRepo).Path)'); import ure.server, ure.app, ure.pe, ure.safezip, ure.tools, ure.engines; print('modulos ok')"
if ($LASTEXITCODE -ne 0) { throw "o backend não importa com o runtime embutido" }
Write-Host "Runtime pronto: $py (Python $version)"
Remove-Item -Recurse -Force $tmp

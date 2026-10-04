param([string]$Source = ".\target\release\sparkbridge-executor.exe", [string]$InstallDir = "$env:ProgramFiles\SparkBridge")
$ErrorActionPreference = "Stop"
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw "Run PowerShell as Administrator" }
New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
Copy-Item $Source "$InstallDir\sparkbridge-executor.exe" -Force
if (-not (Test-Path "$InstallDir\executor.toml")) { Copy-Item ".\config\executor.example.toml" "$InstallDir\executor.toml" }
sc.exe stop SparkBridgeExecutor 2>$null | Out-Null
sc.exe delete SparkBridgeExecutor 2>$null | Out-Null
$bin = '"' + "$InstallDir\sparkbridge-executor.exe" + '" --config "' + "$InstallDir\executor.toml" + '"'
sc.exe create SparkBridgeExecutor binPath= $bin start= auto DisplayName= "SparkBridge Executor" | Out-Null
sc.exe description SparkBridgeExecutor "SparkBridge Fabric authenticated execution node" | Out-Null
sc.exe start SparkBridgeExecutor | Out-Null
Write-Host "SparkBridgeExecutor installed. Edit $InstallDir\executor.toml before enrollment if required."

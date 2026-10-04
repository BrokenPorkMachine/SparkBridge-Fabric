$ErrorActionPreference = "Stop"
sc.exe stop SparkBridgeExecutor 2>$null | Out-Null
sc.exe delete SparkBridgeExecutor 2>$null | Out-Null
Write-Host "SparkBridgeExecutor service removed. Configuration/identity files were intentionally retained."

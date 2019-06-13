$ErrorActionPreference='silentlycontinue'
Remove-item -path "$env:APPDATA\CertImport.log" -Force
Write-host 'Complete'
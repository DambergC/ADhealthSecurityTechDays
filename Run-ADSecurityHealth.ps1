# Example runner to produce JSON and HTML reports

Import-Module -Name "$PSScriptRoot\ADSecurityHealth.psm1" -Force

$summary = Invoke-ADSecurityHealthCheck
$detail  = Invoke-ADSecurityHealthCheck -IncludeRawEvidence

# Save JSON
$summaryPath = Join-Path $PSScriptRoot "adsh-summary.json"
$detailPath  = Join-Path $PSScriptRoot "adsh-detail.json"
$summary | ConvertTo-Json -Depth 6 | Out-File -Encoding utf8 $summaryPath
$detail  | ConvertTo-Json -Depth 6 | Out-File -Encoding utf8 $detailPath

# Create HTML dashboard
$html = $summary |
    Sort-Object Severity, Category |
    ConvertTo-Html -Title "AD Security & Health Summary" -PreContent "<h1>AD Security & Health Summary</h1><p>Generated: $(Get-Date)</p>" |
    Out-String

$htmlPath = Join-Path $PSScriptRoot "adsh-summary.html"
$html | Out-File -Encoding utf8 $htmlPath

Write-Host "Reports written:"
Write-Host " - $summaryPath"
Write-Host " - $detailPath"
Write-Host " - $htmlPath"
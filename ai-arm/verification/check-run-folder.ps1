# Usage: .\check-run-folder.ps1 -Folder C:\unsw-runs\run1
# Run BEFORE starting the AI session (folder must hold only the two CSVs)
# and AFTER it finishes (to list what the AI created).
param([Parameter(Mandatory)][string]$Folder)

$expected = @{
  'UNSW_NB15_training-set.csv' = 175341
  'UNSW_NB15_testing-set.csv'  = 82332
}

Write-Host "Files in ${Folder}:"
Get-ChildItem $Folder -Force | ForEach-Object { Write-Host ("  {0}  ({1:N0} bytes)" -f $_.Name, $_.Length) }

foreach ($name in $expected.Keys) {
  $path = Join-Path $Folder $name
  if (-not (Test-Path $path)) { Write-Host "MISSING: $name" -ForegroundColor Red; continue }
  # data rows = lines minus header
  $rows = (Get-Content $path -ReadCount 100000 | ForEach-Object { $_.Count } | Measure-Object -Sum).Sum - 1
  $hash = (Get-FileHash $path -Algorithm SHA256).Hash
  $status = if ($rows -eq $expected[$name]) { 'OK' } else { "MISMATCH (expected $($expected[$name]))" }
  Write-Host "$name : $rows data rows : $status" -ForegroundColor $(if ($status -eq 'OK') {'Green'} else {'Yellow'})
  Write-Host "  SHA256 $hash"
}

$extra = Get-ChildItem $Folder -Force | Where-Object { $expected.Keys -notcontains $_.Name }
if ($extra) { Write-Host "Extra files present (expected before a run: none):" -ForegroundColor Yellow; $extra | ForEach-Object { Write-Host "  $($_.Name)" } }

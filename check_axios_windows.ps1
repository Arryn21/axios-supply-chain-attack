$found = @()
$badVersions = @("1.14.1", "0.30.4")

Write-Host "Scanning C: drive for axios installations... (this may take a few minutes)"

Get-ChildItem -Path "C:\" -Recurse -Filter "package.json" -ErrorAction SilentlyContinue |
Where-Object { $_.FullName -like "*\axios\*" } |
ForEach-Object {
    try {
        $pkg = Get-Content $_.FullName -Raw | ConvertFrom-Json -ErrorAction SilentlyContinue
        if ($pkg.name -eq "axios") {
            $status = if ($pkg.version -in $badVersions) { "*** MALICIOUS ***" } else { "OK" }
            $entry = "[$status] $($_.FullName) --> v$($pkg.version)"
            Write-Host $entry
            $found += $entry
        }
    } catch {}
}

Write-Host ""
Write-Host "=== SCAN COMPLETE ==="
Write-Host "Total axios installs found: $($found.Count)"

$malicious = $found | Where-Object { $_ -like "*MALICIOUS*" }
if ($malicious.Count -gt 0) {
    Write-Host "!! MALICIOUS VERSIONS FOUND: $($malicious.Count) !!" -ForegroundColor Red
    $malicious | ForEach-Object { Write-Host $_ -ForegroundColor Red }
} else {
    Write-Host "No malicious axios versions detected." -ForegroundColor Green
}

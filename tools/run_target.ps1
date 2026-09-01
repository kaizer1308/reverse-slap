$psi = [System.Diagnostics.ProcessStartInfo]::new('E:\reverse-slop\build\src\app\SlopTarget.exe')
$psi.RedirectStandardInput = $true
$psi.RedirectStandardOutput = $true
$psi.UseShellExecute = $false
$psi.CreateNoWindow = $true
$proc = [System.Diagnostics.Process]::Start($psi)
$outTask = $proc.StandardOutput.ReadToEndAsync()
Start-Sleep -Milliseconds 3000
$proc.StandardInput.WriteLine('quit')
$proc.StandardInput.Close()
[void]$proc.WaitForExit(5000)
$out = $outTask.Result
Write-Host $out
$procId = $proc.Id
$jsonPath = Join-Path $env:TEMP "sloptarget-$procId.json"
if (Test-Path $jsonPath) {
    Write-Host "--- JSON OK ---"
    Get-Content $jsonPath | Select-Object -First 5
} else {
    Write-Host "--- JSON NOT found: $jsonPath ---"
}

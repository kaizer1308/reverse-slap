param(
    [Parameter(Mandatory)][string]$Baseline,
    [Parameter(Mandatory)][string]$Candidate
)
$ErrorActionPreference = 'Stop'
$before = Get-Content -LiteralPath $Baseline -Raw | ConvertFrom-Json
$after = Get-Content -LiteralPath $Candidate -Raw | ConvertFrom-Json
foreach ($row in $before.workloads) {
    $next = @($after.workloads | Where-Object name -EQ $row.name)
    if ($next.Count -ne 1) { throw "Missing or duplicate workload: $($row.name)" }
    $next = $next[0]
    if ($row.result -ne $next.result) { throw "Result changed: $($row.name)" }
    [PSCustomObject]@{
        Workload = $row.name
        BeforeMs = $row.median_ms
        AfterMs = $next.median_ms
        Speedup = [Math]::Round($row.median_ms / $next.median_ms, 2)
        BeforeBytes = $row.allocated_bytes
        AfterBytes = $next.allocated_bytes
    }
}

[CmdletBinding()]
param(
    [Parameter(Mandatory)][long]$RunId,
    [string]$Repository = 'kaizer1308/reverse-slap',
    [string]$OutputPath
)
$ErrorActionPreference = 'Stop'
$base = "https://api.github.com/repos/$Repository/actions/runs/$RunId"
$run = Invoke-RestMethod $base
$jobs = @()
for ($page = 1; ; $page++) {
    $batch = Invoke-RestMethod "$base/jobs?per_page=100&page=$page"
    $jobs += $batch.jobs
    if ($batch.jobs.Count -lt 100) { break }
}
$rows = @($jobs | ForEach-Object {
    $job = $_
    [ordered]@{
        name = $job.name
        conclusion = $job.conclusion
        seconds = if ($job.completed_at) {
            ([datetime]$job.completed_at - [datetime]$job.started_at).TotalSeconds
        } else { $null }
        steps = @($job.steps | ForEach-Object {
            [ordered]@{
                name = $_.name
                conclusion = $_.conclusion
                seconds = if ($_.started_at -and $_.completed_at) {
                    ([datetime]$_.completed_at - [datetime]$_.started_at).TotalSeconds
                } else { $null }
            }
        })
    }
})
$result = [ordered]@{
    run_id = $RunId
    sha = $run.head_sha
    url = $run.html_url
    status = $run.status
    conclusion = $run.conclusion
    # End at the last job, not updated_at (which can change after completion).
    elapsed_seconds = if ($run.status -eq 'completed' -and $jobs.Count) {
        $end = ($jobs | Where-Object completed_at | Sort-Object completed_at | Select-Object -Last 1).completed_at
        ([datetime]$end - [datetime]$run.created_at).TotalSeconds
    } else { $null }
    jobs = $rows
}
$json = $result | ConvertTo-Json -Depth 8
if ($OutputPath) { $json | Set-Content -LiteralPath $OutputPath }
$json

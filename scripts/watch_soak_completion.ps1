param(
    [Parameter(Mandatory = $true)]
    [int]$ProcessId,

    [Parameter(Mandatory = $true)]
    [string]$RunId,

    [Parameter(Mandatory = $true)]
    [string]$ArtifactDir,

    [Parameter(Mandatory = $true)]
    [string]$MetadataPath,

    [int]$PollSeconds = 60
)

$ErrorActionPreference = "Stop"

function Write-NoticeFile {
    param(
        [string]$Message
    )

    $timestamp = (Get-Date).ToString("s")
    $noticePath = Join-Path $ArtifactDir "SOAK_RUN_WATCHER_NOTICE.txt"
    $logPath = Join-Path $ArtifactDir "soak_watcher.log"

    "$timestamp $Message" | Out-File -FilePath $noticePath -Encoding utf8
    "$timestamp $Message" | Out-File -FilePath $logPath -Encoding utf8 -Append
}

function Try-Notify {
    param(
        [string]$Message,
        [string]$Title
    )

    try {
        msg.exe $env:USERNAME $Message | Out-Null
        return
    } catch {
    }

    try {
        Add-Type -AssemblyName PresentationFramework
        [void][System.Windows.MessageBox]::Show($Message, $Title)
        return
    } catch {
    }

    try {
        [console]::beep(1200, 800)
    } catch {
    }
}

while ($true) {
    $runner = Get-Process -Id $ProcessId -ErrorAction SilentlyContinue
    if (-not $runner) {
        break
    }
    Start-Sleep -Seconds $PollSeconds
}

$status = "finished"
$note = ""

if (Test-Path -LiteralPath $MetadataPath) {
    try {
        $meta = Get-Content -LiteralPath $MetadataPath -Raw | ConvertFrom-Json
        if ($meta.artifact_dir -eq $ArtifactDir) {
            if ($meta.status) {
                $status = [string]$meta.status
            }
            if ($meta.note) {
                $note = [string]$meta.note
            }
        }
    } catch {
    }
}

$reportPath = Join-Path $ArtifactDir "research_soc_report.md"
$latestReportPath = Join-Path (Split-Path $ArtifactDir -Parent) "latest_wallclock_research_report.md"

if ((Test-Path -LiteralPath $reportPath) -or (Test-Path -LiteralPath $latestReportPath)) {
    $status = "completed"
}

$message = "Soak run $RunId ended with status '$status'."
if ($note) {
    $message += " $note"
}

Write-NoticeFile -Message $message
Try-Notify -Message $message -Title "Epidemic Lab Soak Run"

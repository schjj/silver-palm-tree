$watcher = New-Object System.IO.FileSystemWatcher
$watcher.Path = "$PSScriptRoot"
$watcher.IncludeSubdirectories = $true
$watcher.EnableRaisingEvents = $true

$action = {
    $path = $Event.SourceEventArgs.FullPath
    $changeType = $Event.SourceEventArgs.ChangeType
    $ext = [System.IO.Path]::GetExtension($path)
    if ($ext -notin ".py",".bat",".ps1",".md",".txt",".json",".sh") { return }
    if ($path -like "*\.git*") { return }

    Start-Sleep -Seconds 5
    cd $PSScriptRoot
    git add -A 2>&1 | Out-Null
    $status = git status --porcelain
    if ($status) {
        git commit -m "Auto-sync: $changeType $(Split-Path $path -Leaf)" 2>&1 | Out-Null
        git push 2>&1 | Out-Null
        Write-Host "[$(Get-Date -Format HH:mm:ss)] Synced: $changeType $(Split-Path $path -Leaf)"
    }
}

Register-ObjectEvent $watcher "Changed" -Action $action | Out-Null
Register-ObjectEvent $watcher "Created" -Action $action | Out-Null
Register-ObjectEvent $watcher "Deleted" -Action $action | Out-Null
Write-Host "Auto-sync running. Watching $($watcher.Path)... (Ctrl+C to stop)"
while ($true) { Start-Sleep -Seconds 10 }

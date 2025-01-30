#Accepts a Job as a parameter and writes the latest progress of it
function WriteJobProgress
{
    param($Job)
 
    #Make sure the first child job exists
    if($Job.ChildJobs[0].Progress -ne $null)
    {
        #Extracts the latest progress of the job and writes the progress
        $jobProgressHistory = $Job.ChildJobs[0].Progress;
        $latestProgress = $jobProgressHistory[$jobProgressHistory.Count - 1];
        $latestPercentComplete = $latestProgress | Select -expand PercentComplete;
        $latestActivity = $latestProgress | Select -expand Activity;
        $latestStatus = $latestProgress | Select -expand StatusDescription;
    
        #When adding multiple progress bars, a unique ID must be provided. Here I am providing the JobID as this
        #Write-Progress -Id $Job.Id -Activity $latestActivity -Status $latestStatus -PercentComplete $latestPercentComplete;
        Write-Host $Job.Id $latestPercentComplete
    }
}

$jsonBase = @{}
$allverinfo_json_path = "${runner}-${ver}-versioninfo.json"
$allverinfo_json_enhanced_path = "${runner}-${ver}-versioninfo.enhanced.json"
$has_getrpc = (Get-Command 'Get-RpcServer' -errorAction SilentlyContinue)
$cpu_count = (Get-CimInstance Win32_ComputerSystem).NumberOfLogicalProcessors
$allpaths_to_scan = "C:\Windows\System32\", "C:\Program Files (x86)\Mi*", "C:\Program Files (x86)\Win*", "C:\Program Files\Mi*", "C:\Program Files\Win*", "C:\Program*\Common*"

$ver = .\get_ver.ps1
$bin_types = "*.exe", "*.dll", "*.sys", "*.winmd", "*.cpl", "*.ax", "*.node", "*.ocx", "*.efi", "*.acm", "*.scr", "*.tsp", "*.drv"


Write-Host has get-rpc $has_getrpc
Write-Host limit: $limit
Write-Host cpus: $cpu_count
# these files cause a block when processed with get-rpc
$skip_rpc_files = "dpnaddr.dll"
$count = 0

# clear jobs
Remove-Job -Force *

foreach ($path in $allpaths_to_scan) {

  Start-Job  {
      gci -Recurse -include $using:bin_types $using:path -ErrorAction SilentlyContinue | select  Name, VersionInfo, DirectoryName, PSPath, FullName      
  }
}

$running = @(Get-Job | Where-Object { $_.State -eq 'Running' })
Write-Host Waiting for all $running.Count jobs...
$jobs_start = $(get-date)
while(($now_running = (Get-Job | Where-Object {$_.State -ne "Completed"}).Count) -gt 0)
{    
    Get-Job | Where-Object { $_.State -eq 'Running' } | % { WriteJobProgress($_) }
    
    Write-Host Jobs complete (Get-Job | Where-Object {$_.State -eq "Completed"}).Count / $running.Count
    Write-Host Time since for file proc jobs.. ($(get-date) - $jobs_start)
    Start-Sleep -Seconds 30
}
$jobs_end = $(get-date)

# Wait for all jobs to complete and results ready to be received
Wait-Job * | Out-Null

$all_files = Receive-Job *

write-host $all_files.count
write-host $all_files[0]
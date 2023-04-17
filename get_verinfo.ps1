# utility

$init_funcs = { 
  ## from https://hinchley.net/articles/an-approach-for-managing-microsoft-applocker-policies

  $FSR = [System.Security.AccessControl.FileSystemRights]

  # Unfortunately the FileSystemRights enum doesn't contain all the values from the Win32 API. Urgh.
  $GenericRights = @{
    GENERIC_READ    = [int]0x80000000;
    GENERIC_WRITE   = [int]0x40000000;
    GENERIC_EXECUTE = [int]0x20000000;
    GENERIC_ALL     = [int]0x10000000;
    FILTER_GENERIC  = [int]0x0FFFFFFF;
  }

  # ... so we need to map them ourselves.
  $MappedGenericRights = @{
    FILE_GENERIC_READ    = $FSR::ReadAttributes -bor $FSR::ReadData -bor $FSR::ReadExtendedAttributes -bor $FSR::ReadPermissions -bor $FSR::Synchronize
    FILE_GENERIC_WRITE   = $FSR::AppendData -bor $FSR::WriteAttributes -bor $FSR::WriteData -bor $FSR::WriteExtendedAttributes -bor $FSR::ReadPermissions -bor $FSR::Synchronize
    FILE_GENERIC_EXECUTE = $FSR::ExecuteFile -bor $FSR::ReadPermissions -bor $FSR::ReadAttributes -bor $FSR::Synchronize
    FILE_GENERIC_ALL     = $FSR::FullControl
  }

  Function Map-GenericRightsToFileSystemRights([System.Security.AccessControl.FileSystemRights]$Rights) {
    $MappedRights = New-Object -TypeName $FSR

    if ($Rights -band $GenericRights.GENERIC_EXECUTE) {
      $MappedRights = $MappedRights -bor $MappedGenericRights.FILE_GENERIC_EXECUTE
    }

    if ($Rights -band $GenericRights.GENERIC_READ) {
      $MappedRights = $MappedRights -bor $MappedGenericRights.FILE_GENERIC_READ
    }

    if ($Rights -band $GenericRights.GENERIC_WRITE) {
      $MappedRights = $MappedRights -bor $MappedGenericRights.FILE_GENERIC_WRITE
    }

    if ($Rights -band $GenericRights.GENERIC_ALL) {
      $MappedRights = $MappedRights -bor $MappedGenericRights.FILE_GENERIC_ALL
    }

    return (($Rights -band $GenericRights.FILTER_GENERIC) -bor $MappedRights) -as $FSR
  }

  # These are the rights from the FileSystemRights enum we care about.
  $WriteRights = @('WriteData', 'CreateFiles', 'CreateDirectories', 'WriteExtendedAttributes', 'WriteAttributes', 'Write', 'Modify', 'FullControl')


  function isWriteableByIdentStr([System.Security.AccessControl.AuthorizationRuleCollection]$access, [string]$identStr) {

    $is_writeable = $false
    $access |     
    ? { $_.identityreference -imatch $identStr } | % {                
            (map-genericrightstofilesystemrights $_.filesystemrights).tostring().split(",") | % {
        if ($writerights -contains $_.trim()) {
          $is_writeable = $true
        }
      }
    }
    return $is_writeable
  }
}
### end utility

$runner = $args[0]
$paths = $args[1]
$limit = $args[2]

$start_time = $(get-date)

$ver = [System.Environment]::OSVersion.Version -join '.'
$bin_types = "*.exe", "*.dll", "*.sys", "*.winmd", "*.cpl", "*.ax", "*.node", "*.ocx", "*.efi", "*.acm", "*.scr", "*.tsp", "*.drv"

if ($paths -eq $null -or $paths -eq "all") {
  $allpaths_to_scan = "C:\Windows\System32\", "C:\Program Files (x86)\Mi*", "C:\Program Files (x86)\Win*", "C:\Program Files\Mi*", "C:\Program Files\Win*", "C:\Program*\Common*"
}
else {
  $allpaths_to_scan = $paths
}

Write-Host Starting: Collecting files...
Write-Host folders: $allpaths_to_scan


$jsonBase = @{}
$allverinfo_json_path = "${runner}-${ver}-versioninfo.json"
$allverinfo_json_enhanced_path = "${runner}-${ver}-versioninfo.enhanced.json"
$has_getrpc = (Get-Command 'Get-RpcServer' -errorAction SilentlyContinue)
$cpu_count = (Get-CimInstance Win32_ComputerSystem).NumberOfLogicalProcessors

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
    Get-Job | Where-Object { $_.State -eq 'Running' }
    
    Write-Host Jobs complete $now_running  / $running.Count
    Write-Host Time since for file proc jobs.. ($(get-date) - $jobs_start)
    Start-Sleep -Seconds 5
}
$jobs_end = $(get-date)

# Wait for all jobs to complete and results ready to be received
Wait-Job * | Out-Null

$all_files = Receive-Job *

#$all_files = gci -Recurse -include $bin_types $allpaths_to_scan -ErrorAction SilentlyContinue | select  Name, VersionInfo, DirectoryName, PSPath, FullName

$gci_time = $(get-date) - $start_time
$job_file_count = [math]::Max(2000, $all_files.Count)
$max_jobs = 4 * $cpu_count
$min_jobs = $cpu_count * 2
$num_jobs = [math]::Ceiling($all_files.count / $job_file_count)

$num_jobs = [math]::Max($min_jobs,$num_jobs)

$job_file_count = [math]::Ceiling($all_files.count / $num_jobs)

Write-Host All files count $all_files.count
Write-Host GCI time: $gci_time
Write-Host Max jobs: $max_jobs
Write-Host Num jobs: $num_jobs
Write-Host Job file count : $job_file_count

for ($i=0; $i -lt $num_jobs; $i++)
{
    [int]$StartRow = ($i * $job_file_count)
    [int]$EndRow=(($i+1) * $job_file_count - 1)
    $rows_string = "Rows {0} to {1}" -f $StartRow.ToString(),$EndRow.ToString()
    write-host ($rows_string)
    write-host Starting 

    $running = @(Get-Job | Where-Object { $_.State -eq 'Running' })
    Write-Host Jobs running count: $running.Count
    
    if ($running.Count -ge $max_jobs) {
        Write-Host waiting to start next job...
        $running | Wait-Job -Any | Out-Null
    }

    Start-Job  -ArgumentList ($all_files[$StartRow..$EndRow],$limit) -InitializationScript $init_funcs {
        #PARAM ($arguments)
        
        $files = $args[0]
        $limit = $args[1]

        $count = 0        
        $jsonBase = @{}        
        $paths_processed = [System.Collections.ArrayList]@()

        foreach ($file in $files) {

            

            if ($limit -and $count -ge $limit) {
              Write-Host breaking on limit $limit with total files actually $files.Count
              break
            }

            $count++            
            #$complete = (($count / $files.Count) * 100)
          
            if ($paths_processed.Contains($file.FullName)) {
                Write-Host Skipping $file.FullName .. already added
                continue
            }
            else {
                $key = ($file | Get-FileHash).Hash

                if ($jsonBase.ContainsKey($key)) {
                    Write-Host Skipping $file.FullName .. already added
                    continue
                }

                #Write-Host $key
                $acl = $file | Get-Acl                 
                $acl = $acl | Select-Object Owner, Group, Sddl, AccessToString, Audit
                $parent_access = ($file.DirectoryName | Get-Acl)
                $is_parent_user_writeable = isWriteableByIdentStr ($parent_access).Access ".*USERS|EVERYONE"
                    
                if ($has_getrpc) {
                    if (-Not $skip_rpc_files.contains($file.Name)) {
                        $rpc_server = $file | Get-RpcServer
                        $rpc_info = $rpc_server | select InterfaceId, InterfaceVersion, TransferSyntaxId, TransferSyntaxVersion, ProcedureCount, Server, Name, ServiceName, ServiceDisplayName, IsServiceRunning, Endpoints, EndpointCount, Client 
                        $rpc_procs = $rpc_server | Select-Object -ExpandProperty Procedures | select Name
                        $rpc_info | Add-Member -MemberType NoteProperty -Name "Procedures" -Value $procs.Name
                    }
                }
            
                $file_data = @{}        
                $file_data.Add("VersionInfo", $file.VersionInfo)
                $file_data.Add("acl", $acl)
                $file_data.Add("rpc", $rpc_info)
                $file_data.Add("isparentuserwriteable", $is_parent_user_writeable)
                $file_data.Add("parentfolder", $file.Directory.fullname)
                $file_data.Add("Name", $file.Name)     
                
                $paths_processed.Add($file.FullName)
                $jsonBase.Add($key, $file_data)

            }

           
        }

        write-host $jsonBase.Count
        return  $jsonBase

    } | Out-Null
} 


Get-Job

$running = @(Get-Job | Where-Object { $_.State -eq 'Running' })
Write-Host Waiting for all $running.Count jobs...

# #Monitor all running jobs in the current sessions until they are complete
# #Call our custom WriteJobProgress function for each job to show progress. Sleep 1 second and check again
# while((Get-Job | Where-Object {$_.State -ne "Completed"}).Count -gt 0)
# {    
#     Get-Job | Where-Object {$_.State -ne "Completed"} | % {WriteJobProgress($_) }
#     Start-Sleep -Seconds 1
# }
$jobs_start = $(get-date)
while(($now_running = (Get-Job | Where-Object {$_.State -ne "Completed"}).Count) -gt 0)
{    
    Get-Job | Where-Object { $_.State -eq 'Running' }
    
    Write-Host Jobs complete (Get-Job | Where-Object {$_.State -eq "Completed"}).Count / $running.Count
    Write-Host Time since for file proc jobs.. ($(get-date) - $jobs_start)
    Start-Sleep -Seconds 5
}
$jobs_end = $(get-date)

# Wait for all jobs to complete and results ready to be received
Wait-Job * | Out-Null

# merge all results 
$mergedJson = @{}
foreach ($job in Get-Job) {
    $json = Receive-Job $job

    Write-Host jobid: $job.id
    Write-Host files count: $json.Count

    foreach ($key in $json.Keys) 
    {        

        if ($mergedJson.ContainsKey($key)) {
            Write-Host Skipping $key .. already added
            continue
        }
        else {
            $mergedJson.Add($key,$json.$key)
        }       

    }
}

Write-Host writing versioninfo json...
Write-Host $mergedJson.Count objects
$mergedJson | ConvertTo-Json -Depth 3 | Out-File $allverinfo_json_path 

$proc_json_path = "${runner}-${ver}-proc.json"

python .\enhance_verinfo.py $allverinfo_json_path $proc_json_path $allverinfo_json_enhanced_path

Write-Host Wrote $jsonBase.Count objects
Write-Host Wrote : $allverinfo_json_path 
Write-Host Wrote : $allverinfo_json_enhanced_path
Write-Host gci time: $gci_time
Write-Host file processing time : ($jobs_end - $jobs_start)

# tar.gz json
tar czf ($allverinfo_json_enhanced_path + '.tar.gz') $allverinfo_json_enhanced_path


$init_funcs = {
    function isWriteableByIdentStr([System.Security.AccessControl.AuthorizationRuleCollection]$access, [string]$identStr) {

        return 0
    }

    function test1() {
        return 0
    }

}


$allpaths_to_scan = "C:\Windows\System32\spool", "C:\Program Files (x86)\Mi*", "C:\Program Files (x86)\Win*" #, "C:\Program Files\Mi*", "C:\Program Files\Win*", "C:\Program*\Common*"
$bin_types = "*.exe", "*.dll", "*.sys", "*.winmd", "*.cpl", "*.ax", "*.node", "*.ocx", "*.efi", "*.acm", "*.scr", "*.tsp", "*.drv"
$cpu_count = (Get-CimInstance Win32_ComputerSystem).NumberOfLogicalProcessors
$has_getrpc = (Get-Command 'Get-RpcServer' -errorAction SilentlyContinue)
# clear jobs
Remove-Job -Force *


foreach ($path in $allpaths_to_scan ) {
    

    # $running = @(Get-Job | Where-Object { $_.State -eq 'Running' })
    # Write-Host Jobs runing count: $running.Count
    # if ($running.Count -ge $cpu_count) {
    #     Write-Host waiting to start next job...
    #     $running | Wait-Job -Any | Out-Null
    # }

    Write-Host "Starting job for $path"
    Start-Job  -InitializationScript $init_funcs {
        # do something with $using:server. Just sleeping for this example.
        $all_files = gci -Recurse -Depth 0 -include $using:bin_types $using:path -ErrorAction SilentlyContinue | select  Name, VersionInfo, DirectoryName, PSPath, FullName

        $count = 0        
        $jsonBase = @{}        

        $paths_processed = @()
        foreach ($file in $all_files) {

            $count++
            #Write-Host $file.FullName
            $complete = (($count / $all_files.Count) * 100)
            #     Write-Host complete '%' $complete
            
          
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

                Write-Host $key
                $acl = $file | Get-Acl                 
                $acl = $acl | Select-Object Owner, Group, Sddl, AccessToString, Audit
                $is_parent_user_writeable = isWriteableByIdentStr (($file.DirectoryName | Get-Acl).Access) ".*USERS|EVERYONE"
                    
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
                
                
                $jsonBase.Add($key, $file_data)

            }

            if ($count -gt 105) {
                break
            }
            
            Write-Progress -Activity $using:path -Status hi -PercentComplete $complete
            
        }


        return  $jsonBase

    } | Out-Null
}

$running = @(Get-Job | Where-Object { $_.State -eq 'Running' })
Write-Host Waiting for all $running.Count jobs...
# Wait for all jobs to complete and results ready to be received
Wait-Job * | Out-Null

$jsonBase = @{}
$mergedJson = @{}
# Process the results
foreach ($job in Get-Job) {
    $json = Receive-Job $job

    Write-Host jobid: $job.id
    Write-Host files count: $json.Count

    $mergedJson += $json   

}

Remove-Job -State Completed

write-host $mergedJson.Count

$mergedJson | ConvertTo-Json | Out-File para.json

#1..1000 | ForEach-Object -Parallel { "Hello: $_" } 

# This *is* guaranteed to work because the passed in concurrent dictionary object is thread safe
# $threadSafeDictionary = [System.Collections.Concurrent.ConcurrentDictionary[string,object]]::new()

# $allpaths_to_scan | ForEach-Object -Parallel {
#     $dict = $using:threadSafeDictionary
    
#     $files = gci $_ -Depth 1

#     foreach ($file in $files) {
#         echo $file.FullName
#         $dict.TryAdd($file.FullName, $file.CreationTime)
#     }

    
    
# }

# echo $dict

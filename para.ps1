$init_funcs = {
    function isWriteableByIdentStr([System.Security.AccessControl.AuthorizationRuleCollection]$access, [string]$identStr) {

        return 0
    }

    function test1() {
        return 0
    }
    


}

$allpaths_to_scan = "C:\Windows\System32\spool", "C:\Program Files (x86)\Mi*" # , "C:\Program Files (x86)\Win*" #, "C:\Program Files\Mi*", "C:\Program Files\Win*", "C:\Program*\Common*"
#$allpaths_to_scan = "C:\Windows\System32\spool"
$bin_types = "*.exe", "*.dll", "*.sys", "*.winmd", "*.cpl", "*.ax", "*.node", "*.ocx", "*.efi", "*.acm", "*.scr", "*.tsp", "*.drv"
$cpu_count = (Get-CimInstance Win32_ComputerSystem).NumberOfLogicalProcessors
$has_getrpc = (Get-Command 'Get-RpcServer' -errorAction SilentlyContinue)

# clear jobs
Remove-Job -Force *

$all_files = gci -Recurse -Depth 0 -include $bin_types $allpaths_to_scan -ErrorAction SilentlyContinue | select  Name, VersionInfo, DirectoryName, PSPath, FullName

$job_file_count = [math]::Max(2000, $all_files.Count)
$max_jobs = 4 * $cpu_count
$min_jobs = $cpu_count * 2
$num_jobs = [math]::Ceiling($all_files.count / $job_file_count)

$num_jobs = [math]::Max($min_jobs,$num_jobs)

$job_file_count = [math]::Ceiling($all_files.count / $num_jobs)

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

    Start-Job  -ArgumentList (,$all_files[$StartRow..$EndRow]) -InitializationScript $init_funcs {
        #PARAM ($arguments)
        
        $files = $args[0]
        $count = 0        
        
        $jsonBase = @{}        

        $paths_processed = [System.Collections.ArrayList]@()
        foreach ($file in $files) {

            $count++
            #Write-Host $file.FullName
            $complete = (($count / $files.Count) * 100)
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

           
            Write-Progress -Activity 'File' -Status 'Processing...' -PercentComplete $complete
            
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
while((Get-Job | Where-Object {$_.State -ne "Completed"}).Count -gt 0)
{    
    Get-Job  
    Write-Host Jobs complete ((Get-Job | Where-Object {$_.State -ne "Completed"}).Count / $running.Count)
    Start-Sleep -Seconds 5
    
}

# Wait for all jobs to complete and results ready to be received
Wait-Job * | Out-Null

$mergedJson = @{}
# Process the results
foreach ($job in Get-Job) {
    $json = Receive-Job $job

    Write-Host jobid: $job.id
    Write-Host files count: $json.Count

    $skipped = 0
    $added = 0
    foreach ($key in $json.Keys) 
    {        
        
        if ($mergedJson.ContainsKey($key)) {            
            $skipped += 1
            continue
        }
        else {
            $mergedJson.Add($key,$json.$key)
            $added += 1
        }       

        
    }
    
    Write-Host Added: $json.Count

}

Remove-Job -State Completed

write-host $mergedJson.Count

$mergedJson | ConvertTo-Json | Out-File para.json

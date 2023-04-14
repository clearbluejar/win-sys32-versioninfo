$allpaths_to_scan = "C:\Windows\System32\","C:\Program*\Common*"


Get-Job | Receive-job -AutoRemoveJob -Wait
foreach ($server in $allpaths_to_scan ) {
    # $running = @(Get-Job | Where-Object { $_.State -eq 'Running' })
    # if ($running.Count -ge 2) {
    #     $running | Wait-Job -Any | Out-Null
    # }

    Write-Host "Starting job for $server"
    Start-Job {
        # do something with $using:server. Just sleeping for this example.
        Start-Sleep 5

        $files = gci $using:server -Depth 0

        return $files
    } | Out-Null
}

# Wait for all jobs to complete and results ready to be received
Wait-Job * | Out-Null

# Process the results
foreach($job in Get-Job)
{
    $result = Receive-Job $job
    Write-Host $result
}

Remove-Job -State Completed


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

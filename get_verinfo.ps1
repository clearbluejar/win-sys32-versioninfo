# utility


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
### end utility

$runner = $args[0]
$paths = $args[1]
$limit = $args[2]

$ver = [System.Environment]::OSVersion.Version -join '.'
$bin_types = "*.exe", "*.dll", "*.sys", "*.winmd", "*.cpl", "*.ax", "*.node", "*.ocx", "*.efi", "*.acm", "*.scr", "*.tsp", "*.drv"

if ($paths) {
  $allpaths_to_scan = $paths
}
else {
  $allpaths_to_scan = "C:\Windows\System32\", "C:\Program Files (x86)\Mi*", "C:\Program Files (x86)\Win*", "C:\Program Files\Mi*", , "C:\Program Files\Win*", "C:\Program*\Common*"
}


Write-Host Starting: Collecting files...
Write-Host folders: $allpaths_to_scan


$jsonBase = @{}
$allverinfo_json_path = "${runner}-${ver}-versioninfo.json"
$allverinfo_json_enhanced_path = "${runner}-${ver}-versioninfo.enhanced.json"
$has_getrpc = (Get-Command 'Get-RpcServer' -errorAction SilentlyContinue)
$cpu_count = (Get-CimInstance Win32_ComputerSystem).NumberOfLogicalProcessors

Write-Host has get-rpc $has_getrpc
Write-Host processing $all_files.Count
Write-Host limit: $limit
Write-Host cpus: $cpu_count
# these files cause a block when processed with get-rpc
$skip_rpc_files = "dpnaddr.dll"
$count = 0

# clear jobs
Remove-Job -Force *

foreach ($path in $allpaths_to_scan ) {
    

  $running = @(Get-Job | Where-Object { $_.State -eq 'Running' })
  Write-Host Jobs runing count: $running.Count
  
  # don't limit cpus, as we are doing so much disk IO, let it run...
  # if ($running.Count -ge $cpu_count) {
  #     Write-Host waiting to start next job...
  #     $running | Wait-Job -Any | Out-Null
  # }

  Write-Host "Starting job for $path"
  Start-Job {
    # do something with $using:server. Just sleeping for this example.
    $files = Get-ChildItem $allpaths_to_scan -Include $bin_types -Recurse -ErrorAction SilentlyContinue | select  Name, VersionInfo, DirectoryName, PSPath, FullName
    
    return $files
  } | Out-Null
}

$running = @(Get-Job | Where-Object { $_.State -eq 'Running' })
Write-Host Collecting Waiting for all $running.Count jobs...
# Wait for all jobs to complete and results ready to be received
Wait-Job * | Out-Null



foreach ($file in $all_files) {


  $count++
  Write-Host $file.FullName
  Write-Host complete '%' ($count / $all_files.Count)       
  $key = ($file | Get-FileHash).Hash

  if ($jsonBase.ContainsKey($key)) {
    Write-Host Skipping $key .. already added
    continue
  }
  Write-Host $key
        
  $acl = $file | Get-Acl 
  $acl_access = $acl.Access
  $acl = $acl | select Owner, Group, Sddl, AccessToString, Audit
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

Write-Host writing versioninfo json...
Write-Host $jsonBase.Count objects
$jsonBase | ConvertTo-Json -Depth 3 | Out-File $allverinfo_json_path 

$proc_json_path = "${runner}-${ver}-proc.json"

python .\enhance_verinfo.py $allverinfo_json_path $proc_json_path $allverinfo_json_enhanced_path

# tar.gz json
tar czf ($allverinfo_json_enhanced_path + '.tar.gz') $allverinfo_json_enhanced_path

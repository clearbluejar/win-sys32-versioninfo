# create get-process json
$runner=$args[0]
$ver = .\get_ver.ps1
$procJsonBase = @{}
$proc_json_path = "${runner}-${ver}-proc.json"
$procs = Get-Process -IncludeUserName

foreach ($proc in $procs) {
    $procJson = @{}  
    Write-Host Processing $proc.Name $proc.Path
    $id = $proc.ID
    $modules = get-process -id $proc.ID -ErrorAction SilentlyContinue | select -expand Modules -ea silentlycontinue | select Filename
    $commandline =  (Get-CimInstance -ClassName Win32_Process -Filter "ProcessId = '$id'").CommandLine

    $procJson.Add('modules', $modules)
    $procJson.Add('name', $proc.Name)
    $procJson.Add('path', $proc.Path)
    $procJson.Add('running', $true)
    $procJson.Add('username', $proc.UserName)
    $procJson.Add('commandline', $commandline)

    $procJsonBase.Add("$($proc.ID)-$($proc.Name)",$procJson)

}

Write-Host writing versioninfo json...
Write-Host $procJsonBase.Count objects
$procJsonBase | ConvertTo-Json -Depth 3 | Out-File $proc_json_path 
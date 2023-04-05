        $ver = [System.Environment]::OSVersion.Version -join '.'
        $bin_types = "*.exe","*.dll","*.sys","*.winmd","*.cpl","*.ax","*.node","*.ocx","*.efi","*.acm","*.scr","*.tsp","*.drv"
        $allpaths_to_scan = "C:\Program*\Mi*","C:\Program*\Win*", "C:\Windows\System32\", "C:\Program*\Common*"
        #$allpaths_to_scan = "C:\\Program Files\\Microsoft Office\\root\\vfs\\ProgramFilesCommonX64\\Microsoft Shared\\OFFICE16\\AppvIsvSubsystems64.dll"
        $all_files = Get-ChildItem $allpaths_to_scan -Include $bin_types -Recurse -ErrorAction SilentlyContinue
        # $all_files | select  Name,VersionInfo | ConvertTo-Json -depth 100 -Compress | Out-File $allrecurse

        $allverinfo_json_path = "${ver}-versioninfo.json"
        $allacl_json_path = "${ver}-acl.json"
        $allrpc_json_path = "${ver}-rpc.json"
        

        $all_verinfo = $all_files | select  Name,VersionInfo
        $all_verinfo | ConvertTo-Json -depth 100 -Compress | Out-File $allverinfo_json_path
        
        $all_acl = $all_files | Get-Acl | select Owner,Group,Access,Sddl,AccessToString,Audit

        # write files
        #$all_verinfo | ConvertTo-Json -depth 100 -Compress | Out-File $allverinfo_json_path
        $all_acl | ConvertTo-Json -depth 100 -Compress | Out-File $allacl_json_path


        # get rpc info
        #Install-Module -Name NtObjectManager
        Set-GlobalSymbolResolver -DbgHelpPath 'C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\dbghelp.dll' 
        $all_rpc = $all_files | Get-RpcServer
        $all_rpc | select InterfaceId, InterfaceVersion, TransferSyntaxId, TransferSyntaxVersion, ProcedureCount, Procedures, Server, FilePath, Name, ServiceName, ServiceDisplayName, IsServiceRunning, Endpoints, EndpointCount, Client | ConvertTo-Json -depth 3  | Out-File $allrpc_json_path
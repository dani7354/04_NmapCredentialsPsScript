
Param(
    #IP scope
    [parameter(Mandatory)]
    [String]$IPScope, 
    
    #Output file
    [parameter(Mandatory)]
    [String]$OutputDir,
    
    # fingerprint file
    [parameter(Mandatory=$false)]
    [String]$FingerprintFile = "",
    
    # TCP ports
    [parameter(Mandatory=$false)]
    [int[]]$Ports = @(80,443),
    
    # Delete the raw reports from the scans (located in %temp%)
    [Parameter(Mandatory=$false)]
    [Boolean]
    $DeleteOrgXmlReports = $true
    
    )
    
    $BaseLocation = $env:TEMP
    $NmapPath = "C:\Program Files (x86)\Nmap\nmap.exe"  
    
    # Check for valid path to nmap executable
    $NmapExe = Get-Item $NmapPath
    if(!$NmapExe){
        Write-Host "Nmap executable not found at the specified path. Please update this path and run the script again!"
        Write-Host "Exiting with code 1"
        exit 1
    }
    
    # Creating file name without dots and slash from CIDR notation - TODO: use a regular expression
    $TempXmlBaseName = $IPScope.Replace('/', '_').Replace('.', '_')
    
    # Folder for temporary generated XML scan reports
    $TempDir = "$($BaseLocation)\nmap-temp-"
    $TempDir += Get-Date -Format "dd-MM-yyyy_HH_mm"
    $ExistingFolder = Get-Item $TempDir -ErrorAction SilentlyContinue
    if($ExistingFolder){
       Remove-Item -Recurse $ExistingFolder 
    }
    New-Item -Path $TempDir -ItemType Directory > $null
    
    # Perform credential scan separately on the specified ports
    if($Ports.Length -gt 0){
        foreach ($Port in $Ports) {
            try {
                if(($Port -lt 65536)  -and ($Port -gt 0)){ 
                    $TempOutFile = "$($TempXmlBaseName)_port$($Port).xml" 
                    Write-Host "Performing default credentials check on hosts $($IPScope) TCP port $($Port)"
                    
                    & $NmapExe -sV --script http-default-accounts.nse -p $Port $IPScope -oX  "$($TempDir)\$($TempOutFile)" > $null
                }
            }
            catch {
                Write-Host "Something went wrong while perforing the scan: $($IPScope) : $($Port)!"
                continue 
            }
        }
    }
    else {
        Write-Host "No ports specified - QUITTIG!"
    }
    
    # Read the generated XML reports
    try {
        $Services = @()
        $XmlFiles = Get-ChildItem -Path $TempDir
        foreach ($File in $XmlFiles) {
            [Xml]$Report = Get-Content -Path "$($TempDir)\$File"
           $Hosts = $Report.SelectNodes("//host")
            foreach ($HostNode in $Hosts) {
                $AddressNode = $HostNode.SelectSingleNode("address[@addrtype='ipv4']")
    
                # Skip to next host if host is not valid 
                if(!$AddressNode){
                    continue
                }
                    $PortNode = $HostNode.SelectSingleNode("ports/port")
                    $Service = New-Object psobject ;
                    $Service | Add-Member -MemberType NoteProperty -Name Host -Value $AddressNode.addr
                    $Service | Add-Member -MemberType NoteProperty -Name Proto -Value $PortNode.protocol
                    $Service | Add-Member -MemberType NoteProperty -Name Port -Value $PortNode.portid
                    $Service | Add-Member -MemberType NoteProperty -Name State -Value $PortNode.state.state
                    $Service | Add-Member -MemberType NoteProperty -Name Service -Value ("$($PortNode.service.name) $($PortNode.service.tunnel)")
                    $Service | Add-Member -MemberType NoteProperty -Name ServiceDescription -Value ("$($PortNode.service.product) $($PortNode.service.version) $($PortNode.service.extrainfo)")
                
                # Reading found credentials
                $Credentials = @()
                $CredentialElements = $PortNode.SelectNodes("script[@id='http-default-accounts']/table/table[@key='credentials']/table")
                $CredentialElements | ForEach-Object { 
                    $Password = $_.SelectSingleNode("elem[@key='password']")."#text"
                    $Username = $_.SelectSingleNode("elem[@key='password']")."#text"
                    $Credentials += "$($Username):$($Password)"
                }
                $Service | Add-Member -MemberType NoteProperty -Name Credentials -Value $Credentials
            
                # Reading found paths 
                $Paths = @()
                $PathElements = $PortNode.SelectNodes("script[@id='http-default-accounts']/table/elem[@key='path']") 
                $PathElements | ForEach-Object {
                    $Paths += $_."#text"
                }
                $Service | Add-Member -MemberType NoteProperty -Name Paths -Value $Paths
    
                if (($Service.proto -ne "") -and ($Service.state -ne "closed")) {
                    $Services += $Service
                }
            }
        }
        $Services | Sort-Object -Property Host
    }
    catch {
        Write-Host "Something went wrong while reading XML file(s)"
    }
    finally{
    
        # Delete XML reports
        if($DeleteOrgXmlReports){
            Write-Host "Removing temporary nmap XML reports located in $($TempDir)"
            Remove-Item -Recurse $TempDir
        }
        else{
            Write-Host "Nmap XML reports are located in $($TempDir)"
        }
    }
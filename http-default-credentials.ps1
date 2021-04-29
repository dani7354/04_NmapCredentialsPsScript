Function Find-Http-Credentials()
{
Param(
    #IP scope
    [parameter(Mandatory)]
    [String]$IPScope, 
    
    #Output file
    [parameter(Mandatory)]
    [String]$OutputDir,
    
    # fingerprint file
    [parameter(Mandatory=$false)]
    [ValidateScript({Test-Path $_})]
    [String]$FingerprintFile = "",

    # Nmap scan timing option. Default: T3, Most aggressive: T5, Most paranoid: T0 see https://nmap.org/book/man-performance.html for details
    [Parameter(Mandatory=$false)]
    [ValidateSet("T0", "T1", "T2", "T3", "T4", "T5")]
    [String]
    $ScanTime = "T3",

    # TCP port range
    [parameter(Mandatory=$false)]
    [String]$PortRange ="80,443",

    # Delete the raw reports from the scans (located in %temp%)
    [parameter(Mandatory=$false)]
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


    # Discover hosts, services and try out default credentials.
    if($PortRange -ne ""){
        $TempOutFile = "$($TempXmlBaseName)_ports$($PortRange).xml"
        Write-Host "Performing scan and default credentials check on host(s) $($IPScope) TCP ports $($PortRange)"

        & $NmapExe -sV --script http-default-accounts.nse -p $PortRange $IPScope -oX  "$($TempDir)\$($TempOutFile)" -$ScanTime > $null
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
                $PortNodes = $HostNode.SelectNodes("ports/port")
                foreach ($PortNode in $PortNodes) {
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
                        $Username = $_.SelectSingleNode("elem[@key='username']")."#text"
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
        }
        $Services | Sort-Object -Property Host | Format-Table -AutoSize
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
}

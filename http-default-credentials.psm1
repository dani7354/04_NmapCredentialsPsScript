$BaseLocation = $env:TEMP
$NmapPath = "C:\Program Files (x86)\Nmap\nmap.exe"  
 
# Functions for internal use
Function GetNmapLocation()
{
    $NmapExe = Get-Item $NmapPath
    if(!$NmapExe){
       Write-Error "Nmap executable not found at the specified path. Please update this path and run the script again!"
       Write-Error "Exiting with code 1"
       exit 1 
    }
    $NmapExe
}

Function GetServicesFromXml()
{
    Param(
        [Parameter(Mandatory)]
        [String]$XmlDir
    )
    $ServiceCol = @()
    $XmlFiles = Get-ChildItem -Path $XmlDir
    foreach ($File in $XmlFiles) 
    {
        [Xml]$ScanReport = Get-Content -Path "$($XmlDir)\$File"
        $Hosts = $ScanReport.SelectNodes("//host")
        foreach ($Host in $Hosts) 
        {
            # Check if the host state == up
            if($Host.status.state -ne "up"){
                Write-Host "Host not up"
                continue
            }

            # Check for XML node with valid IP address
            $AddressNode = if($Host.SelectSingleNode("address[@addrtype='ipv4']")) { $Host.SelectSingleNode("address[@addrtype='ipv4']") } Else { $Host.SelectSingleNode("address[@addrtype='ipv6']")  }
            if(!$AddressNode.addr){
                Write-Host "Host skipped!"
                    continue
            }
            
            $HostObj = [PSCustomObject]@{
                Mac = if($Host.SelectSingleNode("address[@addrtype='mac']")) {  $Host.SelectSingleNode("address[@addrtype='mac']").addr } Else { "" }
                Ip = $AddressNode.addr
            }


            # Read all open ports
            $PortNodes = $Host.SelectNodes("ports/port")
            foreach ($Port in $PortNodes) 
            {
                if($Port.state -eq "closed"){
                    Write-Host "Skip"
                    continue
                }
                $ServiceObj = [PSCustomObject]@{
                    HostIp = $HostObj.Ip
                    HostMac = $HostObj.Mac
                    Protocol = $Port.protocol
                    Port = $Port.portid
                    State = $Port.state.state
                    Service = "$($Port.service.name) $($Port.service.tunnel)"
                    ServiceDescription = "$($Port.service.product) $($Port.service.version) $($Port.service.extrainfo)"
                    NseScriptResult = ""
                }

                $NseScriptXPath = ""
                switch ($Port.service.name) {
                    "http" { $NseScriptXPath = "script[@id='http-default-accounts']" }
                    "ftp" { $NseScriptXPath = "script[@id='ftp-anon']" }
                    Default {}
                }

                $ScriptNode = $Port.SelectSingleNode($NseScriptXPath)
                if($ScriptNode){
                    Write-Host $ScriptNode.output
                   # $ScriptOutput = $ScriptNode.output.Replace("\n", "").Replace("\r", "").Replace("&#xa;", "").Replace("\\n", "").Replace("\\r", "")
                   $ScriptOutput = $ScriptNode.output -Replace "`n","" -Replace "`r",""
                    $ServiceObj.NseScriptResult = "[$($ScriptNode.id)]: $($ScriptOutput)"
                }
                $ServiceCol += $ServiceObj
            }
        }
    }
    $ServiceCol
}

Function Find-HttpServicesUsingWeakAuth()
{
Param(
    # Hosts to scan
    [parameter(Mandatory)]
    [String]$HostRange, 
    
    # Path to CSV file for scan results
    [parameter(Mandatory=$false)]
    [String]$Csv = "",
    
    # fingerprint file. If none is specified the default fingerprint file will be used
    [parameter(Mandatory=$false)]
    [ValidateScript({Test-Path $_})]
    [String]$Fingerprints = "",

    # Nmap scan timing option. Default: T3, Most aggressive: T5, Most paranoid: T0 see https://nmap.org/book/man-performance.html for details
    [Parameter(Mandatory=$false)]
    [ValidateSet("T0", "T1", "T2", "T3", "T4", "T5")]
    [String]$ScanTime = "T3",

    # TCP port range
    [parameter(Mandatory=$false)]
    [ValidateScript({$_ -ne ""})]
    [String]$PortRange ="80,443",

    # Delete the raw reports from the scans (located in %temp%)
    [parameter(Mandatory=$false)]
    [Boolean]$DeleteOrgXmlReports = $true
    )
    
    # Check for valid path to nmap executable
    $NmapExe = GetNmapLocation
  
    # Creating file name without dots and slash from CIDR notation - TODO: use a regular expression
    $TempXmlBaseName = $HostRange.Replace('/', '_').Replace('.', '_')
    
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
        Write-Host "Performing scan and default credentials check on host(s) $($HostRange) TCP ports $($PortRange)"

        if($Fingerprints -ne ""){
            Write-Host "Using alternative fingerprint file: $($Fingerprints)"
            & $NmapExe -sV --script "http-default-accounts.nse, ftp-anon.nse" --script-args http-default-accounts.fingerprintfile=$Fingerprints -p $PortRange $HostRange -oX  "$($TempDir)\$($TempOutFile)" -$ScanTime > $null
        }
        else{
            & $NmapExe -sV --script "http-default-accounts.nse, ftp-anon.nse" -p $PortRange $HostRange -oX  "$($TempDir)\$($TempOutFile)" -$ScanTime > $null
        }
    }
    
    # Read the generated XML reports
   # try {
        $Services = GetServicesFromXml $TempDir
        $Services |Sort-Object -Property "HostIp" |Export-Csv -Path $Csv -Delimiter ";"
        $Services 
#        $Services = @()
#        $XmlFiles = Get-ChildItem -Path $TempDir
#        foreach ($File in $XmlFiles) {
#            [Xml]$Report = Get-Content -Path "$($TempDir)\$File"
#           $Hosts = $Report.SelectNodes("//host")
#            foreach ($HostNode in $Hosts) {
#                $AddressNode = $HostNode.SelectSingleNode("address[@addrtype='ipv4']")
#    
#                # Skip to next host if host is not valid 
#                if(!$AddressNode){
#                    continue
#                }
#                $PortNodes = $HostNode.SelectNodes("ports/port")
#                foreach ($PortNode in $PortNodes) {
#                    $Service = New-Object psobject ;
#                    $Service | Add-Member -MemberType NoteProperty -Name Host -Value $AddressNode.addr
#                    $Service | Add-Member -MemberType NoteProperty -Name Proto -Value $PortNode.protocol
#                    $Service | Add-Member -MemberType NoteProperty -Name Port -Value $PortNode.portid
#                    $Service | Add-Member -MemberType NoteProperty -Name State -Value $PortNode.state.state
#                    $Service | Add-Member -MemberType NoteProperty -Name Service -Value ("$($PortNode.service.name) $($PortNode.service.tunnel)")
#                    $Service | Add-Member -MemberType NoteProperty -Name ServiceDescription -Value ("$($PortNode.service.product) $($PortNode.service.version) $($PortNode.service.extrainfo)")
#                     # Reading found credentials
#                    $Credentials = ""
#                    $CredentialElements = $PortNode.SelectNodes("script[@id='http-default-accounts']/table/table[@key='credentials']/table")
#                    $CredentialElements | ForEach-Object { 
#                        $Password = $_.SelectSingleNode("elem[@key='password']")."#text"
#                        $Username = $_.SelectSingleNode("elem[@key='username']")."#text"
#                        $Credentials += if($Credentials.Length -eq 0) {"$($Username):$($Password)"} Else {", $($Username):$($Password)"}
#                    }
#                    $Service | Add-Member -MemberType NoteProperty -Name Credentials -Value $Credentials
#            
#                    # Reading found paths 
#                    $Paths = ""
#                    $PathElements = $PortNode.SelectNodes("script[@id='http-default-accounts']/table/elem[@key='path']") 
#                    $PathElements | ForEach-Object {
#                        $Paths +=  if ($Paths.Length -eq 0)  {$_."#text"} Else {", " + $_."#text"} 
#                    }
#                    $Service | Add-Member -MemberType NoteProperty -Name Paths -Value $Paths
#    
#                    if (($Service.proto -ne "") -and ($Service.state -ne "closed")) {
#                        $Services += $Service
#                    }
#                }
#            }
#        }
#        # Return found services and credentials if any!
#        if($Services.Length -gt 0){
#            $ServiceSorted = $Services | Sort-Object -Property Host
#            if($Csv -ne ""){
#                $ServiceSorted | Export-Csv -Path $Csv -Delimiter ";"
#            }
#            $ServiceSorted | Format-Table -AutoSize
#        }
#        else{
#            Write-Host "No services were found!"
#        }
 #   }
 #   catch {
#        Write-Host "Something went wrong while reading XML file(s)"
#    }
#    finally{
#    
#        # Delete XML reports
#        if($DeleteOrgXmlReports){
#            Write-Host "Removing temporary nmap XML reports located in $($TempDir)"
#            Remove-Item -Recurse $TempDir
#        }
#        else{
#            Write-Host "Nmap XML reports are located in $($TempDir)"
#        }
#    }
}

Function Find-FtpServicesWithAnonAuth(){
    Write-Warning "Hello World!"
}
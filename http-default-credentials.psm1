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

Function CreateTemporaryDirectory()
{
    $TempDir = "$($BaseLocation)\nmap-temp-"
    $TempDir += Get-Date -Format "dd-MM-yyyy_HH_mm_ss_fff"
    $ExistingFolder = Get-Item $TempDir -ErrorAction SilentlyContinue

    if($ExistingFolder){
       Remove-Item -Recurse $ExistingFolder 
    }

    New-Item -Path $TempDir -ItemType Directory > $nulla
    $TempDir
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
                Write-Host "Skip host (up)"
                continue
            }

            # Check for XML node with valid IP address
            $AddressNode = if($Host.SelectSingleNode("address[@addrtype='ipv4']")) { $Host.SelectSingleNode("address[@addrtype='ipv4']") } Else { $Host.SelectSingleNode("address[@addrtype='ipv6']")  }
            if(!$AddressNode.addr){ # TODO: check if theres a better way to check false /null 
                Write-Host "Skip host"
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
                if($Port.state.state -eq "closed"){
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

                switch ($Port.service.name) {
                    "http" { $ScriptNode = $Port.SelectSingleNode("script[@id='http-default-accounts']") }
                    "ftp" { $ScriptNode = $Port.SelectSingleNode("script[@id='ftp-anon']") }
                    Default { $ScriptNode = $null }
                }

                if($ScriptNode){
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
    [String[]]$HostRanges, 
    
    # Path to CSV file for scan results
    [parameter(Mandatory=$false)]
    [ValidateScript({$_ -match ".+\.csv"})]
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
   try{ 
    # Check for valid path to nmap executable
    $NmapExe = GetNmapLocation

    # Folder for temporary generated XML scan reports
    $TempDir = CreateTemporaryDirectory

    foreach ($HostRange in $HostRanges) {
        # Creating file name without dots and slash from CIDR notation - TODO: use a regular expression
        $TempXmlBaseName = $HostRange.Replace('/', '_').Replace('.', '_').Replace(',', '_')

        # Discover hosts, services and try out default credentials.
        if($PortRange -ne ""){
            $TempOutFile = "$($TempXmlBaseName)_ports$($PortRange).xml"
            Write-Host "Performing scan and default credentials check on host(s) $($HostRange) TCP ports $($PortRange)"

            if($Fingerprints -ne ""){
                Write-Host "Using alternative fingerprint file: $($Fingerprints)"
                & $NmapExe -sV --script "http-default-accounts.nse" --script-args http-default-accounts.fingerprintfile=$Fingerprints -p $PortRange $HostRange -oX  "$($TempDir)\$($TempOutFile)" -$ScanTime > $null
            }
            else{
                & $NmapExe -sV --script "http-default-accounts.nse" -p $PortRange $HostRange -oX  "$($TempDir)\$($TempOutFile)" -$ScanTime > $null
            }
        }
    }
    
    # Read the generated XML reports
    Write-Host "Reading XML output from the scans preparing output"
    $Services = GetServicesFromXml -XmlDir $TempDir
    $ServicesSorted = $Services |Sort-Object -Property "HostIp"
    if($Csv -ne "" -and $ServicesSorted.Length -gt 0){
        Write-Host "Exporting CSV file: $($Csv)..."
        $ServicesSorted |Export-Csv -Path $Csv -Delimiter ";" 
    }
    $ServicesSorted
    }
    catch {
        Write-Error -Message "Something went wrong!" 
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


Function Find-FtpServicesWithAnonAuth(){
# Hosts to scan
Param(
    [parameter(Mandatory)]
    [String[]]$HostRanges, 
    
    # Path to CSV file for scan results
    [parameter(Mandatory=$false)]
    [ValidateScript({$_ -match ".+\.csv"})]
    [String]$Csv = "",
    
    # Nmap scan timing option. Default: T3, Most aggressive: T5, Most paranoid: T0 see https://nmap.org/book/man-performance.html for details
    [Parameter(Mandatory=$false)]
    [ValidateSet("T0", "T1", "T2", "T3", "T4", "T5")]
    [String]$ScanTime = "T3",

    # TCP port range
    [parameter(Mandatory=$false)]
    [ValidateScript({$_ -ne ""})]
    [String]$Ports ="21,990,2121",

    # Delete the raw reports from the scans (located in %temp%)
    [parameter(Mandatory=$false)]
    [Boolean]$DeleteOrgXmlReports = $true
    )

    try {
        # Check for valid path to nmap executable
        $NmapExe = GetNmapLocation

        # Folder for temporary generated XML scan reports
        $TempDir = CreateTemporaryDirectory
        foreach ($HostRange in $HostRanges) {
            # Creating file name without dots and slash from CIDR notation - TODO: use a regular expression
            $TempXmlBaseName = $HostRange.Replace('/', '_').Replace('.', '_').Replace(',', '_')

            # Discover hosts, services and try out default credentials.
            $TempOutFile = "$($TempXmlBaseName)_ports$($Ports).xml"
            Write-Host "Scanning for services and testing FTP services for anonymous login on host(s) $($HostRange) TCP ports $($Ports)..."

            & $NmapExe -sV --script "ftp-anon.nse" -p $Ports $HostRange -oX  "$($TempDir)\$($TempOutFile)" -$ScanTime > $null
        }

        $Services = GetServicesFromXml -XmlDir $TempDir
        $ServicesSorted = $Services | Sort-Object -Property "HostIp"
        if($Csv -ne ""){
            Write-Host "Exporting CSV file: $($Csv)..."
            $ServicesSorted | Export-Csv -Path $Csv -Delimiter ";"
        }
        $ServicesSorted
    }
    catch {
        Write-Error -Message "Something went wrong!"
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

# Exported functions
Export-ModuleMember -Function Find-FtpServicesWithAnonAuth, Find-HttpServicesUsingWeakAuth
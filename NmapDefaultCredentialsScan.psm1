$BaseLocation = $env:TEMP
$NmapPath = "C:\Program Files (x86)\Nmap\nmap.exe"  

$InsecureCiphers = @("3des-cbc", "arcfour", "arcfour256", "arcfour128", "aes256-cbc", "aes128-cbc", "aes196-cbc")
$InsecureMac = @("hmac-md5", "hmac-md5-96", "hmac-sha1-96", "hmac-md5-96@openssh.com", "hmac-md5-etm@openssh.com", "hmac-md5-96-etm@openssh.com")
$InsecureKeyEx = @("diffie-hellman-group1-sha1", " diffie-hellman-group14-sha1", "rsa1024-sha1")

# Functions for internal use
Function GetNmapLocation(){
    $NmapExe = Get-Item $NmapPath
    if(!$NmapExe){
       Write-Error "Nmap executable not found at the specified path. Please update this path and run the script again!"
       Write-Error "Exiting with code 1"
       exit 1 
    }
    $NmapExe
}

Function CreateTemporaryDirectory(){
    $TempDir = "$($BaseLocation)\nmap-temp-"
    $TempDir += Get-Date -Format "dd-MM-yyyy_HH_mm_ss_fff"
    $ExistingFolder = Get-Item $TempDir -ErrorAction SilentlyContinue

    if($ExistingFolder){
       Remove-Item -Recurse $ExistingFolder 
    }

    New-Item -Path $TempDir -ItemType Directory > $nulla
    $TempDir
}

Function CheckForExistingOutputFile(){
    Param(
        # Path or name for output file
        [Parameter(Mandatory)]
        [String]$Filename
    )
    $FileNameBase = $Filename.Substring(0,$Filename.LastIndexOf("."))
    $FileExtension = $Filename.Substring($Filename.LastIndexOf("."))
    $Counter = 0
    while (Test-Path $Filename) {
       $Filename = "$($FileNameBase)_$($Counter)$($FileExtension)"
       $Counter++ 
    }
    $Filename
}

Function FindInsecureAlgos(){
    Param(
        # Cipher algorithms output from ssh2-enum-algos.nse
        [Parameter(Mandatory)]
        [String[]]
        $EncAlgos,

        # Key exchange algorithms output from ssh-enum-algos.nse
        [Parameter(Mandatory)]
        [String[]]
        $KeyExAlgos,
        
        # Mac algorithms output from ssh2-enum-algos.nse
        [Parameter(Mandatory)]
        [String[]]
        $MacAlgos
    )
    $MacAlgosStr = ""
    $KeyExAlgosStr = ""
    $EncAlgosStr = ""
    foreach ($EncAlgo in $EncAlgos) {
        if($InsecureCiphers.Contains($EncAlgo.Trim())){
            $EncAlgosStr += " $($EncAlgo)"
        }
    }
    foreach ($KeyExAlgo in $KeyExAlgos) {
        if($InsecureKeyEx.Contains($KeyExAlgo.Trim())){
            $KeyExAlgosStr += " $($KeyExAlgo)"
        }
    }
    foreach ($MacAlgo in $MacAlgos) {
        if($InsecureMac.Contains($MacAlgo.Trim())){
            $MacAlgosStr += " $($MacAlgo)"
        }   
    }
    $Result = "[InsecureAlgorithms]:"
    $Result += if($EncAlgosStr.Length -gt 0) { "  Encryption: $($EncAlgosStr) " } else { " Encryption: NONE " }
    $Result += if($MacAlgosStr.Length -gt 0) { "  MAC: $($MacAlgosStr) " } else { " MAC: NONE " }
    $Result += if($KeyExAlgosStr.Length -gt 0) { "  Key Exchange: $($KeyExAlgosStr) " } else { " Key Exchange: NONE " }
    $Result
}

Function GetHostsFromXml(){
    Param(
        [Parameter(Mandatory)]
        [String]$XmlDir
    )
    $HostCol = @()
    $XmlFiles = Get-ChildItem -Path $XmlDir
    foreach ($File in $XmlFiles) 
    {
        [Xml]$ScanReport = Get-Content -Path "$($XmlDir)\$File"
        $Hosts = $ScanReport.SelectNodes("//host")
        foreach ($Host in $Hosts) 
        {
            # Check for XML node with valid IP address
            $AddressNode = if($Host.SelectSingleNode("address[@addrtype='ipv4']")) { $Host.SelectSingleNode("address[@addrtype='ipv4']") } Else { $Host.SelectSingleNode("address[@addrtype='ipv6']")  }
            if(!$AddressNode.addr -or $Host.status.state -ne "up"){ 
                    continue
            }
            $HostObj = [PSCustomObject]@{
                Mac = if($Host.SelectSingleNode("address[@addrtype='mac']")) {  $Host.SelectSingleNode("address[@addrtype='mac']").addr } Else { "N/A" }
                Ip = $AddressNode.addr
                State = $Host.status.state
            }

            $HostCol += $HostObj
        }
    }
    $HostCol
}

Function GetServicesFromXml(){
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
                continue
            }
            # Check for XML node with valid IP address
            $AddressNode = if($Host.SelectSingleNode("address[@addrtype='ipv4']")) { $Host.SelectSingleNode("address[@addrtype='ipv4']") } Else { $Host.SelectSingleNode("address[@addrtype='ipv6']")  }
            if(!$AddressNode.addr){ 
                    continue
            }
            $Mac = if($Host.SelectSingleNode("address[@addrtype='mac']")) {  $Host.SelectSingleNode("address[@addrtype='mac']").addr } Else { "N/A" }
            $Ip = $AddressNode.addr
            # Read all open ports
            $PortNodes = $Host.SelectNodes("ports/port")
            foreach ($Port in $PortNodes) 
            {
                if($Port.state.state -eq "closed"){
                    continue
                }
                $ServiceObj = [PSCustomObject]@{
                    HostIp = $Ip.Trim()
                    HostMac = $Mac.Trim()
                    Protocol = $Port.protocol.Trim()
                    Port = $Port.portid.Trim()
                    State = $Port.state.state.Trim()
                    Service = "$($Port.service.name) $($Port.service.tunnel)".Trim()
                    ServiceDescription = if($Port.service.product -ne "") { "$($Port.service.product) $($Port.service.version) $($Port.service.extrainfo)".Trim() } else { "N/A" }
                    NseScriptResult = ""
                }
                switch ($Port.service.name) {
                    "http" { $ScriptNode = $Port.SelectSingleNode("script[@id='http-default-accounts']") }
                    "ftp" { $ScriptNode = $Port.SelectSingleNode("script[@id='ftp-anon']") }
                    "ssh" { 
                        $ScriptNode =$Port.SelectSingleNode("script[@id='ssh2-enum-algos']") 
                        if($ScriptNode){
                            $EncryptionAlgos = ($ScriptNode.SelectNodes("//script/table[@key='encryption_algorithms']/elem") | ForEach-Object { $_.'#text' })
                            $MacAlgos = ($ScriptNode.SelectNodes("//script/table[@key='mac_algorithms']/elem") | ForEach-Object { $_.'#text' })
                            $KeyExAlgos = ($ScriptNode.SelectNodes("//script/table[@key='kex_algorithms']/elem") | ForEach-Object { $_.'#text' })
 
                            $ServiceObj.NseScriptResult = if($EncryptionAlgos.Length -gt 0) { (FindInSecureAlgos -EncAlgos $EncryptionAlgos -KeyExAlgos $KeyExAlgos -MacAlgos $MacAlgos) } else {"N/A"}
                        }

                        $ScriptNode = $Port.SelectSingleNode("script[@id='ssh-brute']") 
                    }
                    Default { $ScriptNode = $null }
                }
                if($ScriptNode){
                   $ScriptOutput = $ScriptNode.output -Replace "`n","" -Replace "`r",""
                    $ServiceObj.NseScriptResult += "[$($ScriptNode.id)]: $($ScriptOutput)".Trim()
                }
                $ServiceCol += $ServiceObj
            }
        }
    }
    $ServiceCol
}

Function GetXmlFileName(){
    Param(
        # Hostrange to use for filename
        [Parameter(Mandatory)]
        [String]$HostRange
    )
    $FileName = $HostRange.Replace(".","_").Replace("/", "_")
    $FileName += ".xml"
    $FileName
}

Function Find-ActiveHosts(){
# Hosts to scan
Param(
    [Parameter(Mandatory)]
    [String[]]$HostRanges, 
    
    # Path to CSV file for scan results
    [Parameter(Mandatory=$false)]
    [ValidateScript({$_ -match ".+\.csv"})]
    [String]$Csv = "",
    
    # Nmap scan timing option. Default: T3, Most aggressive: T5, Most paranoid: T0 see https://nmap.org/book/man-performance.html for details
    [Parameter(Mandatory=$false)]
    [ValidateSet("T0", "T1", "T2", "T3", "T4", "T5")]
    [String]$ScanTime = "T3",

    # Delete the raw reports from the scans (located in %temp%)
    [Parameter(Mandatory=$false)]
    [Boolean]$DeleteOrgXmlReports = $true
    )

    try {
        # Check for valid path to nmap executable
        $NmapExe = GetNmapLocation

        # Folder for temporary generated XML scan reports
        $TempDir = CreateTemporaryDirectory
        foreach ($HostRange in $HostRanges) {
            $TempXmlBaseName = GetXmlFileName -HostRange $HostRange
            $TempOutFile = "$($TempXmlBaseName).xml"
            Write-Host "Scanning for hosts $($HostRange)..."

            & $NmapExe -vv -sn $HostRange -oX  "$($TempDir)\$($TempOutFile)" -$ScanTime > $null
        }

        $Hosts = GetHostsFromXml -XmlDir $TempDir
        $HostsSorted = $Hosts | Sort-Object -Property "Ip"
        if($Csv -ne ""){
            $CsvFile = CheckForExistingOutputFile -Filename $Csv
            Write-Host "Exporting CSV file: $($CsvFile)..."
            $HostsSorted | Export-Csv -Path $CsvFile -Delimiter ";"
        }
        $HostsSorted
    }
    catch {
        Write-Host "Something went wrong: " + $_.Exception.ToString() -BackgroundColor Red
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

Function Find-HttpServices(){
Param(
    # Hosts to scan
    [Parameter(Mandatory)]
    [String[]]$HostRanges, 
    
    # Path to CSV file for scan results
    [Parameter(Mandatory=$false)]
    [ValidateScript({$_ -match ".+\.csv"})]
    [String]$Csv = "",
    
    # fingerprint file. If none is specified the default fingerprint file will be used
    [Parameter(Mandatory=$false)]
    [ValidateScript({Test-Path $_})]
    [String]$Fingerprints = "",

    # Nmap scan timing option. Default: T3, Most aggressive: T5, Most paranoid: T0 see https://nmap.org/book/man-performance.html for details
    [Parameter(Mandatory=$false)]
    [ValidateSet("T0", "T1", "T2", "T3", "T4", "T5")]
    [String]$ScanTime = "T3",

    # TCP port range
    [Parameter(Mandatory=$false)]
    [ValidateScript({$_ -ne ""})]
    [String]$Ports ="80,443,631,7080,8080,8443,8088,5800,3872,8180,8000,9000,9091",

    # Delete the raw reports from the scans (located in %temp%)
    [Parameter(Mandatory=$false)]
    [Boolean]$DeleteOrgXmlReports = $true
    )
   try{ 
    # Check for valid path to nmap executable
    $NmapExe = GetNmapLocation

    # Folder for temporary generated XML scan reports
    $TempDir = CreateTemporaryDirectory

    foreach ($HostRange in $HostRanges) {
        $TempXmlBaseName = GetXmlFileName -HostRange $HostRange
        if($Ports -ne ""){
            $TempOutFile = "$($TempXmlBaseName)_ports$($Ports).xml"
            Write-Host "Performing scan and default credentials check on host(s) $($HostRange) TCP ports $($Ports)"

            if($Fingerprints -ne ""){
                Write-Host "Using alternative fingerprint file: $($Fingerprints)"
                & $NmapExe -sV --script "http-default-accounts.nse" --script-args http-default-accounts.fingerprintfile=$Fingerprints -p $Ports $HostRange -oX  "$($TempDir)\$($TempOutFile)" -$ScanTime > $null
            }
            else{
                & $NmapExe -sV --script "http-default-accounts.nse" -p $Ports $HostRange -oX  "$($TempDir)\$($TempOutFile)" -$ScanTime > $null
            }
        }
    }
    
    # Read the generated XML reports
    Write-Host "Reading XML output from the scans preparing output"
    $Services = GetServicesFromXml -XmlDir $TempDir
    $ServicesSorted = $Services |Sort-Object -Property "HostIp"
    if($Csv -ne "" -and $ServicesSorted.Length -gt 0){
        $CsvFile = CheckForExistingOutputFile -Filename $Csv 
        Write-Host "Exporting CSV file: $($CsvFile)..."
        $ServicesSorted |Export-Csv -Path $CsvFile -Delimiter ";" 
    }
    $ServicesSorted
    }
    catch {
        Write-Host "Something went wrong: " + $_.Exception.ToString() -BackgroundColor Red
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

Function Find-FtpServices(){
Param(
    # Hosts to scan
    [Parameter(Mandatory)]
    [String[]]$HostRanges, 
    
    # Path to CSV file for scan results
    [Parameter(Mandatory=$false)]
    [ValidateScript({$_ -match ".+\.csv"})]
    [String]$Csv = "",
    
    # Nmap scan timing option. Default: T3, Most aggressive: T5, Most paranoid: T0 see https://nmap.org/book/man-performance.html for details
    [Parameter(Mandatory=$false)]
    [ValidateSet("T0", "T1", "T2", "T3", "T4", "T5")]
    [String]$ScanTime = "T3",

    # TCP port range
    [Parameter(Mandatory=$false)]
    [ValidateScript({$_ -ne ""})]
    [String]$Ports ="21,990,2121",

    # Delete the raw reports from the scans (located in %temp%)
    [Parameter(Mandatory=$false)]
    [Boolean]$DeleteOrgXmlReports = $true
    )

    try {
        # Check for valid path to nmap executable
        $NmapExe = GetNmapLocation

        # Folder for temporary generated XML scan reports
        $TempDir = CreateTemporaryDirectory
        foreach ($HostRange in $HostRanges) {
            $TempXmlBaseName = GetXmlFileName -HostRange $HostRange
            $TempOutFile = "$($TempXmlBaseName)_ports$($Ports).xml"
            Write-Host "Scanning for services and testing FTP services for anonymous login on host(s) $($HostRange) TCP ports $($Ports)..."

            & $NmapExe -sV --script "ftp-anon.nse" -p $Ports $HostRange -oX  "$($TempDir)\$($TempOutFile)" -$ScanTime > $null
        }

        $Services = GetServicesFromXml -XmlDir $TempDir
        $ServicesSorted = $Services | Sort-Object -Property "HostIp"
        if($Csv -ne ""){
            $CsvFile = CheckForExistingOutputFile -Filename $Csv
            Write-Host "Exporting CSV file: $($CsvFile)..."
            $ServicesSorted | Export-Csv -Path $CsvFile -Delimiter ";"
        }
        $ServicesSorted
    }
    catch {
        Write-Host "Something went wrong: " + $_.Exception.ToString() -BackgroundColor Red
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

Function Find-SshServices(){
Param(
    # Hosts to scan
    [Parameter(Mandatory)]
    [String[]]$HostRanges, 
    
    # Path to CSV file for scan results
    [Parameter(Mandatory=$false)]
    [ValidateScript({$_ -match ".+\.csv"})]
    [String]$Csv = "",

    # File containing usernames
    [Parameter(Mandatory=$false)]
    [ValidateScript({ Test-Path -Path $_ })]
    [String]$UsernameFile = "",
    
    # File containing usernames
    [Parameter(Mandatory=$false)]
    [ValidateScript({ Test-Path -Path $_ })]
    [String]$PasswordFile = "",
    
    # File containing pairs of usernames and password separated by '/' (e.g. admin/password)
    [Parameter(Mandatory=$false)]
    [ValidateScript({ Test-Path -Path $_ })]
    [String]$CredFile = "",

    # Nmap scan timing option. Default: T3, Most aggressive: T5, Most paranoid: T0 see https://nmap.org/book/man-performance.html for details
    [Parameter(Mandatory=$false)]
    [ValidateSet("T0", "T1", "T2", "T3", "T4", "T5")]
    [String]$ScanTime = "T3",

    # TCP port range
    [Parameter(Mandatory=$false)]
    [ValidateScript({$_ -ne ""})]
    [String]$Ports ="22,830,2222,2382,22222,55554",

    # Delete the raw reports from the scans (located in %temp%)
    [Parameter(Mandatory=$false)]
    [Boolean]$DeleteOrgXmlReports = $true
    )

    try {
        # Check for valid path to nmap executable
        $NmapExe = GetNmapLocation

        # Folder for temporary generated XML scan reports
        $TempDir = CreateTemporaryDirectory
        foreach ($HostRange in $HostRanges) {
            $TempXmlBaseName = GetXmlFileName -HostRange $HostRange
            $TempOutFile = "$($TempXmlBaseName)_ports$($Ports).xml"
            Write-Host "Scanning for services and testing SSH services for defaukt credentials login on host(s) $($HostRange) TCP ports $($Ports)..."

            if($UsernameFile -ne "" -and $PasswordFile -ne ""){
                & $NmapExe -sV --script "ssh-brute.nse, ssh2-enum-algos.nse" --script-args userdb=$UsernameFile,passdb=$PasswordFile -p $Ports $HostRange -oX  "$($TempDir)\$($TempOutFile)" -$ScanTime > $null
            }
            elseif($CredFile -ne ""){
                & $NmapExe -sV --script "ssh-brute.nse, ssh2-enum-algos.nse" --script-args brute.credfile=$CredFile -p $Ports $HostRange -oX  "$($TempDir)\$($TempOutFile)" -$ScanTime > $null
            }
            else{
                & $NmapExe -sV --script "ssh-brute.nse, ssh2-enum-algos.nse" -p $Ports $HostRange -oX  "$($TempDir)\$($TempOutFile)" -$ScanTime > $null
            }    
        }

        $Services = GetServicesFromXml -XmlDir $TempDir
        $ServicesSorted = $Services | Sort-Object -Property "HostIp"
        if($Csv -ne ""){
            $CsvFile = CheckForExistingOutputFile -Filename $Csv
            Write-Host "Exporting CSV file: $($CsvFile)..."
            $ServicesSorted | Export-Csv -Path $CsvFile -Delimiter ";"
        }
        $ServicesSorted
    }
    catch {
        Write-Host "Something went wrong: " + $_.Exception.ToString() -BackgroundColor Red
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

Function Find-AllServices(){
Param(
    # Hosts to scan
    [Parameter(Mandatory)]
    [String[]]$HostRanges, 
    
    # Path to CSV file for scan results
    [Parameter(Mandatory=$false)]
    [ValidateScript({$_ -match ".+\.csv"})]
    [String]$Csv = "",

    # File containing usernames
    [Parameter(Mandatory=$false)]
    [ValidateScript({ Test-Path -Path $_ })]
    [String]$UsernameFile = "",
    
    # File containing fingerprints 
    [Parameter(Mandatory=$false)]
    [ValidateScript({ Test-Path -Path $_ })]
    [String]$Fingerprints = "",
    
    # File containing pairs of usernames and password separated by '/' (e.g. admin/password)
    [Parameter(Mandatory=$false)]
    [ValidateScript({ Test-Path -Path $_ })]
    [String]$CredFile = "",

    # Nmap scan timing option. Default: T3, Most aggressive: T5, Most paranoid: T0 see https://nmap.org/book/man-performance.html for details
    [Parameter(Mandatory=$false)]
    [ValidateSet("T0", "T1", "T2", "T3", "T4", "T5")]
    [String]$ScanTime = "T3",

    # TCP port range
    [Parameter(Mandatory=$false)]
    [ValidateScript({$_ -ne ""})]
    [String]$Ports ="0-65535",

    # Delete the raw reports from the scans (located in %temp%)
    [Parameter(Mandatory=$false)]
    [Boolean]$DeleteOrgXmlReports = $true
    )

    try {
        # Check for valid path to nmap executable
        $NmapExe = GetNmapLocation

        # Folder for temporary generated XML scan reports
        $TempDir = CreateTemporaryDirectory
        foreach ($HostRange in $HostRanges) {
            $TempXmlBaseName = GetXmlFileName -HostRange $HostRange
            $TempOutFile = "$($TempXmlBaseName)_ports$($Ports).xml"
            Write-Host "Scanning for services and testing SSH, FTP and HTTP services for anonymous login on host(s) $($HostRange) TCP ports $($Ports)..."

            if($CredFile -ne "" -and $Fingerprints -ne ""){
                & $NmapExe -sV --script "ssh-brute.nse" --script "ftp-anon.nse" --script "ssh2-enum-algos.nse" --script "http-default-accounts.nse" --script-args brute.credfile=$CredFile --script-args http-default-accounts.fingerprintsfile=$Fingerprints -p $Ports $HostRange -oX  "$($TempDir)\$($TempOutFile)" -$ScanTime > $null
            }
            elseif($CredFile -ne ""){
                & $NmapExe -sV --script "ssh-brute.nse" --script "ftp-anon.nse" --script "ssh2-enum-algos.nse" --script "http-default-accounts.nse" --script-args brute.credfile=$CredFile -p $Ports $HostRange -oX  "$($TempDir)\$($TempOutFile)" -$ScanTime > $null
            }
            elseif($Fingerprints -ne ""){
                & $NmapExe -sV --script "ssh-brute.nse" --script "ftp-anon.nse" --script "ssh2-enum-algos.nse" --script "http-default-accounts.nse" --script-args http-default-accounts.fingerprintsfile=$Fingerprints -p $Ports $HostRange -oX  "$($TempDir)\$($TempOutFile)" -$ScanTime > $null
            }
            else{
                & $NmapExe -sV --script "ssh-brute.nse" --script "ftp-anon.nse" --script "ssh2-enum-algos.nse" --script "http-default-accounts.nse" -p $Ports $HostRange -oX  "$($TempDir)\$($TempOutFile)" -$ScanTime > $null
            }    
        }

        $Services = GetServicesFromXml -XmlDir $TempDir
        $ServicesSorted = $Services | Sort-Object -Property "HostIp"
        if($Csv -ne ""){
            $CsvFile = CheckForExistingOutputFile -Filename $Csv
            Write-Host "Exporting CSV file: $($CsvFile)..."
            $ServicesSorted | Export-Csv -Path $CsvFile -Delimiter ";"
        }
        $ServicesSorted
    }
    catch {
        $LineNumber = $_.Exception.InvocationInfo.ScriptLineNumber
        $ExceptionInfo = $_.Exception.ToString()

        Write-Host "Something went wrong at line $($LineNumber): $($ExceptionInfo)" -BackgroundColor Red
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
New-Alias -Name fd-hosts -Value Find-ActiveHosts
New-Alias -Name fd-ftp -Value Find-FtpServices
New-Alias -Name fd-http -Value Find-HttpServices
New-Alias -Name fd-ssh -Value Find-SshServices
New-Alias -Name fd-alls -Value Find-AllServices
Export-ModuleMember -Function Find-ActiveHosts, Find-FtpServices, Find-HttpServices, Find-SshServices, Find-AllServices -Alias fd-hosts, fd-ftp, fd-http, fd-ssh
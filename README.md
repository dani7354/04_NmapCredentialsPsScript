# PSModule with Nmap wrapper functions for testing access with default credentials
## About
This PowerShell module contains scripts for scanning networks for active hosts and testing selected protocols for access with default credentials. The scans are carried out using Nmap for Windows. After the scanning is completed, the scripts will read through the scanning results from temporary XML files and print out the results as a list containing PowerShell-style objects (PSCustomObject)

Following scripts are included:
* __Find-ActiveHosts__: Scans for active hosts on the selected networks.
* __Find-FtpServices__: Scans for services on the selected ports. Afterwards, it checks FTP services for anonymous login.
* __Find-HttpServices__: Scans for services in the selected ports and tests the found HTTP services for access with a list of credentials provided by the user (or Nmap). By default it uses the fingerprint file included in the Nmap installation to recognize the services, but an alternative file can be provided by the user.
* __Find-SshServices__: Scans for services on the selected networks and ports. The script looks after SSH services and checks whether it is possible to gain access with a list of credentials provided by the user (or the Nmap installation). Also, it checks the SSH server's supported algorithms for key exchange, encryption and message authentication (MAC).
* __Find-AllServices__: This script scans both FTP, HTTP and SSH services as described above.


## Setup
1. Install [Nmap for Windows](https://nmap.org/book/inst-windows.html)
2. Clone the repository:
```
$ git clone --single-branch https://github.com/dani7354/04_NmapCredentialsPsScript.git 
```
3. Place the .psm1 file at the following location (Or at some other location in `$env:PSModulePath`):
```
C:\Users\<USER>\Documents\WindowsPowerShell\Modules\NmapDefaultCredentialsScan
```

4. (Optional) Replace the following files in the Nmap install directory (files included in this repo):
* C:\Program Files (x86)\Nmap\nselib\data\http-default-accounts-fingerprints.lua
* C:\Program Files (x86)\Nmap\nselib\data\shortport.lua

5. Open up PowerShell and import the module:
```PowerShell
> Import-Module NmapDefaultCredentialsScan
```

## Running the scripts

### General parameters for all the scripts:
* __HostRange__: (Mandatory) IP ranges to scan
* __ScanTime__: (Optional) Nmap timing template. "T0" is slowest, "T5" is fastest, "T3" is default. Please refer to [Nmap - Timing and Performance](https://nmap.org/book/man-performance.html) in the Nmap docs for more details.
* __Csv__: (Optional) Nam of CSV file to create with the scan results
* __DeleteOrgXmlReports__: (Optional) Delete the XML reports, which are created by Nmap tohold the scanning results temporarily. Can be $true or $false (Default is $true).

### Find-ActiveServices
Example:
```PowerShell
> Find-ActiveHosts -HostRanges "192.168.1.0/24", "10.211.55.0/24" -ScanTime "T4" -Csv "ActiveHosts.csv" -Delete
OrgXmlReports $false
```

### Find-FtpServices
Example:
```PowerShell
> Find-FtpServices -HostRanges "10.211.55.0/24" -Ports "0-65535" -ScanTime "T4" -Csv "FtpServices.csv" -DeleteOrgXmlReports $false
```
Parameters:
* __Ports__: (Optional) Ports to scan for services (Default: 21,990,2121).

### Find-HttpServices
Example:
```PowerShell
> Find-HttpServices -HostRanges "192.168.1.0/24" -Ports "80,443,8000,8081" -ScanTime "T3" -Fingerprints "alt-http-default-accounts-fingerprints.lua" -Csv "HttpServices.csv" -DeleteOrgXmlReports $false
```
* __Ports__: (Optional) Ports to scan for services (Default: 80,443,631,7080,8080,8443,8088,5800,3872,8180,8000,9000,9091).
* __Fingerprints__: (Optional) Alternative fingerprint file

### Find-SshServices
Example:
```PowerShell
> Find-SshServices -HostRanges "192.168.1.0/24" -Ports "22,2222" -ScanTime "T4" -CredFile "ssh_creds.lst" -Csv "SshServices.csv"
```
* __Ports__: (Optional) Ports to scan for services (Default: 22,830,2222,2382,22222,55554).
* __CredFile__: (Optional) Textfile containing set of usernames and passwords separated by a slash (/). E.g. admin/12345678. Used INSTEAD OF the "UsernameFile" and "PasswordFile" parameters.
* __UsernameFile__: (Optional) Textfile containing only username. Used IN COMBINATION with with the "PasswordFile" parameter
* __PasswordFile__: (Optional) Textfile containing only passwords. Used IN COMBINATION with the "UsernameFile" parameter.

### Find-AllServices
* __Ports__: (Optional) Ports to scan for services (Default: 0-65535)
* __CredFile__: (Optional) See "Find-SshServices" for explanation.
* __FingerprintFile__: (Optional) See "Find-HttpServices" for explanation
<#
.SYNOPSIS
   Patch for Microsoft's design deficiency of not logging PublisherTBSHash if ACFB policy is enfoiced.

.DESCRIPTION
   ExtractTBSHash is a tool that fixes a design deficiency of an Application Control for Business (former WDAC)
   security control by Microsoft. When ACfB policy is enforced, it does not log neither of the following file
   attributes necessary for the scalable ACfB policy rule creation:
   PublisherNAme, IssuerName, PublisherTBSHash, SHA1 and SHA256 hashes.
   This tool extracts at least PublisherTBSHash and IssuerName from the blocked file that allows a publisher rule creation.

   USAGE SUMMARY:
   Script is intended to be executed from a scheduled task triggered by ACfB blocked file event ID, usually 3033.
   The installer takes care of a creation of the scheduled task and event log source for its own output.

.NOTES
   Requires  : PowerShell V5 on Windows 11 24H2 (Constrained Language Mode is fine) - it fails on older OS with PS v4.0
   Version   : see $patchVer
   Contacts  : sazari@worldbankgroup.org

   Slow (Full) Mode:
      For longer API call because of the known bug in New-CIPolicyRule the cmdlet needs to be called
      twice accroding to Microsoft. If you are want to enable that mode - please include some known
      harmless signed exe in your installation folder. The example uses putty.exe, but it can be any
      just chnage the name accordingly

   Version History:
      1.0.0 - Initial release
      1.0.1 - Added precreation of event log source at installation time
      1.0.2 - Switched default execution to "fast mode"
      1.0.3 - Added digital signature verification
      1.0.4 - Added comment decorations
      
   LICENSE : MIT License
      Copyright (c) 2025 World Bank Group

      Permission is hereby granted, free of charge, to any person obtaining a copy
      of this software and associated documentation files (the "Software"), to deal
      in the Software without restriction, including without limitation the rights
      to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
      copies of the Software, and to permit persons to whom the Software is
      furnished to do so, subject to the following conditions:

      THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
      IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
      EVENT SHALL THE
      AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
      LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
      OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
      SOFTWARE.

.LINK
	Download: https://tinyurl.com/ACfBbugfix -or- https://github.com/worldbank/ExtractTBSHash
	Public Github repo: https://tinyurl.com/ACfBbugfix -or- https://github.com/worldbank/ExtractTBSHash

.PARAMETER fastMode
If set to $true (default), the script will run in fast mode, which means it will only extract the PublisherTBSHash
and issuer from blocked file using Add-SignerRule ACfB cmdlet.

If set to $false, the script will run in slow mode, which means it will extract both PublisherTBSHash and file hashes
(SHA1 and SHA256) from the blocked file using New-CIPolicyRule cmdlet. This is very slow cmdlet, it scans global catalog
and might take about 25 min to run wuth high CPU utilization.

.PARAMETER EventID
Tells the script which Event ID to look for in the Application log. Default is 3033, but could also be 3077.
This parameter should match the tiriggered event ID from Task Scheduler.

.PARAMETER VerifySelf
If present, the script will verify its own digital signature against the expected WBG-issued certificate.
This is useful to ensure that the script has not been tampered with and is running the official version.

.OUTPUTS
All log files are stored in '.\Log' folder (= "$global:LogFolder").
In both fast and slow modes, the script will create a event log entry in the Application log
with Event ID 33067 for fast mode and 33089 for slow mode. 

.EXAMPLE
.\ExtractTBSHash.ps1
Start ExtractTBSHash.ps1 in fast mode, read last event log entry with ID=3033 and extract Publisher information
from associated file blocked by ACfB

.EXAMPLE
.\ExtractTBSHash.ps1 -EventID 3077
Start ExtractTBSHash.ps1 in fast mode, read last event log entry with ID=3077 and extract Publisher information
from associated file blocked by ACfB

.EXAMPLE
.\ExtractTBSHash.ps1 -fastMode $false -EventID 3033
Start ExtractTBSHash.ps1 in slow mode, read last event log entry with ID=3033 and extract Publisher information
from associated file blocked by ACfB

.EXAMPLE
C:\Windows\System32\conhost.exe --headless powershell.exe -WindowStyle Hidden -NoProfile -ExecutionPolicy Bypass
      -File "C:\Program Files\The World Bank Group\Extract ACfB Signer Info\ExtractTBSHash.ps1" -fastMode $true -EventID 3033
Example of launching the script from a scheduled task with hidden window and bypassing execution policy on Windows 11
using conhost.exe.

.EXAMPLE
.\ExtractTBSHash.ps1 -version
Displays ExtractTBSHash.ps1 dated version number
#>

param(
    [bool]$fastMode = $true,
    [switch]$VerifySelf, # If present, the script will verify its own digital signature against the expected WBG-issued certificate.
    [string]$LogName,
    [string]$EventSource,
    [int]$EventID = 3033,
    [string]$EventLevel,
    [string]$EventUser,
    [string]$EventComputer,
    [datetime]$EventTime,
    [string]$EventXPath # This will often contain a complex string, so handle carefully
)

# Checks if script is digitally signed with specific WBG-issued official signature
$Script:ScriptPath = $MyInvocation.MyCommand.Path
function Test-ScriptSignatureDetails {
    param (
        [string]$ExpectedThumbprint,
        [string]$ExpectedSubject,
        [string]$ExpectedIssuer,
        [string]$ScriptPath = $Script:ScriptPath
    )

    $signature = Get-AuthenticodeSignature -File $ScriptPath

    if ($signature.Status -ne 'Valid') {
        Write-Error "ERROR: Script signature is invalid or missing. Status: $($signature.Status)"
        return $false
    }

    $cert = $signature.SignerCertificate
    $isValid = $true

    if ($ExpectedThumbprint -and ($cert.Thumbprint -ne $ExpectedThumbprint)) {
        Write-Error "ERROR: Certificate thumbprint mismatch."
        Write-Host "Expected: $ExpectedThumbprint"
        Write-Host "Actual:   $($cert.Thumbprint)"
        $isValid = $false
    }

    if ($ExpectedSubject -and ($cert.Subject -ne $ExpectedSubject)) {
        Write-Error "ERROR: Certificate subject mismatch."
        Write-Host "Expected: $ExpectedSubject"
        Write-Host "Actual:   $($cert.Subject)"
        $isValid = $false
    }

    if ($ExpectedIssuer -and ($cert.Issuer -ne $ExpectedIssuer)) {
        Write-Error "ERROR: Certificate issuer mismatch."
        Write-Host "Expected: $ExpectedIssuer"
        Write-Host "Actual:   $($cert.Issuer)"
        $isValid = $false
    }

    if ($isValid) {
        Write-Host "Script signature is valid and matches all specified certificate criteria."
    }

    return $isValid
}

$expectedThumbprint = "CCC157725C0015239D7C25DD883506789E399E91"
$expectedSubject    = "CN=World Bank Group, O=World Bank Group, S=District of Columbia, C=US"
$expectedIssuer     = "CN=Sectigo Public Code Signing CA R36, O=Sectigo Limited, C=GB"

if ($VerifySelf) {
    if (-not (Test-ScriptSignatureDetails -ExpectedThumbprint $expectedThumbprint -ExpectedSubject $expectedSubject -ExpectedIssuer $expectedIssuer)) {
        exit 1 # Exit with error if signature verification fails
    }
}

Import-Module ConfigCI

$patchVer = "1.0.4, June 30, 2025."
$maxExecLimit = 100
$DummyFile = ".\putty.exe"
$LogFolder = ".\Log"
$evtSourceName = "ACfB-WBG-Patch"
$TempFolder = $env:TEMP


function OutStr{
    param(
        [string]$myStr
    )
        Add-Content -Path $logFilePath -Value $myStr
        Write-Host $myStr
}

function ExtractFilePath {
    param(
        [string]$rawMessage
    )

    $filePath = ""
    if ($rawMessage -match "attempted to load (.+) that did not meet") {
        $filePath = $Matches[1]
        $filePath = $filePath.Replace("\Device\HarddiskVolume3\", "C:\")
   }
   return $filePath
}

function ExtractParentProcess {
    param(
        [string]$rawMessage
    )

    $filePath = ""
    if ($rawMessage -match "determined that a process \((.+)\) attempted to load") {
        $filePath = $Matches[1]
        $filePath = $filePath.Replace("\Device\HarddiskVolume3\", "C:\")
   }
   return $filePath
}

function ExtractSignerInfo {
    param(
        [string]$EventFilePath = ".\putty.exe",
        [bool]$fastCheck = $false
    )

    $retMessage = ""
    $IssuerName = "Unknown"
    $PublisherName = "Unknown"
    $PublisherTBSHash = "Unknown"

    if (-not $fastCheck) {
        OutStr "$(Get-Date -Format o) : Generating dummy ACfB SIGNER policy for file: $EventFilePath"
        $DummySignerPolicyPath = Join-Path -Path $TempFolder -ChildPath "$(GenerateRandomFileName).xml"
        OutStr "Generated xml filename for dummy SIGNER policy to be created: $DummySignerPolicyPath"
        .\CreateSignerPolicy.ps1 -WdacBinPath "$DummyFile" -DriverFilePath $EventFilePath `
                                 -PolicyPath $DummySignerPolicyPath -Level "Publisher" -Deny "False"
    }
    else {
        $DummySignerPolicyPath = $EventFilePath
    }
    OutStr "$(Get-Date -Format o) : Dummy policy file location: $DummySignerPolicyPath"

    if (Test-Path -Path $DummySignerPolicyPath) {
        OutStr "Extracting Signer info..."
        [xml]$policyXml = Get-Content -Path $DummySignerPolicyPath

        $firstRule = $policyXml.SiPolicy.Signers.LastChild
        $PublisherName = $firstRule.CertPublisher.Value
        $IssuerName = $firstRule.Name
        $PublisherTBSHash = $firstRule.CertRoot.Value

        # Display its properties
        OutStr "ID: $($firstRule.ID)"
        OutStr "IssuerName: $IssuerName"
        OutStr "PublisherName: $PublisherName"
        OutStr "PublisherTBSHash: $PublisherTBSHash"
        #Delete tmp policy file
        if (-not $fastCheck) {Remove-Item -Path $DummySignerPolicyPath -Force -Confirm:$false -ErrorAction SilentlyContinue}
        $retMessage = "PublisherName=""$PublisherName"" IssuerName=""$IssuerName"" PublisherTBSHash=$PublisherTBSHash"
    }
        else {OutStr "Error creating $DummySignerPolicyPath"}

        $retMessage
}

function WriteEvent {
    param(
        [string]$Message = "ACfB Test.",
        [int]$EventID = 30000
        )
    Write-EventLog -LogName "Application" -Source $evtSourceName -EventID $EventID -EntryType Information -Message $Message
}

function Write33099Event {
    param(
        [string]$Message = "ACfB 33099 Test."
    )
    WriteEvent -Message $Message -EventID 33099
}

function Write33089Event {
    param(
        [string]$Message = "ACfB 33089 Test."
    )
    WriteEvent -Message $Message -EventID 33089
}

function Write33067Event {
    param(
        [string]$Message = "ACfB Fast Check Test (33067)."
    )
    WriteEvent -Message $Message -EventID 33067
}

function CreateSubfolder {
    param(
        [string]$folderPath = ".\TestFolder"
    )

    if (-not (Test-Path -Path $folderPath)) {
        Write-Host "Folder '$folderPath' does not exist. Creating it now..."

        try {
            New-Item -Path $folderPath -ItemType Directory -Force -ErrorAction Stop | Out-Null       
            Write-Host "Successfully created folder: '$folderPath'"
        }
        catch {
            # If an error occurs during folder creation, display the error message.
            Write-Error "Failed to create folder '$folderPath'. Error: $_"
        }
    }
}


function GenerateRandomFileName {
    $randomNameOnly = [System.IO.Path]::GetFileNameWithoutExtension([System.IO.Path]::GetRandomFileName())
    $timestamp = Get-Date -Format "yyyyMMdd-HHmmss-fff"
    "$timestamp-$randomNameOnly" # Return Value
}

function ExtractHashInfo {
    param(
        [string]$EventFilePath
    )

    $retMessage = ""
    $SHA1_Hash = "Unknown"
    $SHA256_Hash = "Unknown"

    OutStr "$(Get-Date -Format o) : Generating dummy ACfB HASH policy for file: $EventFilePath"
    $DummySignerPolicyPath = Join-Path -Path $TempFolder -ChildPath "$(GenerateRandomFileName).xml"
    OutStr "Generated xml filename for dummy HASH policy to be created: $DummySignerPolicyPath"
    .\CreateSignerPolicy.ps1 -WdacBinPath "$DummyFile" -DriverFilePath $EventFilePath `
                             -PolicyPath $DummySignerPolicyPath -Level "Hash" -Deny "False"

    if (Test-Path -Path $DummySignerPolicyPath) {
        OutStr "Extracting Hash info..."
        [xml]$policyXml = Get-Content -Path $DummySignerPolicyPath

        $policyXml.SiPolicy.FileRules.ChildNodes | ForEach-Object {
            $FriendlyName = $_.FriendlyName
            if ($FriendlyName.EndsWith("Hash Sha1")) {$SHA1_Hash = $_.Hash}
            if ($FriendlyName.EndsWith("Hash Sha256")) {$SHA256_Hash = $_.Hash}
        }
        OutStr "SHA1 Hash: $SHA1_Hash"
        OutStr "SHA256 Hash: $SHA256_Hash"
        #Delete tmp policy file
        Remove-Item -Path $DummySignerPolicyPath -Force -Confirm:$false -ErrorAction SilentlyContinue
        $retMessage = "SHA1_Hash=$SHA1_Hash SHA256_Hash=$SHA256_Hash"
    }
    else {OutStr "Error creating " + $DummySignerPolicyPath}                             
    
    $retMessage
}

function LogMaintenance {
    $logCountLimit = $maxExecLimit + 10
    OutStr "Performing log folder maintenance\cleanup ..."
    Set-Location $LogFolder
    $files = get-childitem -filter "*.log" | Sort-Object LastWriteTime -Descending

    $actionMsgStart = "ExtractTBSHash log file Maintenance -"
    $i = 1
    foreach ($file in $files) {
        if ($i -le $logCountLimit) {
            $actionMsg = "$actionMsgStart Keep log file: $($file.Name)"
        }
        else {
            $actionMsg = "$actionMsgStart Delete log file: $($file.Name)"
            Remove-Item -Path $file.Name -Force -Confirm:$false -ErrorAction SilentlyContinue
        }
        #Set-Location "..\"
        #OutStr $actionMsg
        #Set-Location $LogFolder
        $i++
    }
    Set-Location "..\"
}

function FastCertCheck {
    param (
        $filePath = ".\putty.exe"
    )

    $retVal = ""
    $templatePolicy = ".\ExtractTBSHash_Template_v10.0.0.5.xml"
    #$filePath = ".\hashcat.exe"
    $signature = Get-AuthenticodeSignature $filePath

    if ($signature.Status -eq "Valid")
    {
        OutStr "The file '$filePath' is digitally signed and the signature is valid."
        $certPath = Join-Path -Path $TempFolder -ChildPath "$(GenerateRandomFileName).cer"
        OutStr "Temporary certificate file name: $certPath"
        $polPath = Join-Path -Path $TempFolder -ChildPath "ExtractTBSHash-Quick-$(GenerateRandomFileName).xml"
        Copy-Item -Path $templatePolicy -Destination $polPath -Force
        OutStr "Copied Template Policy to: $polPath"

        $cert = $signature.SignerCertificate
        $var = Export-Certificate -Cert $cert -FilePath $certPath

        Add-SignerRule -CertificatePath $certPath -FilePath $polPath -User
        $retVal = ExtractSignerInfo -EventFilePath $polPath -fastCheck $true
        OutStr "Fast Signature check message: $retVal"

        Remove-Item -Path $certPath -Force -Confirm:$false -ErrorAction SilentlyContinue
        Remove-Item -Path $polPath -Force -Confirm:$false -ErrorAction SilentlyContinue
    }
    else {
        OutStr "File '$filePath' either is not signed or signature is not valid."
    }

    $retVal
}

function ParseEvent {
    param(
        [int]$TriggerEventID = 3033,    # Pass the Event ID from Task Scheduler
        [string]$TriggerLogName         # Pass the Log Name from Task Scheduler
    )

    $TriggerLogName = "Microsoft-Windows-CodeIntegrity/Operational"

    # --- Find the most recent matching event ---
    try {
        $latestEvent = Get-WinEvent -LogName $TriggerLogName -FilterXPath "*[System[EventID=$TriggerEventID]]" -MaxEvents 1 -ErrorAction Stop

        if ($latestEvent) {
            $LogName = $latestEvent.LogName
            $EventSource = $latestEvent.ProviderName # Use ProviderName for source
            $EventID = $latestEvent.Id
            $EventLevel = $latestEvent.LevelDisplayName
            $EventComputer = $latestEvent.MachineName
            $EventTime = $latestEvent.TimeCreated
            $EventMessage = $latestEvent.Message
            $EventFilePath = ExtractFilePath -rawMessage $EventMessage
            $EventParentProcess = ExtractParentProcess -rawMessage $EventMessage
            $EventXml = [xml]$latestEvent.ToXml()

            # --- Output/Log for debugging ---
            OutStr "Script version: $patchVer"
            OutStr "Fast mode: $fastMode"
            OutStr "Triggered by Log: $LogName"
            OutStr "Source: $EventSource"
            OutStr "Trigger Event ID: $EventID"
            OutStr "Level: $EventLevel"
            OutStr "Computer: $EventComputer"
            OutStr "Time: $EventTime (UTC)"
            OutStr "Message: $EventMessage"
            OutStr "File Path: $EventFilePath"
            OutStr "Parent Process: $EventParentProcess"
            $ActivityId = $EventXml.Event.System.Correlation.ActivityID
            OutStr "Activity ID: $ActivityId"

            $msgSuffix = " TriggerEventID=$EventID FilePath=""$EventFilePath"" ParentProcess=""$EventParentProcess"" fastMode=$fastMode patchVer=""$patchVer"" ActivityID=$ActivityId"

            $isSigned = FastCertCheck -filePath $EventFilePath
            if ( -not $isSigned -eq "" ) {
                $endTime = Get-Date
                $duration = $endTime - $startTime
                [int]$secRound = $duration.TotalSeconds
                OutStr "Execution Time: $secRound seconds."
                $isSigned += " execTimeSec=$secRound" + $msgSuffix
                Write33067Event -Message $isSigned
            }

            if (-not $fastMode) {
                if ( -not $isSigned -eq "" ) {
                    # if file is signed - calculate both PublisherTBSHash and File Hashes
                    $NewEVT_Message = ExtractHashInfo -EventFilePath $EventFilePath
                    $NewEVT_Message += " $(ExtractSignerInfo -EventFilePath $EventFilePath -fastCheck $false)"
                }
                else {
                    # if file is not signed - calculate only File Hashes
                    $NewEVT_Message = ExtractHashInfo -EventFilePath $EventFilePath
                }

                $endTime = Get-Date
                $duration = $endTime - $startTime
                [int]$secRound = $duration.TotalSeconds
                OutStr "Execution Time: $secRound seconds."
                $NewEVT_Message += " execTimeSec=$secRound" + $msgSuffix
                Write33089Event -Message $NewEVT_Message
            }            
        }
    } catch {
        Add-Content -Path $logFilePath -Value "--- Script Error: $(Get-Date) ---"
        Add-Content -Path $logFilePath -Value "An error occurred: $($_.Exception.Message)"
    } finally {
        # Remove old logs to prevent log folder from growing
        LogMaintenance
        Add-Content -Path $logFilePath -Value "--- Script Finished: $(Get-Date) ---`n"
    }
}

function CheckFrequencySafeguard {
    Set-Location $LogFolder
    $timestampToday = Get-Date -Format "yyyyMMdd"
    $logFileNamePattern = "ExtractTBSHashLogFile-$timestampToday-*.log"
    $files = get-childitem -filter $logFileNamePattern | Sort-Object LastWriteTime -Descending
    Set-Location "..\"
    Write-Host "ExtractTBSHash was executed $($files.Count) times today."
    $files.Count
}

#----------------------START----------------------------------
if ($Version) {
    Write-Host "ExtractTBSHash version: $patchVer"
    exit 0
}
$startTime = Get-Date
# Check if log and temp folders exists, create if not
CreateSubfolder -folderPath $LogFolder
CreateSubfolder -folderPath $TempFolder

if ($(CheckFrequencySafeguard) -gt $maxExecLimit) {
    $msg = "ExtractTBSHash was already executed on this machine more than $maxExecLimit times today. Exiting."
    Write-Host $msg
    Write33099Event -Message $msg
    return
}

$logFilePath = Join-Path -Path $LogFolder -ChildPath "ExtractTBSHashLogFile-$(GenerateRandomFileName).log"
Write-Host "Generated log Filename: $logFilePath"
OutStr "--- Script Started: $(Get-Date) ---"
OutStr "$(Get-Date -Format o) : ACfB Event Log $EventID was generated."
OutStr "This log file name: $logFilePath"
$currentUser = whoami
OutStr "Script runs under user context: $currentUser"

ParseEvent -TriggerEventID $EventID


# SIG # Begin signature block
# MIIulwYJKoZIhvcNAQcCoIIuiDCCLoQCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCDIZA88D8vA483u
# EMDe3EFUZZF/tJ7OWt3FQgdiSyOtAaCCEgEwggVvMIIEV6ADAgECAhBI/JO0YFWU
# jTanyYqJ1pQWMA0GCSqGSIb3DQEBDAUAMHsxCzAJBgNVBAYTAkdCMRswGQYDVQQI
# DBJHcmVhdGVyIE1hbmNoZXN0ZXIxEDAOBgNVBAcMB1NhbGZvcmQxGjAYBgNVBAoM
# EUNvbW9kbyBDQSBMaW1pdGVkMSEwHwYDVQQDDBhBQUEgQ2VydGlmaWNhdGUgU2Vy
# dmljZXMwHhcNMjEwNTI1MDAwMDAwWhcNMjgxMjMxMjM1OTU5WjBWMQswCQYDVQQG
# EwJHQjEYMBYGA1UEChMPU2VjdGlnbyBMaW1pdGVkMS0wKwYDVQQDEyRTZWN0aWdv
# IFB1YmxpYyBDb2RlIFNpZ25pbmcgUm9vdCBSNDYwggIiMA0GCSqGSIb3DQEBAQUA
# A4ICDwAwggIKAoICAQCN55QSIgQkdC7/FiMCkoq2rjaFrEfUI5ErPtx94jGgUW+s
# hJHjUoq14pbe0IdjJImK/+8Skzt9u7aKvb0Ffyeba2XTpQxpsbxJOZrxbW6q5KCD
# J9qaDStQ6Utbs7hkNqR+Sj2pcaths3OzPAsM79szV+W+NDfjlxtd/R8SPYIDdub7
# P2bSlDFp+m2zNKzBenjcklDyZMeqLQSrw2rq4C+np9xu1+j/2iGrQL+57g2extme
# me/G3h+pDHazJyCh1rr9gOcB0u/rgimVcI3/uxXP/tEPNqIuTzKQdEZrRzUTdwUz
# T2MuuC3hv2WnBGsY2HH6zAjybYmZELGt2z4s5KoYsMYHAXVn3m3pY2MeNn9pib6q
# RT5uWl+PoVvLnTCGMOgDs0DGDQ84zWeoU4j6uDBl+m/H5x2xg3RpPqzEaDux5mcz
# mrYI4IAFSEDu9oJkRqj1c7AGlfJsZZ+/VVscnFcax3hGfHCqlBuCF6yH6bbJDoEc
# QNYWFyn8XJwYK+pF9e+91WdPKF4F7pBMeufG9ND8+s0+MkYTIDaKBOq3qgdGnA2T
# OglmmVhcKaO5DKYwODzQRjY1fJy67sPV+Qp2+n4FG0DKkjXp1XrRtX8ArqmQqsV/
# AZwQsRb8zG4Y3G9i/qZQp7h7uJ0VP/4gDHXIIloTlRmQAOka1cKG8eOO7F/05QID
# AQABo4IBEjCCAQ4wHwYDVR0jBBgwFoAUoBEKIz6W8Qfs4q8p74Klf9AwpLQwHQYD
# VR0OBBYEFDLrkpr/NZZILyhAQnAgNpFcF4XmMA4GA1UdDwEB/wQEAwIBhjAPBgNV
# HRMBAf8EBTADAQH/MBMGA1UdJQQMMAoGCCsGAQUFBwMDMBsGA1UdIAQUMBIwBgYE
# VR0gADAIBgZngQwBBAEwQwYDVR0fBDwwOjA4oDagNIYyaHR0cDovL2NybC5jb21v
# ZG9jYS5jb20vQUFBQ2VydGlmaWNhdGVTZXJ2aWNlcy5jcmwwNAYIKwYBBQUHAQEE
# KDAmMCQGCCsGAQUFBzABhhhodHRwOi8vb2NzcC5jb21vZG9jYS5jb20wDQYJKoZI
# hvcNAQEMBQADggEBABK/oe+LdJqYRLhpRrWrJAoMpIpnuDqBv0WKfVIHqI0fTiGF
# OaNrXi0ghr8QuK55O1PNtPvYRL4G2VxjZ9RAFodEhnIq1jIV9RKDwvnhXRFAZ/ZC
# J3LFI+ICOBpMIOLbAffNRk8monxmwFE2tokCVMf8WPtsAO7+mKYulaEMUykfb9gZ
# pk+e96wJ6l2CxouvgKe9gUhShDHaMuwV5KZMPWw5c9QLhTkg4IUaaOGnSDip0TYl
# d8GNGRbFiExmfS9jzpjoad+sPKhdnckcW67Y8y90z7h+9teDnRGWYpquRRPaf9xH
# +9/DUp/mBlXpnYzyOmJRvOwkDynUWICE5EV7WtgwggYaMIIEAqADAgECAhBiHW0M
# UgGeO5B5FSCJIRwKMA0GCSqGSIb3DQEBDAUAMFYxCzAJBgNVBAYTAkdCMRgwFgYD
# VQQKEw9TZWN0aWdvIExpbWl0ZWQxLTArBgNVBAMTJFNlY3RpZ28gUHVibGljIENv
# ZGUgU2lnbmluZyBSb290IFI0NjAeFw0yMTAzMjIwMDAwMDBaFw0zNjAzMjEyMzU5
# NTlaMFQxCzAJBgNVBAYTAkdCMRgwFgYDVQQKEw9TZWN0aWdvIExpbWl0ZWQxKzAp
# BgNVBAMTIlNlY3RpZ28gUHVibGljIENvZGUgU2lnbmluZyBDQSBSMzYwggGiMA0G
# CSqGSIb3DQEBAQUAA4IBjwAwggGKAoIBgQCbK51T+jU/jmAGQ2rAz/V/9shTUxjI
# ztNsfvxYB5UXeWUzCxEeAEZGbEN4QMgCsJLZUKhWThj/yPqy0iSZhXkZ6Pg2A2NV
# DgFigOMYzB2OKhdqfWGVoYW3haT29PSTahYkwmMv0b/83nbeECbiMXhSOtbam+/3
# 6F09fy1tsB8je/RV0mIk8XL/tfCK6cPuYHE215wzrK0h1SWHTxPbPuYkRdkP05Zw
# mRmTnAO5/arnY83jeNzhP06ShdnRqtZlV59+8yv+KIhE5ILMqgOZYAENHNX9SJDm
# +qxp4VqpB3MV/h53yl41aHU5pledi9lCBbH9JeIkNFICiVHNkRmq4TpxtwfvjsUe
# dyz8rNyfQJy/aOs5b4s+ac7IH60B+Ja7TVM+EKv1WuTGwcLmoU3FpOFMbmPj8pz4
# 4MPZ1f9+YEQIQty/NQd/2yGgW+ufflcZ/ZE9o1M7a5Jnqf2i2/uMSWymR8r2oQBM
# dlyh2n5HirY4jKnFH/9gRvd+QOfdRrJZb1sCAwEAAaOCAWQwggFgMB8GA1UdIwQY
# MBaAFDLrkpr/NZZILyhAQnAgNpFcF4XmMB0GA1UdDgQWBBQPKssghyi47G9IritU
# pimqF6TNDDAOBgNVHQ8BAf8EBAMCAYYwEgYDVR0TAQH/BAgwBgEB/wIBADATBgNV
# HSUEDDAKBggrBgEFBQcDAzAbBgNVHSAEFDASMAYGBFUdIAAwCAYGZ4EMAQQBMEsG
# A1UdHwREMEIwQKA+oDyGOmh0dHA6Ly9jcmwuc2VjdGlnby5jb20vU2VjdGlnb1B1
# YmxpY0NvZGVTaWduaW5nUm9vdFI0Ni5jcmwwewYIKwYBBQUHAQEEbzBtMEYGCCsG
# AQUFBzAChjpodHRwOi8vY3J0LnNlY3RpZ28uY29tL1NlY3RpZ29QdWJsaWNDb2Rl
# U2lnbmluZ1Jvb3RSNDYucDdjMCMGCCsGAQUFBzABhhdodHRwOi8vb2NzcC5zZWN0
# aWdvLmNvbTANBgkqhkiG9w0BAQwFAAOCAgEABv+C4XdjNm57oRUgmxP/BP6YdURh
# w1aVcdGRP4Wh60BAscjW4HL9hcpkOTz5jUug2oeunbYAowbFC2AKK+cMcXIBD0Zd
# OaWTsyNyBBsMLHqafvIhrCymlaS98+QpoBCyKppP0OcxYEdU0hpsaqBBIZOtBajj
# cw5+w/KeFvPYfLF/ldYpmlG+vd0xqlqd099iChnyIMvY5HexjO2AmtsbpVn0OhNc
# WbWDRF/3sBp6fWXhz7DcML4iTAWS+MVXeNLj1lJziVKEoroGs9Mlizg0bUMbOalO
# hOfCipnx8CaLZeVme5yELg09Jlo8BMe80jO37PU8ejfkP9/uPak7VLwELKxAMcJs
# zkyeiaerlphwoKx1uHRzNyE6bxuSKcutisqmKL5OTunAvtONEoteSiabkPVSZ2z7
# 6mKnzAfZxCl/3dq3dUNw4rg3sTCggkHSRqTqlLMS7gjrhTqBmzu1L90Y1KWN/Y5J
# KdGvspbOrTfOXyXvmPL6E52z1NZJ6ctuMFBQZH3pwWvqURR8AgQdULUvrxjUYbHH
# j95Ejza63zdrEcxWLDX6xWls/GDnVNueKjWUH3fTv1Y8Wdho698YADR7TNx8X8z2
# Bev6SivBBOHY+uqiirZtg0y9ShQoPzmCcn63Syatatvx157YK9hlcPmVoa1oDE5/
# L9Uo2bC5a4CH2RwwggZsMIIE1KADAgECAhBk1lC4pB88d+7U1HAmOty+MA0GCSqG
# SIb3DQEBDAUAMFQxCzAJBgNVBAYTAkdCMRgwFgYDVQQKEw9TZWN0aWdvIExpbWl0
# ZWQxKzApBgNVBAMTIlNlY3RpZ28gUHVibGljIENvZGUgU2lnbmluZyBDQSBSMzYw
# HhcNMjUwNjI1MDAwMDAwWhcNMjYwNjI1MjM1OTU5WjBiMQswCQYDVQQGEwJVUzEd
# MBsGA1UECAwURGlzdHJpY3Qgb2YgQ29sdW1iaWExGTAXBgNVBAoMEFdvcmxkIEJh
# bmsgR3JvdXAxGTAXBgNVBAMMEFdvcmxkIEJhbmsgR3JvdXAwggIiMA0GCSqGSIb3
# DQEBAQUAA4ICDwAwggIKAoICAQDbWQSAMUDxIw8i4je80JPlZHmrcrWhH8KYKRMS
# K6qDu2fhCJWn4UUthR1nE+vL7Z2r1RZ/loKHHTKJTBHM0rgOvLfsub7aoUUPNYr7
# ODEfVXO89kgcG+KU83Um6gSSQLK0r42tmG0gH1Q21aicrlPvGmv3AwZ3el1TVowN
# TcuZx7PyWhAe/AGxI+WDp818ZNmy2vUTx30s0PF72VSvjRt67Gdkb6rsgWbGkKA6
# gnAvyMGlwnVoiX7pHB/qV/frwThwTqSwrIJYBgjwELcUabp/fs47qz/FhELXgUgz
# xaXH6wT9cph95LEDTdHe6Gc2AbtxSJFWlHxlupPVs7g3z4SqhxZSFlriWpaPwA+C
# vd7JmUGpoY386WSVUQVepFckcBkI4mEd2PJ7zafDzNpmE40yCQaO44f6k/Rf1brw
# ma3Bf4u2Y+P9MLSl4CpsfcrtyZNVicdVabT4vKXyhTI9GlhtJCkaz8EM+WldtKsB
# qGsdfBDp9AQqnSEYKeJdR7bsJ1NTa3oElDAAjJDztx5M/Zp/sMlow/uxgw4cH4sH
# M2ols1MdTtguLk1if8ZtyWmAc4HnTO1hRq8NHdimUGkNdZR9vqqHqyI7DcKDwFIf
# QYUwagZLS5Ow3LAoAfFJgxFbIR/7RpupvFggKHUFykK0wCayVGZE+q+/17TaAd0Z
# 91aP5wIDAQABo4IBqjCCAaYwHwYDVR0jBBgwFoAUDyrLIIcouOxvSK4rVKYpqhek
# zQwwHQYDVR0OBBYEFBXImZos4CT57eJMtRdGVb201AcWMA4GA1UdDwEB/wQEAwIH
# gDAMBgNVHRMBAf8EAjAAMBMGA1UdJQQMMAoGCCsGAQUFBwMDMEoGA1UdIARDMEEw
# NQYMKwYBBAGyMQECAQMCMCUwIwYIKwYBBQUHAgEWF2h0dHBzOi8vc2VjdGlnby5j
# b20vQ1BTMAgGBmeBDAEEATBJBgNVHR8EQjBAMD6gPKA6hjhodHRwOi8vY3JsLnNl
# Y3RpZ28uY29tL1NlY3RpZ29QdWJsaWNDb2RlU2lnbmluZ0NBUjM2LmNybDB5Bggr
# BgEFBQcBAQRtMGswRAYIKwYBBQUHMAKGOGh0dHA6Ly9jcnQuc2VjdGlnby5jb20v
# U2VjdGlnb1B1YmxpY0NvZGVTaWduaW5nQ0FSMzYuY3J0MCMGCCsGAQUFBzABhhdo
# dHRwOi8vb2NzcC5zZWN0aWdvLmNvbTAfBgNVHREEGDAWgRRzYXphcmlAd29ybGRi
# YW5rLm9yZzANBgkqhkiG9w0BAQwFAAOCAYEAcnvRqymgmJz2rsXN8yDi4+F5xLX8
# TcJjiIL3qre1fMa+TyTbs+SmnFJiJ2IzNq2TaebpUgVep5FQt8sC/Z+k8013L9Vh
# RQksEwyDsW7zmpArkM0gIzZc2jeD6OaJXadYvHxKR/UJDG+C5BemQ7Ruh5dvXsjp
# 5WFAtEs55G9WG6K52onBdBGcPnj6Ai7MZ3JuzMID0PTXfAdVxX8SXsTAErCRfr8+
# Ua6zWHlCyP6FyLG65E5Nd1uvBLVwabg37sZVlxFTA3NRiXCPa7Tpe9N6LhyzKgoe
# I9nAe8oGw50/hgKLhZYNcMEDWHwkrDPismG//Ok/vfoz515l+Fe8caQZHNmNeBxe
# ti0qzrbbzBgp+xNvrADRMTwWBntkDPaCPG7WK2zLLkz+Ye8EzkWMvkDR8CtFg+c6
# 3FAnJr5pHSX+bRypy75GGtwAg3FruvpBJNaWiFSsCh3NPtNiyQvCj4mRBDE4Uagy
# 31ZGzxAuI1CHwagmz/Q6c7TAPtWS3A0m3COTMYIb7DCCG+gCAQEwaDBUMQswCQYD
# VQQGEwJHQjEYMBYGA1UEChMPU2VjdGlnbyBMaW1pdGVkMSswKQYDVQQDEyJTZWN0
# aWdvIFB1YmxpYyBDb2RlIFNpZ25pbmcgQ0EgUjM2AhBk1lC4pB88d+7U1HAmOty+
# MA0GCWCGSAFlAwQCAQUAoHwwEAYKKwYBBAGCNwIBDDECMAAwGQYJKoZIhvcNAQkD
# MQwGCisGAQQBgjcCAQQwHAYKKwYBBAGCNwIBCzEOMAwGCisGAQQBgjcCARUwLwYJ
# KoZIhvcNAQkEMSIEIP4ZyeYFS/dx19ukosCzDXRzX4SLrO1ilD5Ra8nC0yPPMA0G
# CSqGSIb3DQEBAQUABIICABOdMeZpQpb6qxNetXv9ewMBzZvHTdK39BRMt1VbYaFu
# afBXniyHM7wVkGilLg+TBc5TyE2yu6gmPBcG1t0EvMgL7vsu3zXIbGpnhir75Sis
# a5QlbVCFjTiQnGQ1Hde33sD21WXBHEp6dT7uUkqb6pcPSfuJtoSMVGc1fsu0ha1n
# 1Mw+EqFmMJqgBRNZv9eduOX6J4sKd8h6Ifmm/ql7lthqI9HHsE8Tuoa14RaRdgcf
# hWhPCVNQHW567WMu9F95DndqR/aFEUyiKWyIjKY5w2nTLodWteCvTMugwpjn8Coz
# A7npkupY2BZUZV/XVmWEbZmLv6gQmeDYwkPFy5rPhveE47fof5TmKcevLvM9gdna
# 9+opoj7bzaL6Cgcrwf8a1y9r2aPYPEfrW+qA4hyyDytbAO8UGCZ/mgW7wOxGQ59c
# 5ZJELI574OVFXYLBPvDyoWX1FyLUJ7Ptsk9q83yYwqShIRlPwaATSoF2SIphsD1M
# 2YOU6EjeIg7Da+mqtnN4gs9JepVa2i2xIJPsGykEZVRNcoEA1Ee+j080cAkE+tMk
# g+pXfEFJDpJCK6e8nDGJhS8bwAOJ3YSj4kVI0saaS9kKkqTJxla4h4gaHQKvPMLU
# AwttDiMTqSxH3I0jYwXP/P4wsFma1UHmED2vZIFpMXmV+ozwA7uxxsDz9SIKc5on
# oYIY1zCCGNMGCisGAQQBgjcDAwExghjDMIIYvwYJKoZIhvcNAQcCoIIYsDCCGKwC
# AQMxDzANBglghkgBZQMEAgIFADCB9wYLKoZIhvcNAQkQAQSggecEgeQwgeECAQEG
# CisGAQQBsjECAQEwMTANBglghkgBZQMEAgEFAAQgokDNVlg3ziKwaehceiecVKtQ
# qoGrPaZdWHIhNsSJt9gCFAIEwTqxEuWM/2Uvdm6uMQzaQkIFGA8yMDI1MDcwMTAw
# MTQzMFqgdqR0MHIxCzAJBgNVBAYTAkdCMRcwFQYDVQQIEw5XZXN0IFlvcmtzaGly
# ZTEYMBYGA1UEChMPU2VjdGlnbyBMaW1pdGVkMTAwLgYDVQQDEydTZWN0aWdvIFB1
# YmxpYyBUaW1lIFN0YW1waW5nIFNpZ25lciBSMzagghMEMIIGYjCCBMqgAwIBAgIR
# AKQpO24e3denNAiHrXpOtyQwDQYJKoZIhvcNAQEMBQAwVTELMAkGA1UEBhMCR0Ix
# GDAWBgNVBAoTD1NlY3RpZ28gTGltaXRlZDEsMCoGA1UEAxMjU2VjdGlnbyBQdWJs
# aWMgVGltZSBTdGFtcGluZyBDQSBSMzYwHhcNMjUwMzI3MDAwMDAwWhcNMzYwMzIx
# MjM1OTU5WjByMQswCQYDVQQGEwJHQjEXMBUGA1UECBMOV2VzdCBZb3Jrc2hpcmUx
# GDAWBgNVBAoTD1NlY3RpZ28gTGltaXRlZDEwMC4GA1UEAxMnU2VjdGlnbyBQdWJs
# aWMgVGltZSBTdGFtcGluZyBTaWduZXIgUjM2MIICIjANBgkqhkiG9w0BAQEFAAOC
# Ag8AMIICCgKCAgEA04SV9G6kU3jyPRBLeBIHPNyUgVNnYayfsGOyYEXrn3+SkDYT
# Ls1crcw/ol2swE1TzB2aR/5JIjKNf75QBha2Ddj+4NEPKDxHEd4dEn7RTWMcTIfm
# 492TW22I8LfH+A7Ehz0/safc6BbsNBzjHTt7FngNfhfJoYOrkugSaT8F0IzUh6VU
# woHdYDpiln9dh0n0m545d5A5tJD92iFAIbKHQWGbCQNYplqpAFasHBn77OqW37P9
# BhOASdmjp3IijYiFdcA0WQIe60vzvrk0HG+iVcwVZjz+t5OcXGTcxqOAzk1frDNZ
# 1aw8nFhGEvG0ktJQknnJZE3D40GofV7O8WzgaAnZmoUn4PCpvH36vD4XaAF2CjiP
# sJWiY/j2xLsJuqx3JtuI4akH0MmGzlBUylhXvdNVXcjAuIEcEQKtOBR9lU4wXQpI
# SrbOT8ux+96GzBq8TdbhoFcmYaOBZKlwPP7pOp5Mzx/UMhyBA93PQhiCdPfIVOCI
# NsUY4U23p4KJ3F1HqP3H6Slw3lHACnLilGETXRg5X/Fp8G8qlG5Y+M49ZEGUp2bn
# eRLZoyHTyynHvFISpefhBCV0KdRZHPcuSL5OAGWnBjAlRtHvsMBrI3AAA0Tu1oGv
# Pa/4yeeiAyu+9y3SLC98gDVbySnXnkujjhIh+oaatsk/oyf5R2vcxHahajMCAwEA
# AaOCAY4wggGKMB8GA1UdIwQYMBaAFF9Y7UwxeqJhQo1SgLqzYZcZojKbMB0GA1Ud
# DgQWBBSIYYyhKjdkgShgoZsx0Iz9LALOTzAOBgNVHQ8BAf8EBAMCBsAwDAYDVR0T
# AQH/BAIwADAWBgNVHSUBAf8EDDAKBggrBgEFBQcDCDBKBgNVHSAEQzBBMDUGDCsG
# AQQBsjEBAgEDCDAlMCMGCCsGAQUFBwIBFhdodHRwczovL3NlY3RpZ28uY29tL0NQ
# UzAIBgZngQwBBAIwSgYDVR0fBEMwQTA/oD2gO4Y5aHR0cDovL2NybC5zZWN0aWdv
# LmNvbS9TZWN0aWdvUHVibGljVGltZVN0YW1waW5nQ0FSMzYuY3JsMHoGCCsGAQUF
# BwEBBG4wbDBFBggrBgEFBQcwAoY5aHR0cDovL2NydC5zZWN0aWdvLmNvbS9TZWN0
# aWdvUHVibGljVGltZVN0YW1waW5nQ0FSMzYuY3J0MCMGCCsGAQUFBzABhhdodHRw
# Oi8vb2NzcC5zZWN0aWdvLmNvbTANBgkqhkiG9w0BAQwFAAOCAYEAAoE+pIZyUSH5
# ZakuPVKK4eWbzEsTRJOEjbIu6r7vmzXXLpJx4FyGmcqnFZoa1dzx3JrUCrdG5b//
# LfAxOGy9Ph9JtrYChJaVHrusDh9NgYwiGDOhyyJ2zRy3+kdqhwtUlLCdNjFjakTS
# E+hkC9F5ty1uxOoQ2ZkfI5WM4WXA3ZHcNHB4V42zi7Jk3ktEnkSdViVxM6rduXW0
# jmmiu71ZpBFZDh7Kdens+PQXPgMqvzodgQJEkxaION5XRCoBxAwWwiMm2thPDuZT
# zWp/gUFzi7izCmEt4pE3Kf0MOt3ccgwn4Kl2FIcQaV55nkjv1gODcHcD9+ZVjYZo
# yKTVWb4VqMQy/j8Q3aaYd/jOQ66Fhk3NWbg2tYl5jhQCuIsE55Vg4N0DUbEWvXJx
# txQQaVR5xzhEI+BjJKzh3TQ026JxHhr2fuJ0mV68AluFr9qshgwS5SpN5FFtaSEn
# AwqZv3IS+mlG50rK7W3qXbWwi4hmpylUfygtYLEdLQukNEX1jiOKMIIGFDCCA/yg
# AwIBAgIQeiOu2lNplg+RyD5c9MfjPzANBgkqhkiG9w0BAQwFADBXMQswCQYDVQQG
# EwJHQjEYMBYGA1UEChMPU2VjdGlnbyBMaW1pdGVkMS4wLAYDVQQDEyVTZWN0aWdv
# IFB1YmxpYyBUaW1lIFN0YW1waW5nIFJvb3QgUjQ2MB4XDTIxMDMyMjAwMDAwMFoX
# DTM2MDMyMTIzNTk1OVowVTELMAkGA1UEBhMCR0IxGDAWBgNVBAoTD1NlY3RpZ28g
# TGltaXRlZDEsMCoGA1UEAxMjU2VjdGlnbyBQdWJsaWMgVGltZSBTdGFtcGluZyBD
# QSBSMzYwggGiMA0GCSqGSIb3DQEBAQUAA4IBjwAwggGKAoIBgQDNmNhDQatugivs
# 9jN+JjTkiYzT7yISgFQ+7yavjA6Bg+OiIjPm/N/t3nC7wYUrUlY3mFyI32t2o6Ft
# 3EtxJXCc5MmZQZ8AxCbh5c6WzeJDB9qkQVa46xiYEpc81KnBkAWgsaXnLURoYZzk
# sHIzzCNxtIXnb9njZholGw9djnjkTdAA83abEOHQ4ujOGIaBhPXG2NdV8TNgFWZ9
# BojlAvflxNMCOwkCnzlH4oCw5+4v1nssWeN1y4+RlaOywwRMUi54fr2vFsU5QPrg
# b6tSjvEUh1EC4M29YGy/SIYM8ZpHadmVjbi3Pl8hJiTWw9jiCKv31pcAaeijS9fc
# 6R7DgyyLIGflmdQMwrNRxCulVq8ZpysiSYNi79tw5RHWZUEhnRfs/hsp/fwkXsyn
# u1jcsUX+HuG8FLa2BNheUPtOcgw+vHJcJ8HnJCrcUWhdFczf8O+pDiyGhVYX+bDD
# P3GhGS7TmKmGnbZ9N+MpEhWmbiAVPbgkqykSkzyYVr15OApZYK8CAwEAAaOCAVww
# ggFYMB8GA1UdIwQYMBaAFPZ3at0//QET/xahbIICL9AKPRQlMB0GA1UdDgQWBBRf
# WO1MMXqiYUKNUoC6s2GXGaIymzAOBgNVHQ8BAf8EBAMCAYYwEgYDVR0TAQH/BAgw
# BgEB/wIBADATBgNVHSUEDDAKBggrBgEFBQcDCDARBgNVHSAECjAIMAYGBFUdIAAw
# TAYDVR0fBEUwQzBBoD+gPYY7aHR0cDovL2NybC5zZWN0aWdvLmNvbS9TZWN0aWdv
# UHVibGljVGltZVN0YW1waW5nUm9vdFI0Ni5jcmwwfAYIKwYBBQUHAQEEcDBuMEcG
# CCsGAQUFBzAChjtodHRwOi8vY3J0LnNlY3RpZ28uY29tL1NlY3RpZ29QdWJsaWNU
# aW1lU3RhbXBpbmdSb290UjQ2LnA3YzAjBggrBgEFBQcwAYYXaHR0cDovL29jc3Au
# c2VjdGlnby5jb20wDQYJKoZIhvcNAQEMBQADggIBABLXeyCtDjVYDJ6BHSVY/Uwt
# Z3Svx2ImIfZVVGnGoUaGdltoX4hDskBMZx5NY5L6SCcwDMZhHOmbyMhyOVJDwm1y
# rKYqGDHWzpwVkFJ+996jKKAXyIIaUf5JVKjccev3w16mNIUlNTkpJEor7edVJZiR
# JVCAmWAaHcw9zP0hY3gj+fWp8MbOocI9Zn78xvm9XKGBp6rEs9sEiq/pwzvg2/Kj
# XE2yWUQIkms6+yslCRqNXPjEnBnxuUB1fm6bPAV+Tsr/Qrd+mOCJemo06ldon4pJ
# FbQd0TQVIMLv5koklInHvyaf6vATJP4DfPtKzSBPkKlOtyaFTAjD2Nu+di5hErEV
# VaMqSVbfPzd6kNXOhYm23EWm6N2s2ZHCHVhlUgHaC4ACMRCgXjYfQEDtYEK54dUw
# PJXV7icz0rgCzs9VI29DwsjVZFpO4ZIVR33LwXyPDbYFkLqYmgHjR3tKVkhh9qKV
# 2WCmBuC27pIOx6TYvyqiYbntinmpOqh/QPAnhDgexKG9GX/n1PggkGi9HCapZp8f
# Rwg8RftwS21Ln61euBG0yONM6noD2XQPrFwpm3GcuqJMf0o8LLrFkSLRQNwxPDDk
# WXhW+gZswbaiie5fd/W2ygcto78XCSPfFWveUOSZ5SqK95tBO8aTHmEa4lpJVD7H
# rTEn9jb1EGvxOb1cnn0CMIIGgjCCBGqgAwIBAgIQNsKwvXwbOuejs902y8l1aDAN
# BgkqhkiG9w0BAQwFADCBiDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCk5ldyBKZXJz
# ZXkxFDASBgNVBAcTC0plcnNleSBDaXR5MR4wHAYDVQQKExVUaGUgVVNFUlRSVVNU
# IE5ldHdvcmsxLjAsBgNVBAMTJVVTRVJUcnVzdCBSU0EgQ2VydGlmaWNhdGlvbiBB
# dXRob3JpdHkwHhcNMjEwMzIyMDAwMDAwWhcNMzgwMTE4MjM1OTU5WjBXMQswCQYD
# VQQGEwJHQjEYMBYGA1UEChMPU2VjdGlnbyBMaW1pdGVkMS4wLAYDVQQDEyVTZWN0
# aWdvIFB1YmxpYyBUaW1lIFN0YW1waW5nIFJvb3QgUjQ2MIICIjANBgkqhkiG9w0B
# AQEFAAOCAg8AMIICCgKCAgEAiJ3YuUVnnR3d6LkmgZpUVMB8SQWbzFoVD9mUEES0
# QUCBdxSZqdTkdizICFNeINCSJS+lV1ipnW5ihkQyC0cRLWXUJzodqpnMRs46npiJ
# PHrfLBOifjfhpdXJ2aHHsPHggGsCi7uE0awqKggE/LkYw3sqaBia67h/3awoqNvG
# qiFRJ+OTWYmUCO2GAXsePHi+/JUNAax3kpqstbl3vcTdOGhtKShvZIvjwulRH87r
# bukNyHGWX5tNK/WABKf+Gnoi4cmisS7oSimgHUI0Wn/4elNd40BFdSZ1EwpuddZ+
# Wr7+Dfo0lcHflm/FDDrOJ3rWqauUP8hsokDoI7D/yUVI9DAE/WK3Jl3C4LKwIpn1
# mNzMyptRwsXKrop06m7NUNHdlTDEMovXAIDGAvYynPt5lutv8lZeI5w3MOlCybAZ
# DpK3Dy1MKo+6aEtE9vtiTMzz/o2dYfdP0KWZwZIXbYsTIlg1YIetCpi5s14qiXOp
# RsKqFKqav9R1R5vj3NgevsAsvxsAnI8Oa5s2oy25qhsoBIGo/zi6GpxFj+mOdh35
# Xn91y72J4RGOJEoqzEIbW3q0b2iPuWLA911cRxgY5SJYubvjay3nSMbBPPFsyl6m
# Y4/WYucmyS9lo3l7jk27MAe145GWxK4O3m3gEFEIkv7kRmefDR7Oe2T1HxAnICQv
# r9sCAwEAAaOCARYwggESMB8GA1UdIwQYMBaAFFN5v1qqK0rPVIDh2JvAnfKyA2bL
# MB0GA1UdDgQWBBT2d2rdP/0BE/8WoWyCAi/QCj0UJTAOBgNVHQ8BAf8EBAMCAYYw
# DwYDVR0TAQH/BAUwAwEB/zATBgNVHSUEDDAKBggrBgEFBQcDCDARBgNVHSAECjAI
# MAYGBFUdIAAwUAYDVR0fBEkwRzBFoEOgQYY/aHR0cDovL2NybC51c2VydHJ1c3Qu
# Y29tL1VTRVJUcnVzdFJTQUNlcnRpZmljYXRpb25BdXRob3JpdHkuY3JsMDUGCCsG
# AQUFBwEBBCkwJzAlBggrBgEFBQcwAYYZaHR0cDovL29jc3AudXNlcnRydXN0LmNv
# bTANBgkqhkiG9w0BAQwFAAOCAgEADr5lQe1oRLjlocXUEYfktzsljOt+2sgXke3Y
# 8UPEooU5y39rAARaAdAxUeiX1ktLJ3+lgxtoLQhn5cFb3GF2SSZRX8ptQ6IvuD3w
# z/LNHKpQ5nX8hjsDLRhsyeIiJsms9yAWnvdYOdEMq1W61KE9JlBkB20XBee6JaXx
# 4UBErc+YuoSb1SxVf7nkNtUjPfcxuFtrQdRMRi/fInV/AobE8Gw/8yBMQKKaHt5e
# ia8ybT8Y/Ffa6HAJyz9gvEOcF1VWXG8OMeM7Vy7Bs6mSIkYeYtddU1ux1dQLbEGu
# r18ut97wgGwDiGinCwKPyFO7ApcmVJOtlw9FVJxw/mL1TbyBns4zOgkaXFnnfzg4
# qbSvnrwyj1NiurMp4pmAWjR+Pb/SIduPnmFzbSN/G8reZCL4fvGlvPFk4Uab/JVC
# Smj59+/mB2Gn6G/UYOy8k60mKcmaAZsEVkhOFuoj4we8CYyaR9vd9PGZKSinaZIk
# vVjbH/3nlLb0a7SBIkiRzfPfS9T+JesylbHa1LtRV9U/7m0q7Ma2CQ/t392ioOss
# XW7oKLdOmMBl14suVFBmbzrt5V5cQPnwtd3UOTpS9oCG+ZZheiIvPgkDmA8FzPsn
# fXW5qHELB43ET7HHFHeRPRYrMBKjkb8/IN7Po0d0hQoF4TeMM+zYAJzoKQnVKOLg
# 8pZVPT8xggSSMIIEjgIBATBqMFUxCzAJBgNVBAYTAkdCMRgwFgYDVQQKEw9TZWN0
# aWdvIExpbWl0ZWQxLDAqBgNVBAMTI1NlY3RpZ28gUHVibGljIFRpbWUgU3RhbXBp
# bmcgQ0EgUjM2AhEApCk7bh7d16c0CIetek63JDANBglghkgBZQMEAgIFAKCCAfkw
# GgYJKoZIhvcNAQkDMQ0GCyqGSIb3DQEJEAEEMBwGCSqGSIb3DQEJBTEPFw0yNTA3
# MDEwMDE0MzBaMD8GCSqGSIb3DQEJBDEyBDDj1eD+DucK561Di2leGBR4pG6WSYaZ
# 5eAvR6hzufoAvV9Xw7KO2AYIMSTnmKvdUSUwggF6BgsqhkiG9w0BCRACDDGCAWkw
# ggFlMIIBYTAWBBQ4yRSBEES03GY+k9R0S4FBhqm1sTCBhwQUxq5U5HiG8Xw9VRJI
# jGnDSnr5wt0wbzBbpFkwVzELMAkGA1UEBhMCR0IxGDAWBgNVBAoTD1NlY3RpZ28g
# TGltaXRlZDEuMCwGA1UEAxMlU2VjdGlnbyBQdWJsaWMgVGltZSBTdGFtcGluZyBS
# b290IFI0NgIQeiOu2lNplg+RyD5c9MfjPzCBvAQUhT1jLZOCgmF80JA1xJHeksFC
# 2scwgaMwgY6kgYswgYgxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpOZXcgSmVyc2V5
# MRQwEgYDVQQHEwtKZXJzZXkgQ2l0eTEeMBwGA1UEChMVVGhlIFVTRVJUUlVTVCBO
# ZXR3b3JrMS4wLAYDVQQDEyVVU0VSVHJ1c3QgUlNBIENlcnRpZmljYXRpb24gQXV0
# aG9yaXR5AhA2wrC9fBs656Oz3TbLyXVoMA0GCSqGSIb3DQEBAQUABIICAKaMwX73
# uGeygb1paYkpTxnLnob2lDjIZz3XhQj954I+viWA/2Sa1viF7wg/1+FJQKmRbYap
# McQRfrhYUYAWTuBE6JMa+yijOdB304dsG8Tb8PQxyTsSTLL5fdHWSVZKtAokUpmd
# aoQQolx7rIBpkBx8RdVC8BzQDxmTMcq3uK6mCOybFmMX5DsACS4HljrgIIVB90hR
# ncHMPQAxZ52/4ms+rbPAVv5pWsFPxFwVlV6+Pz5udg3OJrqN/XS9RRmSkSMqQ/WG
# MHNShCz88lPYc/JP2OqwZbys5WUfizzUo+5X6FWOH2w7s3QS+iTmIKE+eQfEM5PF
# aF2v61g21SxdJUpT+ukBePkk6UxmQEj+huZbCUcQl0fYzWEGmfI5reh/PoIq5PUH
# m/QrIKIDQAYNi0XHGareedLEs3kAFOV0BVHpLfR94k4z1C29YrKkUF9/OiDZNp/v
# Mhfd8bjRltrv6bBYHRJZ2wvOooKlEVLXP5abALh4aX9Ot6p6exs336+Cxgc2ngQ9
# I1eg3omv0w5ALwB3M4YRhTBKWjcBZIt264O6OpAjVX9nvYtH2GNQE7ZArr05p1WV
# FYP6RRiKOXRO6BjRgrGhEe3LI8WHHLio8OTTeRIhaUlJyDVK/ArJGUWRtnrVin9M
# Ev//bJEVKC9WT4pFLp1YrLjvyGtWsb9cn8md
# SIG # End signature block

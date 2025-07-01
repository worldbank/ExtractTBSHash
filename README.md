# ExtractTBSHash
   Patch for Microsoft's design deficiency of not logging PublisherTBSHash if ACFB policy is enfoiced.

## DESCRIPTION
   ExtractTBSHash is a tool that fixes a design deficiency of an Application Control for Business (former WDAC)
   security control by Microsoft. When ACfB policy is enforced, it does not log neither of the following file
   attributes necessary for the scalable ACfB policy rule creation:
   PublisherNAme, IssuerName, PublisherTBSHash, SHA1 and SHA256 hashes.
   This tool extracts at least PublisherTBSHash and IssuerName from the blocked file that allows a publisher rule creation.

## USAGE SUMMARY:
   Script is intended to be executed from a scheduled task triggered by ACfB blocked file event ID, usually 3033.
   The installer takes care of a creation of the scheduled task and event log source for its own output.

## NOTES
   - Requires  : PowerShell V5 on Windows 11 24H2 (Constrained Language Mode is fine) - it fails on older OS with PS v4.0
   - Version   : see $patchVer
   - Contacts  : sazari@worldbankgroup.org

   Slow (Full) Mode:
      For longer API call because of the known bug in New-CIPolicyRule the cmdlet needs to be called
      twice accroding to Microsoft. If you are want to enable that mode - please include some known
      harmless signed exe in your installation folder. The example uses putty.exe, but it can be any
      just chnage the name accordingly

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

## PARAMETER fastMode
If set to $true (default), the script will run in fast mode, which means it will only extract the PublisherTBSHash
and issuer from blocked file using Add-SignerRule ACfB cmdlet.

If set to $false, the script will run in slow mode, which means it will extract both PublisherTBSHash and file hashes
(SHA1 and SHA256) from the blocked file using New-CIPolicyRule cmdlet. This is very slow cmdlet, it scans global catalog
and might take about 25 min to run wuth high CPU utilization.

## PARAMETER EventID
Tells the script which Event ID to look for in the Application log. Default is 3033, but could also be 3077.
This parameter should match the tiriggered event ID from Task Scheduler.

## PARAMETER VerifySelf
If present, the script will verify its own digital signature against the expected WBG-issued certificate.
This is useful to ensure that the script has not been tampered with and is running the official version.

## OUTPUTS
All log files are stored in '.\Log' folder (= "$LogFolder").
In both fast and slow modes, the script will create a event log entry in the Application log
with Event ID 33067 for fast mode and 33089 for slow mode. 

## EXAMPLE
.\ExtractTBSHash.ps1
Start ExtractTBSHash.ps1 in fast mode, read last event log entry with ID=3033 and extract Publisher information
from associated file blocked by ACfB

## EXAMPLE
.\ExtractTBSHash.ps1 -EventID 3077
Start ExtractTBSHash.ps1 in fast mode, read last event log entry with ID=3077 and extract Publisher information
from associated file blocked by ACfB

## EXAMPLE
.\ExtractTBSHash.ps1 -fastMode $false -EventID 3033
Start ExtractTBSHash.ps1 in slow mode, read last event log entry with ID=3033 and extract Publisher information
from associated file blocked by ACfB

## EXAMPLE
C:\Windows\System32\conhost.exe --headless powershell.exe -WindowStyle Hidden -NoProfile -ExecutionPolicy Bypass
      -File "C:\Program Files\The World Bank Group\Extract ACfB Signer Info\ExtractTBSHash.ps1" -fastMode $true -EventID 3033
Example of launching the script from a scheduled task with hidden window and bypassing execution policy on Windows 11
using conhost.exe.

This repo is still under construction, not all cotnent yet available.

# ExtractTBSHash.ps1
   Patch for Microsoft's design deficiency of not logging PublisherTBSHash if ACFB policy is enfoiced.

## Description
   ExtractTBSHash is a tool that fixes a design deficiency of an Application Control for Business (former WDAC)
   security control by Microsoft. When ACfB policy is enforced, it does not log neither of the following file
   attributes necessary for a scalable ACfB policy rule creation:
   - PublisherName, 
   - IssuerName, 
   - PublisherTBSHash, 
   - SHA1 and SHA256 hashes.
   
   This tool extracts at least PublisherTBSHash and IssuerName from blocked file and logs into the event log that allows an automated publisher rule creation.
   A support case is open with Microsoft to submit a Design Change Request (DCR) for a permanent fix. No ETA.
   The intended audience of this tool are ACfB deployments in a dynamic environment where whitelisting operations continue even after ACfB is switched to an enforced mode.

## Usage Summary
   Script is intended to be executed from a scheduled task triggered by ACfB blocked file event ID, usually 3033.
   The supplied MSI installer takes care of creation of a scheduled task and of an event log source for its own output.
   Please download the latest version of installer from Release section and make sure it is signed by World Bank digital certificate. 

### Contributions
We are happy to receive feedback and/or contributions. Please feel free to report bugs or request new features by opening up a 
[new issue](https://github.com/worldbank/ExtractTBSHash/issues).

You are also welcome to fork this repo and submit a
[pull request](https://github.com/worldbank/ExtractTBSHash/pulls)
with contribution to the code.

### Authors
This package is written and published by Office of Information Security (OIS) part of World Bank Group's Information and Technology Solutions Vice Presidency (ITS).

Contact:
- sazari@worldbankgroup.org

### Release Notes
   - Requires  : PowerShell V5 on Windows 11 24H2 (Constrained Language Mode is fine) - it fails on older OS with PS v4.0
   - Distribution includes CreateSignerPolicy.ps1 script from Microsoft's ACfB Policy Design Wizard (Open Source). For this distributiion it has been digitally signed.
   - Version   : see $patchVer

### LICENSE : MIT License
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

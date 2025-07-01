# ExtractTBSHash
   Patch for Microsoft's design deficiency of not logging PublisherTBSHash if ACFB policy is enfoiced.

## Description
   ExtractTBSHash is a tool that fixes a design deficiency of an Application Control for Business (former WDAC)
   security control by Microsoft. When ACfB policy is enforced, it does not log neither of the following file
   attributes necessary for a scalable ACfB policy rule creation:
   PublisherName, IssuerName, PublisherTBSHash, SHA1 and SHA256 hashes.
   This tool extracts at least PublisherTBSHash and IssuerName from the blocked file and logs into the event log that allows an automated publisher rule creation.

## Usage Summary:
   Script is intended to be executed from a scheduled task triggered by ACfB blocked file event ID, usually 3033.
   The supplied MSI installer takes care of a creation of the scheduled task and event log source for its own output.
   Please download lates version of installer from Release section and make sure it is signed by World Bank digital certificate. 

### Notes
   - Requires  : PowerShell V5 on Windows 11 24H2 (Constrained Language Mode is fine) - it fails on older OS with PS v4.0
   - Version   : see $patchVer
   - Contacts  : sazari@worldbankgroup.org

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

## Active Directory xRay Script

_This fork is maintained by [Omer Elsayed](https://github.com/omerbelsayed), based on the original project by Claudio Merola and Raphaela Pereira. Distributed under the original project's GPL-3.0 license._

The script does not record, create or modify anything in the environment (except for creating a folder named “ADxRay” in C:\ of the computer running the script. Inside that folder the log files and the main report file named “ADxRay_Report(YEAR-MONTH-DAY).htm” is created). 

The script must be run at a Domain Controller running at least Windows Server 2012 (see requirements below). 

The script must be run by a user with Domain Admin privileges (Enterprise Admins if dealing with multiple domains and forests).

#### This script may take several hours to complete!

<BR/>

### What's new in this fork:

This fork adds seven Active Directory security checks on top of the original health-check inventory, reported inside the existing "Domain Controller's Security" tab and the "User Accounts" table:

 - **LDAP Server Signing** and **LDAP Channel Binding** status per Domain Controller
 - **Kerberoastable accounts** (enabled users with an SPN), including how many have a password older than a year
 - **RC4 Kerberos encryption exposure** among Kerberoastable accounts (`msDS-SupportedEncryptionTypes`)
 - **AS-REP Roastable accounts** (Kerberos pre-authentication disabled)
 - **Unconstrained Kerberos delegation** on both user/service accounts and computer accounts
 - **KRBTGT password age**, flagged past Microsoft's recommended 180-day rotation
 - **AdminSDHolder orphaned accounts** and **Protected Users group adoption**

All checks are read-only (registry reads and `Get-ADUser`/`Get-ADComputer` LDAP filters only - no `Set-` commands), reuse the script's existing parallel-job collection pattern, and don't change any existing check, section, or menu option.

Want to see it without a live AD environment first? See [Sample report / demo data](#sample-report--demo-data) below.

<BR/>

### How to run:

Just copy or download `ADxRay.ps1` and run it on any computer that meets the requirements below (typically a Domain Controller, run elevated):

```powershell
.\ADxRay.ps1
```

The script will prompt you to pick one of six options:

 1. **Full Inventory** - collects everything (Forest, Domains, Domain Controllers) and generates the report in one run. This is the default and what most people want.
 2. **Soft Inventory** - same as Full Inventory but intended for repeat/lighter runs.
 3. **Forest Inventory** - collects and reports only forest-level data (fastest option).
 4. **Domain Inventory** - collects and reports forest + domain-level data, skipping per-DC collection.
 5. **Only Collect Inventory Files** - runs the collection ("Hammer") phase and saves the raw XML inventory into `C:\ADxRay\Hammer` plus a `C:\ADxRay\ADxRay.zip`, without generating a report. Useful if you want to collect data on one machine and generate the report elsewhere.
 6. **Process Collected Inventory Files** - skips collection entirely and generates the HTML report from XML files already present in `C:\ADxRay\Hammer` (either from a prior option-5 run, or from the demo data generator below).

The report is written to `C:\ADxRay\ADxRay_Report_<timestamp>.htm` and opens automatically when done. A run log is kept at `C:\ADxRay\ADxRay.log`.

<BR/>

### Sample report / demo data:

You don't need a live Active Directory environment to see what the report looks like. [`samples/Generate-DemoData.ps1`](samples/Generate-DemoData.ps1) fabricates a realistic two-domain forest (a mix of clean and misconfigured findings, including the new Kerberos/LDAP security checks) as the same `C:\ADxRay\Hammer\*.xml` files the real collection phase produces:

```powershell
.\samples\Generate-DemoData.ps1
.\ADxRay.ps1        # choose option 6 (Process Collected Inventory Files)
```

A pre-generated example is included at [`samples/ADxRay_Sample_Report.htm`](samples/ADxRay_Sample_Report.htm) - download it and open it in a browser to see the report without running anything.

Note: three sections (GPO Objects overview, Domain Controllers Security Group Policies, and User Rights Assignments) parse raw `Get-GPOReport`/RSoP XML from a live environment and are not populated by the demo generator; every other section, including all seven new security checks, renders with realistic data.

<BR/>

### SOC / SIEM / XDR integration:

Every run automatically exports the seven security checks above as standardized findings to `C:\ADxRay\ADxRay_Findings_<timestamp>.json` and `.csv` (schema: `Id`, `Category`, `SubCategory`, `Title`, `Severity`, `Status`, `Scope`, `AffectedCount`, `Description`, `Recommendation`, `Timestamp`). This is a local file only - no network activity - and any SIEM's file/log collector can ingest it directly. See [`samples/ADxRay_Sample_Findings.json`](samples/ADxRay_Sample_Findings.json) / [`.csv`](samples/ADxRay_Sample_Findings.csv) for an example generated from the demo data above.

Two additional delivery mechanisms are available, both **opt-in** (off by default, so existing behavior is unchanged unless you ask for them):

```powershell
# Write Fail-status findings to the local Windows Application Event Log (Source: ADxRay, Event IDs 6001-6009).
# Requires local Administrator rights to register the event source on first run.
# Picked up automatically by whatever SIEM/XDR agent already collects Windows Event Logs on the DC
# (Sentinel AMA, Splunk Universal Forwarder, QRadar WinCollect, Defender, CrowdStrike, etc.) - no vendor-specific code needed.
.\ADxRay.ps1 -WriteSecurityEventLog

# Push Fail-status findings as a JSON payload to any HTTP(S) endpoint (a generic webhook receiver,
# Splunk HEC, a Sentinel Logic App HTTP trigger, etc.). This is the only network call the script makes,
# and only runs if -WebhookUrl is explicitly provided.
.\ADxRay.ps1 -WebhookUrl "https://your-siem.example.com/ingest" -WebhookToken "your-bearer-token"
```

Both flags can be combined with any of the six menu options above. Failures in either mechanism (e.g. missing Administrator rights, an unreachable webhook) are logged to `ADxRay.log` and do not interrupt report generation.

<BR/>

### Requirements:

The script must be run with the following requirements:

 - Must be run on Domain Controller (due to the tools used during the inventory)
 - Must be run with rights to read objects in the entire forest and run AD Tools (dcdiag, SETSPN, dsquery, GET-AD*)
 - Must be run with elavated Powershell (Run as Administrator) - This is necessary to create the folders to keep the files generated
 - Internet connection is not required*
 
Internet connection might be use by the script for version validation, but is not a requirement. 

<BR/>

### What the script does:

This script will create the folder C:\ADxRay and run a deep inventory of your entire Active Directory environment, indicating what’s bad and what’s good. All the tests and validations are explained and contains external links to official Microsoft documentation and/or well know blog post from MVPs.

<BR/>

The Inventory phase of the script may take a long time to run depending on the size of the environment.

<BR/>

Even the script may overload the server used to run, it is not harmful to the environment. The users will not be affected and no modifications will be made in the environment (there is not a single “set-” powershell command and the only “new-“ were regarding the creation of the html report file and the xml inventory files)

<BR/>

## Screenshots:

<BR/>

![alt text](https://raw.githubusercontent.com/ClaudioMerola/ADxRay/main/Docs/0.png)

<BR/>

### User and Computer Account's health:

<BR/>

![alt text](https://raw.githubusercontent.com/ClaudioMerola/ADxRay/main/Docs/1.png)

<BR/>

### Group Policy Validations:

<BR/>

![alt text](https://raw.githubusercontent.com/ClaudioMerola/ADxRay/main/Docs/2.png)

<BR/>

### Domain Controller's Health:

<BR/>

![alt text](https://raw.githubusercontent.com/ClaudioMerola/ADxRay/main/Docs/3.png)

<BR/>

### Domain Controller's NTP and DNS Configuration:

<BR/>

![alt text](https://raw.githubusercontent.com/ClaudioMerola/ADxRay/main/Docs/4.png)

<BR/>

### Domain Controller's Security Policy Status (against Microsoft's Best Practices):

<BR/>

![alt text](https://raw.githubusercontent.com/ClaudioMerola/ADxRay/main/Docs/5.png)

<BR/>

### Domain Controller's Hardware Inventory:

<BR/>

![alt text](https://raw.githubusercontent.com/ClaudioMerola/ADxRay/main/Docs/6.png)

<BR/>

### Domain Controller's Software Inventory:

<BR/>

![alt text](https://raw.githubusercontent.com/ClaudioMerola/ADxRay/main/Docs/7.png)

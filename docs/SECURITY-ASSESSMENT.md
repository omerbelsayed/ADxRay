# ADxRay Security, Operational & Compatibility Assessment (2026)

Scope: `ADxRay.ps1` as of this fork's `security-checks-2026` branch (original health-check inventory + the seven added Kerberos/identity checks + SOC/SIEM/XDR findings export). This document is a pre-deployment risk assessment, not a code walkthrough — see `README.md` for functionality and usage.

---

## Executive summary

| Field | Assessment |
|---|---|
| **Overall Risk** | **Medium** |
| **SIEM/XDR Detection Risk** | **Medium-High** (the tool's normal, benign behavior significantly overlaps with AD reconnaissance telemetry signatures) |
| **Required Privileges** | Domain Admin / Enterprise Admin (per current README) for full inventory; local Administrator on the execution host; **local Administrator on every Domain Controller** (implicit, via PowerShell Remoting); additionally local Administrator specifically to register the Windows Event Log source if `-WriteSecurityEventLog` is used |
| **External Network Communication** | One **always-on** outbound HTTPS GET (version check, no data sent); one **opt-in** outbound HTTPS POST (`-WebhookUrl`, only if explicitly configured) |
| **Sensitive Data Access** | **Significant** — see below |
| **System Changes** | None to Active Directory, GPO, DNS, or security configuration. Local-only changes: creates `C:\ADxRay\*`; optionally registers a Windows Event Log source (`-WriteSecurityEventLog`) |
| **Production Deployment Recommendation** | **Approved with Conditions** (see §8) |

**Bottom line:** the script is read-only against Active Directory and does not perform any destructive, persistence, privilege-escalation, or credential-theft action. However, several of its *legitimate* inventory queries produce telemetry that is difficult to distinguish from genuine attacker reconnaissance (SPN/Kerberoastable enumeration, unconstrained-delegation discovery, krbtgt queries, trust enumeration, PowerShell Remoting fan-out to every DC). It should not be run against production without the SOC being informed in advance and without addressing the conditions in §8.

---

## 1. What the script actually does (verified against the code)

- **Local AD queries** (via `Get-AD*` cmdlets, `dsquery`, `setspn`, `dcdiag`, `repadmin`): forest/domain/DC inventory, trust enumeration, GPO report extraction, SYSVOL file listing, user/computer/group enumeration, privileged-group membership counts, plus the seven new checks: LDAP signing/channel binding registry values, Kerberoastable accounts, RC4 encryption exposure, AS-REP roastable accounts, unconstrained delegation (users and computers), KRBTGT password age, AdminSDHolder orphans, Protected Users adoption.
- **Remote execution against every Domain Controller** via `Invoke-Command` (PowerShell Remoting/WinRM): hardware/software inventory, NTP status, SMBv1 feature check, and the new LDAP-signing registry read (`ADxRay.ps1:217-233`).
- **Local file writes only**: `C:\ADxRay\ADxRay.log`, `C:\ADxRay\ADxRay_Report_*.htm`, `C:\ADxRay\ADxRay_Findings_*.json`/`.csv`, `C:\ADxRay\Hammer\*.xml` (raw inventory), optionally `C:\ADxRay\ADxRay.zip` (option 5) and RSoP/GPO report XML. No `Set-`, `New-AD*`, `Remove-*`, or `Add-*` cmdlet against Active Directory anywhere in the script.
- **Outbound network**: one unconditional `Invoke-WebRequest` to `raw.githubusercontent.com` for version comparison (`ADxRay.ps1:4259`, pre-existing in the original project, not added by this fork); one opt-in `Invoke-RestMethod` POST to a user-supplied `-WebhookUrl` (`ADxRay.ps1:898`).
- **New in this fork**: optional `New-EventLog`/`Write-EventLog` against the local Windows Application log (`ADxRay.ps1:861,872`), gated behind `-WriteSecurityEventLog` and off by default.

---

## 2. SIEM/XDR detection risk, by activity

| Activity | Detection risk | Why |
|---|---|---|
| `Get-ADUser -LDAPFilter '(&...(servicePrincipalName=*)...)'` (Kerberoastable enumeration) | **High** | This is structurally the same reconnaissance query used by PowerView/BloodHound/Rubeus before a real Kerberoasting attack. Microsoft Defender for Identity and similar AD-aware sensors alert on LDAP search-filter *content*, not just cmdlet name — this filter is a recognizable signature. The script never requests a TGS ticket for these accounts (no actual Kerberoasting occurs), but the recon step alone can trigger "possible Kerberoasting reconnaissance" alerts. |
| `Get-ADComputer -LDAPFilter '(&(userAccountControl:...:=524288)...)'` (unconstrained delegation discovery) | **High** | This exact LDAP filter is the standard BloodHound/PowerView query for finding unconstrained-delegation targets — a well-known pre-attack recon step. |
| `Get-ADUser -Identity krbtgt -Properties PasswordLastSet` | **Medium-High** | Any direct query against the `krbtgt` object is unusual for normal admin activity and is a known pre-Golden-Ticket recon step. Some MDI/Sentinel rules alert on any access to this specific object regardless of what's requested. |
| `Get-ADUser -LDAPFilter '(&(adminCount=1)...)'` (AdminSDHolder orphans) | **Medium** | Privileged-account discovery via `adminCount=1` maps to ATT&CK T1087.002 (Account Discovery: Domain Account) and is a common recon pattern for finding privilege-escalation targets. |
| `setspn -X -F`, `Get-ADtrust -Filter *` | **Medium** | Forest-wide SPN and trust enumeration; normal for legitimate AD audits but also a standard early-recon step (T1482 Domain Trust Discovery). |
| `Invoke-Command` to every DC (WinRM fan-out) | **Medium-High** | Bulk, near-simultaneous PowerShell Remoting sessions from one host to every Domain Controller closely matches lateral-movement/lateral-tool-transfer telemetry (T1021.006). Defender for Endpoint and Sentinel both have analytics that specifically watch for this fan-out pattern. |
| `dcdiag /e /s:server`, `repadmin /showbackup`, remote `systeminfo`, remote `Get-HotFix`, remote `Get-CimInstance` | **Low-Medium** | Broad but well-known admin/diagnostic tooling; still contributes to a large-volume discovery footprint (T1082 System Information Discovery, T1069 Permission Groups Discovery) that UEBA-style analytics may flag if run from an account/host with no history of it. |
| `Get-GPOReport -All`, SYSVOL recursive enumeration | **Low-Medium** | Legitimate GPO audit activity, but also extracts full GPO XML (including any legacy Group Policy Preferences content) — see §3 for the data-sensitivity angle. |
| `New-EventLog`/`Write-EventLog` (opt-in) | **Low** | Registering a new Event Log source touches `HKLM\SYSTEM\CurrentControlSet\Services\EventLog\Application\ADxRay`. Not persistence, but some EDRs alert generically on new registry keys under the `Services` hive — expect a benign, explainable alert if this triggers. |
| `Invoke-RestMethod` webhook POST (opt-in) | **Low-Medium** | Only fires if explicitly configured; still represents an egress path for internal security-posture data (Kerberoastable account names, KRBTGT age, etc.) to an external URL — should be allow-listed at the firewall/proxy layer if used. |
| `Invoke-WebRequest` version check (always-on) | **Low** | Fixed, hardcoded destination (`raw.githubusercontent.com`), GET only, no data transmitted — but is unconditional egress to a public internet host that some environments will want to block or note in advance. |

### ATT&CK-style classification
- **Discovery (T1069, T1082, T1087, T1482, T1615-adjacent):** the overwhelming majority of the script's behavior. This is the tool's entire purpose (it's an assessment/discovery tool) — the risk is telemetry ambiguity, not malicious intent.
- **Credential Access:** **not performed.** The script never touches LSASS, never requests or handles Kerberos tickets, never reads NTDS.dit/SAM, never decrypts or exports password material. It identifies *accounts that would be vulnerable* to credential-access techniques (Kerberoasting, AS-REP Roasting) without performing those techniques.
- **Privilege Escalation:** not performed. No group membership, ACL, or delegation changes.
- **Persistence:** not performed. No scheduled tasks, services, Run keys, or WMI event subscriptions are created. The one artifact that could superficially resemble persistence is the optional Windows Event Log *source* registration, which is not an execution mechanism.
- **Lateral Movement:** not performed in the exploitative sense (no code execution is pushed to remote hosts, no remote process/service creation), but the WinRM fan-out to every DC generates telemetry indistinguishable from lateral movement without contextual allow-listing.
- **Defense Evasion:** not performed. No AMSI bypass, no log clearing, no Defender/EDR tampering, no obfuscation. `$ErrorActionPreference = "silentlycontinue"` is set globally, which affects the *script's own* error visibility to the operator (an operational quality concern, addressed in §6) but does not suppress Windows/EDR-level logging or telemetry.

---

## 3. Sensitive data access and handling

This is the most significant *operational* (as opposed to detection) concern:

- The tool's own output — `C:\ADxRay\Hammer\*.xml`, the HTML report, and the new `ADxRay_Findings_*.json`/`.csv` — is a consolidated inventory of exactly the information an attacker would want: which accounts are Kerberoastable, which have RC4 enabled, which computers have unconstrained delegation, KRBTGT password age, AdminSDHolder orphans, full user/computer/group listings, and complete GPO configuration (including any legacy Group Policy Preferences content that may still contain the well-known, crackable `cpassword` field on older, unremediated GPOs).
- None of this is transmitted anywhere by default. But it is written to disk **in plaintext-equivalent formats** (CliXML and HTML are both trivially readable) in a predictable location (`C:\ADxRay`), with no access-control hardening, encryption, or automatic cleanup built into the script.
- **Recommendation:** treat `C:\ADxRay` as a sensitive-data directory for the duration of and after each run — restrict NTFS permissions to the executing account/admins only, and establish a retention/cleanup policy (the script does not delete prior runs' output).

---

## 4. Privilege and execution requirements

- **Domain Admin / Enterprise Admin** membership — this is what the current README requires for a full run. This is disproportionate to a "read-only assessment" tool in the strict sense (most individual checks would work with far less), but is a pre-existing characteristic of the original project (needed for `dcdiag`, `repadmin`, and reading every object/attribute forest-wide), not something introduced by this fork's additions.
- **Local Administrator on the execution host** — required to create `C:\ADxRay` and, per the existing README, "necessary to create the folders."
- **Local Administrator on every Domain Controller** — implicit requirement for the `Invoke-Command`/WinRM remoting calls to succeed (hardware/software/NTP/SMB/LDAP-registry checks).
- **Local Administrator, specifically to register the Event Log source** — only relevant if `-WriteSecurityEventLog` is used; fails gracefully (logged, non-fatal) without it, as verified in testing.
- The combination means: whatever host and account run this tool, for the duration of the run, that host effectively holds Domain Admin-equivalent reach across the entire domain. **This is the single largest blast-radius factor** if the execution host were compromised mid-run — not something the script does maliciously, but a structural risk of what it requires to do a complete inventory.

---

## 5. A concrete finding worth fixing before production use

`-WebhookToken` is accepted as a plain `[string]` parameter and is not logged to `ADxRay.log` — but because it's passed as a command-line argument, it **will appear in plaintext** in any process-creation telemetry that captures command lines (Sysmon Event ID 1, Windows Security Event 4688 with command-line auditing enabled, or PowerShell Script Block/Module logging). If SOC/SIEM ingests process command lines (most do), this token will be visible there. **Recommendation before production use of the webhook feature:** change `-WebhookToken` to accept a `SecureString` or read it from a protected file/credential store instead of a plaintext CLI argument.

---

## 6. Compatibility notes

- The script declares `#requires -version 2` but uses PowerShell 5+-only constructs (`[PowerShell]::Create()` runspaces, `Get-CimInstance`) — the declared minimum version is stale and misleading; tested and confirmed working on PowerShell 7.5.8 in this session.
- Depends on the `ActiveDirectory` RSAT module (`Get-AD*` cmdlets, including the ones this fork added), the `GroupPolicy` module (`Get-GPOReport`, `Get-GPResultantSetOfPolicy`), and the `DnsServer` module (`Get-DnsServer`) — none of these are declared via `#Requires -Modules`, and `$ErrorActionPreference = "silentlycontinue"` means a missing module will silently produce an incomplete section rather than a clear "module not found" error to the operator.
- No changes were made in this fork to the script's target OS/PowerShell version support; it remains as documented in the original README (Domain Controller, Windows Server 2012+).

---

## 7. What the script does **not** do (explicitly verified)

- Does not disable, bypass, or modify Windows Defender, EDR/XDR agents, SIEM forwarders, or any logging/audit configuration.
- Does not clear or truncate any Windows Event Log (only ever *writes new entries*, opt-in, to a log it registers itself).
- Does not create, modify, or delete AD objects, GPOs, DNS records, certificates, or trust relationships.
- Does not reset passwords, modify group memberships, or alter any ACL (including AdminSDHolder's own ACL — it only reads the `adminCount` attribute on other objects).
- Does not contain any hardcoded credential, API key, or secret.
- Does not use obfuscation, encoded commands, or any AMSI/logging-evasion technique.

---

## 8. Recommended testing before production execution

1. **Code review** — this document, plus a line-level review of the `-LDAPFilter` queries listed in §2 and the `Invoke-Command` blocks against your organization's specific detection rules.
2. **SOC/detection-engineering notification in advance** — share the exact LDAP filters and the source host/account that will run the tool so analysts can correlate any resulting alerts, or temporarily tune/suppress the specific rules likely to fire (Kerberoastable enumeration, unconstrained delegation discovery, krbtgt access, WinRM fan-out) for the known execution window.
3. **Isolated / non-production AD domain first** — run against a lab or non-production domain that mirrors production topology (multi-DC, at least one site boundary) to confirm behavior and timing before touching production.
4. **Pilot execution against a single production DC or a Domain-Inventory-only run (option 4)** before a full-forest run, to bound the blast radius and telemetry volume of the first real execution.
5. **Change approval** — this should go through your standard change process given the Domain Admin requirement and the WinRM fan-out to every DC, even though no destructive action occurs.
6. **No backup/rollback plan is required for the AD environment itself** (nothing is modified), but do plan secure handling/retention (or deletion) of `C:\ADxRay`'s output after each run, per §3.
7. **Monitor during and after execution**, specifically:
   - Kerberoasting/AS-REP-roasting reconnaissance alerts (Defender for Identity, Sentinel AD analytics, or equivalent)
   - Unconstrained-delegation / BloodHound-signature LDAP query alerts
   - Any alert tied to krbtgt object access
   - WinRM/PowerShell Remoting session-fan-out or lateral-movement analytics
   - New Windows Event Log source registration (if `-WriteSecurityEventLog` used)
   - Any outbound connection to `raw.githubusercontent.com` (expected, benign) or to your configured `-WebhookUrl` (expected only if you enabled it)

---

## 9. Final conclusion

**Approved with Conditions.** The script performs no destructive, persistence, privilege-escalation, or actual credential-theft action, and its behavior is fully consistent with a legitimate read-only AD assessment tool. It is reasonable to run in a production environment **provided that**:

- SOC/detection engineering is notified in advance of the execution window, source host, and account (so genuine alerts aren't lost in noise and false positives aren't chased).
- The change goes through normal change-approval given the Domain Admin requirement.
- `C:\ADxRay`'s output is treated as sensitive and access-restricted/cleaned up after use (§3).
- If SOC/SIEM webhook alerting is used, `-WebhookToken` handling is upgraded from a plaintext CLI argument before production use (§5).
- A non-production or pilot run has been completed first (§8).

It is **not** recommended to run this for the first time, unannounced, directly against a full production forest.

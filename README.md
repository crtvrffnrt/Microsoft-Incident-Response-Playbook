# Microsoft Incident Response Playbook for SOC Analysts

A practical Microsoft-focused incident response and security alert triage checklist for SOC analysts, incident responders, threat hunters, and security professionals.
This guide is optimized for daily investigation work in Microsoft Defender XDR, Microsoft Sentinel, Entra ID, Defender for Endpoint, Defender for Office 365, Defender for Cloud Apps, Exchange Online, Intune, and Azure.
<p align="center">
  <img src="logo.png" alt="AGENTS.md logo" width="360">
</p>
This document is a consolidated Microsoft-focused incident response playbook for practical SOC alert triage, entity investigation, and evidence-driven containment decisions.
Use it by starting with the investigation flow, identifying the affected entities, and then following the relevant section and embedded KQL queries for the alert type.
Incident response playbooks are important during alert investigation because they make triage repeatable, reduce missed evidence, and help analysts make consistent decisions under time pressure.

## Quick Navigation

<div align="center">

<table>
  <tr>
    <th colspan="4" align="left">Start here</th>
  </tr>
  <tr>
    <td align="center"><a href="#investigation-flow"><strong>Investigation Flow</strong></a><br><sub>Overall IR process</sub></td>
    <td align="center"><a href="#fast-triage-checklist"><strong>Fast Triage</strong></a><br><sub>First checks</sub></td>
    <td align="center"><a href="#entity-investigation-map"><strong>Entity Map</strong></a><br><sub>Pick the right path</sub></td>
    <td align="center"><a href="#final-analyst-review-before-closure-or-escalation"><strong>Final Review</strong></a><br><sub>Close or escalate</sub></td>
  </tr>

  <tr>
    <th colspan="4" align="left">User, identity and mailbox incidents</th>
  </tr>
  <tr>
    <td align="center"><a href="#identity-centric-and-user-account-investigation-‍%EF%B8%8F"><strong>Identity</strong></a><br><sub>Sign-ins and users</sub></td>
    <td align="center"><a href="#phishing-and-business-email-compromise-related-mail-centric-investigation"><strong>Phishing / BEC</strong></a><br><sub>Email-based attacks</sub></td>
    <td align="center"><a href="#mailbox-investigation"><strong>Mailbox</strong></a><br><sub>Rules and forwarding</sub></td>
    <td align="center"><a href="#application-and-oauth-investigation"><strong>OAuth / Apps</strong></a><br><sub>Consent and apps</sub></td>
  </tr>

  <tr>
    <th colspan="4" align="left">Endpoint, network and indicators</th>
  </tr>
  <tr>
    <td align="center"><a href="#endpoint-and-device-investigation"><strong>Endpoint</strong></a><br><sub>Device and process</sub></td>
    <td align="center"><a href="#ip-address-investigation"><strong>IP Address</strong></a><br><sub>Source and destination</sub></td>
    <td align="center"><a href="#url-investigation"><strong>URL</strong></a><br><sub>Links and redirects</sub></td>
    <td align="center"><a href="#file-and-hash-investigation"><strong>File / Hash</strong></a><br><sub>Malware evidence</sub></td>
  </tr>

  <tr>
    <th colspan="4" align="left">Cloud, data access and follow-up</th>
  </tr>
  <tr>
    <td align="center"><a href="#azure-and-cloud-activity-investigation"><strong>Azure / Cloud</strong></a><br><sub>Resource activity</sub></td>
    <td align="center"><a href="#data-access-and-exfiltration-indicators"><strong>Data Access</strong></a><br><sub>Exfil indicators</sub></td>
    <td align="center"><a href="#post-containment-validation"><strong>Post-Containment</strong></a><br><sub>Validate cleanup</sub></td>
    <td align="center"><a href="#common-benign-explanations"><strong>Benign Checks</strong></a><br><sub>False positives</sub></td>
  </tr>
</table>

</div>

## Investigation Flow
0. **Understand your own permissions to know what you cannot see during incident investigation.**
1. Understand the alert trigger, source product, detection logic, severity, and first/last activity time.
2. Identify affected users, devices, mailboxes, apps, IPs, URLs, files, subscriptions, and resources.
3. Build a bounded timeline around the alert. Find the first related event and the most recent activity around the affected entities.
4. Validate suspiciousness using user baseline, source IP, device state, MFA/Conditional Access, mailbox activity, endpoint behavior, and related alerts.
5. Correlate across Defender XDR, Sentinel, Entra ID, Exchange Online, Defender for Cloud Apps, MDE, MDO, and Azure Activity.
6. Decide whether early containment is required.

## Fast Triage Checklist

- Understand the alert type, severity, source product, TTPs and all involved entities.
- Extract the primary time anchor: first activity, last activity, alert creation time, and suspicious sign-in time.
- Review related alerts for the same user, host, IP, URL, file hash, app, or mailbox within the surrounding window.
- **Review successful and failed sign-ins around the alert timestamp.**
- Validate the source IP: expected corporate/VPN/proxy/mobile/hosting/TOR/residential proxy/anomalous.
- Review MFA result, Conditional Access result, authentication method, device compliance, join state, browser, user agent, and application.
- Check for suspicious post-authentication activity: MFA-Methods, mailbox access, inbox rules & forwarding, mail sends, file downloads, OAuth consent, role changes, or Azure actions.
- For endpoint alerts, inspect the process tree, command line, file path, signer, prevalence, network connections, and persistence.
- Decide whether evidence supports benign, suspicious, malicious, attempted, historical, or inconclusive activity.

## Entity Investigation Map

| Entity | Primary questions | High-signal telemetry |
| --- | --- | --- |
| User | Was authentication legitimate, and what happened after sign-in? | `EntraIdSignInEvents`,`SigninLogs`, `AADSignInEventsBeta`, `AADNonInteractiveUserSignInLogs`, `AuditLogs`, `IdentityInfo`, `CloudAppEvents` |
| Mailbox | Was mail accessed, manipulated, forwarded, or abused for outbound phishing? | `EmailEvents`, `EmailPostDeliveryEvents`, `EmailAttachmentInfo`, `UrlClickEvents`, `OfficeActivity`, Exchange audit |
| Device | Did code execute, persist, connect outbound, or spread? | `DeviceProcessEvents`, `DeviceFileEvents`, `DeviceNetworkEvents`, `DeviceRegistryEvents`, `DeviceLogonEvents`, `DeviceInfo` |
| IP address | Is the IP expected, shared, anonymized, malicious, or linked to more entities? | Sign-in logs, MDE network events, `CloudAppEvents`, `OfficeActivity`, threat intelligence |
| URL | Was the URL delivered, clicked, detonated, redirected, or contacted by endpoints? | `UrlClickEvents`, `EmailUrlInfo`, `DeviceNetworkEvents`, MDO Explorer, sandbox results |
| File/hash | Was the file delivered, downloaded, executed, prevalent, signed, or quarantined? | `EmailAttachmentInfo`, `DeviceFileEvents`, `DeviceProcessEvents`, file profile, sandbox, reputation |
| Application | Is the app expected, publisher-verified, over-permissioned, or consented by a user? | `OAuthAppInfo`, `CloudAppEvents`, `AuditLogs`, service principal sign-ins |
| Azure resource | Were roles, resources, secrets, network exposure, or identities changed? | `AzureActivity`, Entra audit, Graph activity, resource logs |


## Identity centric and User Account Investigation 🤦‍♂️

- Review interactive and non-interactive sign-ins before, during, and after the alert.
- Compare IP, ASN, country, city, device, browser, user agent, app, and resource against normal user behavior.
- Validate MFA, Conditional Access, device compliance, join state, and token/session continuity.
- Check Identity Protection risk, risky sign-ins, risky users, and Defender XDR correlated attack evidence.
- Review `AuditLogs` for password reset, MFA method changes, app registration, consent, group changes, role assignments, and delegated access.
- Check post-authentication activity in mailbox, cloud apps, endpoint, Azure, and Graph logs.

<details>
<summary>Detailed user account checks</summary>

### Authentication review

- Look further back into User-Logon behaviour to get an idea what was common and what is uncommon now. 
- Identify the exact sign-in that triggered the alert and whether it succeeded.
- Review failed sign-ins immediately before the success for password spray, credential stuffing, or MFA fatigue.
- Check whether MFA was freshly performed, satisfied by claim, bypassed, not required, or denied before success. Or Password was correct but mfa failed. (indicates Password Compromises)
- Review Conditional Access policy result and determine whether device compliance, location, sign-in risk, or session controls were applied.
- Check the UPN's automatic replies / out-of-office status via Teams external search.
- Compare device detail to known managed devices in Entra ID, Intune, and Defender XDR.
- Check whether the same `UniqueTokenIdentifier`, `SessionId`, or `CorrelationId` appears across unexpected IPs or apps.
- Review non-interactive sign-ins from the same IP and session for follow-on token use.
- Check whether the app/resource is expected for the user and role.

### Account and privilege context

- Review user role, department, location, manager, account age, identity source, and hybrid/cloud-only state.
- Review Entra roles, Azure RBAC assignments, administrative units, and privileged identity management activity.
- Check whether the user is a service provider, developer, administrator, shared mailbox owner, or high-value target.
- Check for recent authentication method registration, SSPR, password changes, account disable/enable actions, or unusual admin activity.

### Post-authentication activity

- Review mailbox access, searches, inbox rules, forwarding, deleted items, suspicious sends, and unusual recipients.
- Review MDO URL clicks, quarantine releases, attachment access, and suspicious phishing delivery before the sign-in.
- Review Defender for Cloud Apps activity across Outlook, SharePoint, OneDrive, Teams, Power Platform, and other connected apps.
- Review file downloads, sharing changes, mass access, uncommon locations, and external sharing.
- Review Azure Activity for role assignments, resource changes, network exposure, Key Vault access, storage access, and automation changes.
- Review endpoint logons and local admin usage if the identity maps to a workstation.

### True-positive indicators
- Other alerts for same UPN within 48h timeframe.
- Successful sign-in from an anomalous IP, ASN, country, browser, or unmanaged device followed by mailbox or cloud activity.
- Same token/session used from a different IP or impossible location.
- Repeated MFA denials followed by successful access.
- New MFA method, password reset, OAuth consent, service principal change, or role assignment near the alert.
- New inbox rules, forwarding, mass deletes, unusual sends, or suspicious mailbox traversal.
- Recent phishing email delivery and URL click before suspicious sign-in.

### Common benign explanations to validate

- Expected travel, roaming mobile networks, corporate VPN, ZTNA/SASE egress, proxy, or VDI.
- New or reimaged device, browser update, Intune enrollment, or password reset.
- Known service-provider access, automation, admin scripts, or break-glass activity.
- Mail archiving, mail security gateways, or SSO integrations that produce unusual sign-in properties.
- Datacenter or VPN reputation without suspicious behavior after authentication.

</details>

<details>
<summary>Suspicious sign-in, unfamiliar properties, and potential account compromise checks</summary>

### Dive Deeper to find out if user is compromised

- Treat high-severity unfamiliar sign-in properties as a strong signal until validated.
- Review the user's 14- to 30-day baseline and compare IP, ASN, location, device, browser, user agent, token behavior, app, and resource.
- Review alert evidence: affected user, `AccountObjectId`, IP address, MITRE techniques, source product, first activity, last activity, and related entities.
- Search the relevant sign-in by `AccountObjectId`, not only by UPN.
- Investigate correct-password activity followed by MFA denial or successful access from a new session.
- Check for AiTM indicators: suspicious URL click before sign-in, token/session reuse, unexpected MFA satisfaction, or non-interactive token activity after the alert.
- Correlate suspicious IP and token use across `SigninLogs`, `AADNonInteractiveUserSignInLogs`, `AADSignInEventsBeta`, `CloudAppEvents`, and mailbox/audit activity.
- **Review the user's Defender XDR Timeline for the scoped window and filter out noisy apps, background services, and routine automation to understand meaningful user activity.** 🔎
- Review Defender XDR incident graph for related user, mailbox, URL, file, IP, device, app, and alert entities.
- Review XDR-correlated evidence for credential access, collection, suspicious email/web access, mailbox access, and cloud app abuse.
- Check whether the user accessed suspicious emails, released quarantine messages, or clicked URLs before the sign-in.
- Review mailbox audit, inbox rule creation, forwarding, sends, deletes, and delegated access.
- Review `AuditLogs` for MFA, password, app consent, service principal, and role changes.
- Confirm whether the activity is active, historical, attempted, or unsupported by available telemetry.
- If suspicious activity is likely or cannot be ruled out, revoke sessions while continuing scoping.

</details>

<details>
<summary>KQL - User and sign-in investigation</summary>

### Recent successful and failed sign-ins for a user

```kql
let TargetUser = "user@company.com"; // Replace with investigated UPN
SigninLogs
| where TimeGenerated > ago(14d)
| where UserPrincipalName =~ TargetUser
| project TimeGenerated, UserPrincipalName, ResultType, ResultDescription, IPAddress, Location,
          AppDisplayName, ResourceDisplayName, ClientAppUsed, ConditionalAccessStatus,
          RiskLevelAggregated, RiskDetail, IsRisky, UserAgent, DeviceDetail,
          CorrelationId, UniqueTokenIdentifier
| order by TimeGenerated desc
```

### Defender XDR sign-ins by account object ID

```kql
let TargetAccountObjectId = "OBJECT-ID"; // Replace with AccountObjectId from alert evidence
AADSignInEventsBeta
| where Timestamp > ago(14d)
| where AccountObjectId == TargetAccountObjectId
| project Timestamp, AccountUpn, AccountObjectId, IPAddress, Country, City,
          Application, ResourceDisplayName, LogonType, ErrorCode,
          ConditionalAccessStatus, UserAgent, DeviceName, RiskLevel,
          RiskState, SessionId, CorrelationId
| order by Timestamp desc
```

### Interactive and non-interactive activity using the same token

```kql
let TargetToken = "TOKEN-ID"; // Replace with UniqueTokenIdentifier
union isfuzzy=true SigninLogs, AADNonInteractiveUserSignInLogs
| where TimeGenerated > ago(14d)
| where UniqueTokenIdentifier == TargetToken
| project TimeGenerated, UserPrincipalName, IPAddress, Location, AppDisplayName,
          ResourceDisplayName, ResultType, ConditionalAccessStatus, UserAgent,
          DeviceDetail, CorrelationId, UniqueTokenIdentifier
| order by TimeGenerated desc
```

### Audit activity initiated by a user

```kql
let TargetUser = "user@company.com"; // Replace with investigated UPN
AuditLogs
| where TimeGenerated > ago(14d)
| extend InitiatedByUser = tostring(parse_json(tostring(InitiatedBy.user)).userPrincipalName)
| extend InitiatedByIP = tostring(parse_json(tostring(InitiatedBy.user)).ipAddress)
| where InitiatedByUser =~ TargetUser
| project TimeGenerated, OperationName, ActivityDisplayName, Result, InitiatedByUser,
          InitiatedByIP, TargetResources, AdditionalDetails, CorrelationId
| order by TimeGenerated desc
```

### User privilege and identity context

```kql
let TargetUser = "user@company.com"; // Replace with investigated UPN
IdentityInfo
| where TimeGenerated > ago(14d)
| where AccountUPN =~ TargetUser
| summarize arg_max(TimeGenerated, *) by AccountUPN
| project TimeGenerated, AccountDisplayName, AccountUPN, RiskLevel, RiskState,
          BlastRadius, GroupMembership, AssignedRoles, Department, JobTitle,
          Manager, Country
```

### On-premises identity logons

```kql
let TargetAccount = "user"; // Replace with SAM/account name
IdentityLogonEvents
| where TimeGenerated > ago(14d)
| where AccountName =~ TargetAccount or AccountUpn =~ "user@company.com"
| project TimeGenerated, ActionType, AccountName, AccountUpn, DeviceName,
          LogonType, Protocol, FailureReason, IPAddress, DestinationDeviceName
| order by TimeGenerated desc
```

</details>

## Phishing and Business Email Compromise related mail centric Investigation

- Determine whether the message is malicious, suspicious, benign, or inconclusive.
- Review sender, sender domain, return path, authentication results, headers, sending infrastructure, recipient scope, subject, URLs, attachments, and delivery actions.
- Do not rely on sender IP alone; last-hop mail infrastructure often masks the origin.
- Hunt for other messages from the same sender, domain, subject, URL, attachment filename, hash, sender display name, or sending IP.
- Check URL clicks, attachment execution, post-delivery actions, mailbox access, inbox rules, forwarding, and suspicious outbound sends.
- For BEC, prioritize mailbox persistence and post-compromise behavior over the original phishing message alone.
- Find out if a realistic legitimate connection between the sender and recipient exists.

<details>
<summary>Detailed phishing and BEC checks</summary>

### Message analysis

- Review MDO detection details, delivery location, delivery action, threat names, policy actions, and post-delivery actions.
- Check headers in a message header analyzer and validate SPF, DKIM, DMARC, return path, reply-to, and authentication alignment.
- Inspect URLs, redirects, final landing pages, Cloudflare/challenge behavior, credential-harvest forms, brand impersonation, and attachment-hosted links.
- Inspect attachments, archive contents, HTML/HTM files, scripts, Office macros, ISO/LNK files, executables, QR codes, and embedded images.
- Detonate URLs and attachments only in a safe sandbox and record redirects, downloads, and credential prompts.
- Check whether Safe Links, ZAP, quarantine, or user-reporting pipelines already acted.

### Recipient and spread scoping

- Search for messages with the same sender address, sender domain, display name, subject, URL, attachment filename, attachment hash, and network message ID.
- Identify all recipients, delivery locations, post-delivery removals, user submissions, and clicks.
- Review whether any recipients replied, forwarded, downloaded attachments, clicked links, released quarantine, or authenticated afterward.
- Check whether the same phishing infrastructure appears in endpoint network events or browser downloads.

### BEC and mailbox compromise

- Check mailbox sign-ins and mailbox audit events around suspicious activity.
- Check for new inbox rules that delete, move, mark read, hide, or forward messages.
- Check mailbox forwarding, SMTP forwarding, transport rules, delegates, SendAs, SendOnBehalf, and full access permissions.
- Review outbound mail volume, repeated subjects, external recipients, financial themes, invoice/payment changes, and conversation hijacking.
- Review deleted items, single-mail deletion, unusual mailbox search, message access, and suspicious purge behavior.
- Check Power Automate flows or third-party connected apps that copy mail, forward files, or sync data externally.
- Investigate OAuth consent abuse when mailbox access occurs without obvious interactive sign-in anomalies.

### High-signal BEC indicators

- New rule with actions such as delete, move to RSS/archive, mark as read, forward, redirect, or stop processing more rules.
- External forwarding enabled shortly after suspicious sign-in.
- Sudden outbound sends to many external recipients or repeated subjects.
- Suspicious sent items followed by deletion or cleanup.
- User accessed phishing email or clicked credential-harvest URL before anomalous sign-in.
- Unrecognized app consent with `Mail.Read`, `Mail.ReadWrite`, `Mail.Send`, `offline_access`, `Files.Read.All`, or broad Graph permissions.

</details>

<details>
<summary>KQL - Mailbox, email, and BEC investigation</summary>

### Hunt email by sender, domain, subject, or recipient

```kql
let SenderAddress = "sender@example.com"; // Replace or leave unused
let SenderDomain = "example.com"; // Replace or leave unused
let SubjectText = "invoice"; // Replace or leave unused
let RecipientAddress = "user@company.com"; // Replace or leave unused
EmailEvents
| where Timestamp > ago(14d)
| where SenderFromAddress =~ SenderAddress
    or SenderFromDomain =~ SenderDomain
    or Subject contains SubjectText
    or RecipientEmailAddress =~ RecipientAddress
| project Timestamp, NetworkMessageId, SenderFromAddress, SenderMailFromAddress,
          SenderDisplayName, RecipientEmailAddress, Subject, DeliveryAction,
          DeliveryLocation, ThreatTypes, DetectionMethods, SenderIPv4, SenderIPv6
| order by Timestamp desc
```

### Hunt email attachments by filename or hash

```kql
let TargetFileName = "invoice.html"; // Replace with attachment name
let TargetSHA256 = "SHA256-HASH"; // Replace with SHA256 or leave unused
EmailAttachmentInfo
| where Timestamp > ago(14d)
| where FileName has TargetFileName or SHA256 =~ TargetSHA256
| join kind=leftouter (
    EmailEvents
    | project NetworkMessageId, SenderFromAddress, SenderDisplayName,
              RecipientEmailAddress, Subject, DeliveryAction, DeliveryLocation
) on NetworkMessageId
| project Timestamp, NetworkMessageId, SenderFromAddress, SenderDisplayName,
          RecipientEmailAddress, Subject, FileName, SHA256, DeliveryAction,
          DeliveryLocation
| order by Timestamp desc
```

### URL clicks for messages delivered to a user

```kql
let TargetUser = "user@company.com"; // Replace with recipient UPN
let Timeframe = 7d;
let DeliveredMail =
    EmailEvents
    | where Timestamp > ago(Timeframe)
    | where RecipientEmailAddress =~ TargetUser
    | where UrlCount > 0
    | project EmailTimestamp = Timestamp, NetworkMessageId, SenderFromAddress,
              SenderDisplayName, Subject, ThreatTypes;
DeliveredMail
| join kind=inner (
    UrlClickEvents
    | where Timestamp > ago(Timeframe)
    | where Workload =~ "Email"
    | where ActionType != "ClickBlocked"
    | project ClickTimestamp = Timestamp, NetworkMessageId, Url, IPAddress, ActionType
) on NetworkMessageId
| project EmailTimestamp, ClickTimestamp, SenderFromAddress, SenderDisplayName,
          Subject, Url, IPAddress, ActionType, NetworkMessageId, ThreatTypes
| order by ClickTimestamp desc
```

### Suspicious outbound email volume by subject

```kql
let TargetUser = "user@company.com"; // Replace with investigated sender
EmailEvents
| where Timestamp > ago(10d)
| where SenderMailFromAddress =~ TargetUser or SenderFromAddress =~ TargetUser
| summarize MessageCount = count(), Recipients = dcount(RecipientEmailAddress),
            FirstSeen = min(Timestamp), LastSeen = max(Timestamp)
            by Subject
| order by MessageCount desc
```

### Post-delivery threat actions for a recipient

```kql
let TargetUser = "user@company.com"; // Replace with recipient UPN
let Timeframe = 14d;
let MailToUser =
    EmailEvents
    | where Timestamp > ago(Timeframe)
    | where RecipientEmailAddress =~ TargetUser
    | project EmailTimestamp = Timestamp, NetworkMessageId, SenderFromAddress,
              SenderDisplayName, Subject, DeliveryAction, DeliveryLocation;
MailToUser
| join kind=leftouter (
    EmailPostDeliveryEvents
    | where Timestamp > ago(Timeframe)
    | project PostDeliveryTimestamp = Timestamp, NetworkMessageId, Action,
              ActionType, ActionTrigger, ActionResult, DeliveryLocation,
              ThreatTypes, DetectionMethods
) on NetworkMessageId
| order by EmailTimestamp desc
```

</details>

## Mailbox Investigation

- Review mailbox forwarding and inbox rules before concluding a user is safe.
- Check both Exchange settings and audit logs because persistence may be configured outside visible user rules.
- Investigate suspicious sends, deletes, mailbox traversal, delegated access, and OAuth-driven access.
- Remove malicious rules, forwarding, delegates, or consent only after capturing evidence.

<details>
<summary>Mailbox persistence and abuse checks</summary>

- Check mailbox-level forwarding: `ForwardingSmtpAddress`, `ForwardingAddress`, and `DeliverToMailboxAndForward`.
- Check inbox rules for external forwarding, redirect, delete, move, hide, mark-read, and keyword-based filtering.
- Check transport rules or mail-flow rules if the user has administrative rights.
- Check delegates and mailbox permissions: `FullAccess`, `SendAs`, `SendOnBehalf`, shared mailbox access, and unexpected owners.
- Check `OfficeActivity` and Exchange audit for `New-InboxRule`, `Set-InboxRule`, `Remove-InboxRule`, `Set-Mailbox`, `UpdateInboxRules`, `MailItemsAccessed`, `Send`, `SendAs`, `SendOnBehalf`, `SoftDelete`, and `HardDelete`.
- Review sent items and deleted items for cleanup behavior.
- Review outbound messages for repeated subject lines, unusual recipients, payment redirection, document-sharing lures, and internal phishing.
- Check whether the mailbox was accessed through an OAuth app, legacy protocol, unexpected client app, or anomalous IP.
- Review Power Automate flows connected to the mailbox, OneDrive, SharePoint, or external connectors.

</details>

<details>
<summary>KQL - Mailbox persistence and abuse</summary>

### Mail deletes grouped by subject

```kql
let TargetUser = "user@company.com"; // Replace with investigated UPN
OfficeActivity
| where TimeGenerated > ago(30d)
| where UserId =~ TargetUser
| where Operation has_any ("Delete", "SoftDelete", "HardDelete", "MoveToDeletedItems")
| extend Subject = tostring(parse_json(AffectedItems)[0].Subject)
| summarize EventCount = count(), FirstSeen = min(TimeGenerated), LastSeen = max(TimeGenerated)
          by Operation, Subject
| order by EventCount desc
```

### Inbox rules, forwarding, and mailbox permission changes

```kql
let TargetUser = "user@company.com"; // Replace with mailbox UPN
OfficeActivity
| where TimeGenerated > ago(30d)
| where UserId =~ TargetUser or MailboxOwnerUPN =~ TargetUser
| where Operation has_any ("New-InboxRule", "Set-InboxRule", "Remove-InboxRule",
                           "UpdateInboxRules", "Set-Mailbox", "Add-MailboxPermission",
                           "Add-RecipientPermission", "Set-MailboxRegionalConfiguration",
                           "Send", "SendAs", "SendOnBehalf", "MailItemsAccessed")
| project TimeGenerated, Operation, UserId, MailboxOwnerUPN, ClientIP, UserAgent,
          ResultStatus, Parameters, ModifiedProperties, AffectedItems, Item
| order by TimeGenerated desc
```

</details>

## Endpoint and Device Investigation

- Review the Defender for Endpoint device page, alerts, timeline, logged-on users, exposure level, sensor health, and device tags.
- Inspect process lineage, command line, file path, signer, hash, prevalence, and parent-child relationships.
- Check for script engines, LOLBins, encoded commands, archive extraction, browser downloads, Office child processes, and suspicious persistence.
- Review network connections, DNS, remote IP/URL reputation, bytes transferred, and rare destinations.
- Capture investigation package or live response artifacts before cleanup when compromise is likely.

<details>
<summary>Detailed endpoint checks</summary>

### Device state

- Confirm Defender sensor health, onboarding state, tamper protection, AV mode, EDR mode, and last seen time.
- Check whether the endpoint is active, isolated, contained by policy, offline, or only monitored.
- Review logged-on users, local administrators, recent remote logons, RDP, SMB sessions, and service accounts.
- Check Intune compliance, Entra join/registration state, and device ownership if identity compromise is involved.

### Execution and persistence

- Review suspicious process ancestry and child processes.
- Investigate Office, browser, Teams, OneDrive, Outlook, or PDF reader processes spawning PowerShell, `cmd.exe`, `wscript.exe`, `cscript.exe`, `mshta.exe`, `rundll32.exe`, `regsvr32.exe`, `wmic.exe`, `certutil.exe`, `bitsadmin.exe`, `msiexec.exe`, or `schtasks.exe`.
- Check encoded PowerShell, download cradles, suspicious script paths, user-writable execution paths, and living-off-the-land activity.
- Review autoruns, Run keys, services, scheduled tasks, WMI consumers, startup folders, browser extensions, firewall exclusions, local users, and administrators.
- Check file drops, modifications, archive extraction, temp directories, public folders, downloads, and persistence paths.

### Network and lateral movement

- Review connections to rare domains, cloud VPS, residential proxy, VPN/TOR, non-standard ports, and newly registered domains.
- Correlate remote IPs/URLs with threat intelligence and other affected devices.
- Check for SMB, RDP, WinRM, PsExec, WMI, remote service creation, credential dumping, LSASS access, suspicious Kerberos/NTLM, and lateral movement artifacts.
- Review process-to-network mapping: which process created the connection and what file/hash launched it.

### Containment

- Isolate the endpoint for active malware, C2, credential theft, lateral movement, ransomware, destructive behavior, or uncontrolled data exfiltration.
- Quarantine malicious files and block hashes/URLs/IPs when confidence is high.
- Preserve investigation package, timeline, process tree, files, registry artifacts, scheduled tasks, and relevant event logs before destructive remediation.
- Reimage when persistence or integrity cannot be confidently removed.

</details>

<details>
<summary>KQL - Endpoint and device investigation</summary>

### Device process timeline around an alert

```kql
let TargetDevice = "DEVICE-001"; // Replace with investigated device
let StartTime = datetime(2026-01-01T00:00:00Z); // Replace with investigation start
let EndTime = datetime(2026-01-02T00:00:00Z); // Replace with investigation end
DeviceProcessEvents
| where Timestamp between (StartTime .. EndTime)
| where DeviceName =~ TargetDevice
| project Timestamp, DeviceName, AccountUpn, FileName, FolderPath, SHA256,
          ProcessCommandLine, InitiatingProcessFileName,
          InitiatingProcessCommandLine, InitiatingProcessParentFileName, ReportId
| order by Timestamp asc
```

### Suspicious LOLBin and script activity

```kql
let Lookback = 14d;
DeviceProcessEvents
| where Timestamp > ago(Lookback)
| where FileName in~ ("powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe", "cscript.exe",
                      "mshta.exe", "rundll32.exe", "regsvr32.exe", "wmic.exe",
                      "certutil.exe", "bitsadmin.exe", "msiexec.exe", "schtasks.exe")
| where ProcessCommandLine has_any ("-enc", "EncodedCommand", "FromBase64String", "http",
                                    "download", "invoke", "bypass", "hidden", "IEX")
| project Timestamp, DeviceName, AccountUpn, FileName, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine, SHA256
| order by Timestamp desc
```

### Local administrator interactive logons

```kql
let Lookback = 7d;
DeviceLogonEvents
| where Timestamp > ago(Lookback)
| where LogonType == "Interactive"
| where IsLocalAdmin == true
| project Timestamp, DeviceName, AccountName, AccountDomain, AccountUpn,
          LogonType, IsLocalAdmin, RemoteIP, ActionType
| order by Timestamp desc
```

### Device network connections by process

```kql
let TargetDevice = "DEVICE-001"; // Replace with investigated device
DeviceNetworkEvents
| where Timestamp > ago(14d)
| where DeviceName =~ TargetDevice
| project Timestamp, DeviceName, InitiatingProcessAccountUpn, InitiatingProcessFileName,
          InitiatingProcessCommandLine, RemoteUrl, RemoteIP, RemotePort,
          Protocol, ActionType
| order by Timestamp desc
```

</details>

## IP Address Investigation

- Determine whether the IP is expected corporate infrastructure, VPN, proxy, mobile carrier, ISP, hosting, TOR, residential proxy, business partner, or unknown.
- Review sign-ins for the exact IP and nearby subnet where appropriate.
- Check whether the IP appears across multiple users, devices, mailbox events, cloud app activity, endpoint network events, Azure activity, or alerts.
- Use IP reputation as context, not a standalone verdict.
- Treat one low-confidence reputation hit as suspicious only when supported by behavior.

<details>
<summary>Detailed IP investigation checks</summary>

- Review Entra ID sign-ins filtered by the IP: users, apps, resources, success/failure, MFA, CA status, device, user agent, and timestamp spread.
- Search the first two octets or ASN only when investigating VPN/proxy rotation or clustered activity; expect noise.
- Check whether multiple users authenticate from the IP in a way that matches an office, VPN, SASE, VDI, mail gateway, or service provider.
- Review `DeviceNetworkEvents` for outbound connections to the IP and identify initiating process and device.
- Review `CloudAppEvents`, `OfficeActivity`, and Azure logs for the IP as client or caller IP.
- Enrich with VirusTotal, AbuseIPDB, Shodan, WHOIS, ASN, geolocation, VPN/proxy/TOR/residential proxy sources, and internal allowlists.
- For VPN/proxy data, prioritize confirmed tunnel provider indicators over historical proxy observations.
- If malicious and relevant to endpoint traffic, consider Defender endpoint indicator block.
- If malicious and relevant to email delivery, consider tenant allow/block entries for sender/domain/IP.
- If malicious and relevant to detection, add a threat intelligence indicator with appropriate expiration.

</details>

<details>
<summary>KQL - IP investigation</summary>

### Broad IP sweep across Microsoft telemetry

```kql
let TargetIP = "203.0.113.10"; // Replace with investigated IP
let Lookback = 10d;
union isfuzzy=true
    IdentityLogonEvents,
    IdentityQueryEvents,
    IdentityDirectoryEvents,
    EmailEvents,
    UrlClickEvents,
    DeviceNetworkEvents,
    DeviceFileEvents,
    DeviceLogonEvents,
    DeviceEvents,
    BehaviorAnalytics,
    CloudAppEvents,
    AADSpnSignInEventsBeta,
    AADSignInEventsBeta,
    AADNonInteractiveUserSignInLogs,
    AADServicePrincipalSignInLogs,
    AADUserRiskEvents,
    SigninLogs,
    OfficeActivity,
    AzureActivity,
    MicrosoftGraphActivityLogs,
    GraphAPIAuditEvents,
    SecurityEvent,
    SecurityAlert
| extend EventTime = coalesce(
    column_ifexists("Timestamp", datetime(null)),
    column_ifexists("TimeGenerated", datetime(null))
)
| where EventTime > ago(Lookback)
| where LocalIP == TargetIP
    or FileOriginIP == TargetIP
    or RequestSourceIP == TargetIP
    or SenderIPv4 == TargetIP
    or SenderIPv6 == TargetIP
    or IPAddress == TargetIP
    or SourceIPAddress == TargetIP
    or ClientIP == TargetIP
    or RemoteIP == TargetIP
    or DestinationIPAddress == TargetIP
    or CallerIpAddress == TargetIP
    or tostring(parse_json(tostring(ExtendedProperties))["Client IP Address"]) == TargetIP
    or tostring(IpAddress) == TargetIP
| project EventTime, Type, AccountUpn, UserPrincipalName, AccountName, DeviceName,
          IPAddress, ClientIP, RemoteIP, RemoteUrl, SenderFromAddress,
          RecipientEmailAddress, Operation, ActivityType, ActionType
| order by EventTime desc
```

### Sign-ins from an IP or IP prefix

```kql
let TargetIP = "203.0.113.10"; // Replace with investigated IP
let TargetPrefix = "203.0."; // Replace only when subnet/prefix review is justified
SigninLogs
| where TimeGenerated > ago(14d)
| where IPAddress == TargetIP or IPAddress startswith TargetPrefix
| summarize SignIns = count(), Successful = countif(ResultType == 0),
            Failed = countif(ResultType != 0),
            Users = dcount(UserPrincipalName),
            Apps = make_set(AppDisplayName, 20),
            Locations = make_set(Location, 20)
            by IPAddress
| order by SignIns desc
```

### Endpoint network activity to an IP

```kql
let TargetIP = "203.0.113.10"; // Replace with investigated IP
DeviceNetworkEvents
| where Timestamp > ago(14d)
| where RemoteIP == TargetIP
| project Timestamp, DeviceName, InitiatingProcessAccountUpn, InitiatingProcessFileName,
          InitiatingProcessCommandLine, RemoteIP, RemotePort, RemoteUrl, Protocol,
          ActionType, ReportId
| order by Timestamp desc
```

</details>

## URL Investigation

- Check whether the URL was delivered by email, clicked by users, contacted by devices, or embedded in attachments.
- Detonate in a safe sandbox and record redirect chain, final URL, downloaded files, credential prompts, and blocked/challenge behavior.
- Search reputation sources and URL scanning platforms, but validate with telemetry.
- Scope affected users and devices through MDO URL clicks and MDE network events.

<details>
<summary>Detailed URL checks</summary>

- Normalize the URL and also investigate domain, hostname, path, query, redirect targets, shortened URLs, and final landing page.
- Check MDO Explorer for delivery, clicks, user submissions, Safe Links, ZAP, and quarantine actions.
- Check `UrlClickEvents` for clicked, allowed, blocked, and pending verdict actions.
- Check `DeviceNetworkEvents` for endpoint contact to the URL or domain.
- Check email messages containing the URL and identify all recipients and delivery locations.
- Check attachment content if the URL is embedded in HTML, PDF, Office, archive, or image/QR content.
- Review DNS age, registrar, hosting provider, TLS certificate, page title, page content, and brand impersonation indicators.
- Block the URL/domain when malicious and still reachable or observed in telemetry.

</details>

<details>
<summary>KQL - URL investigation</summary>

### URL clicks

```kql
let TargetUrl = "https://phishing.example.com/login"; // Replace with investigated URL or domain fragment
UrlClickEvents
| where Timestamp > ago(14d)
| where Url contains TargetUrl
| project Timestamp, AccountUpn, Workload, Url, IPAddress, ActionType,
          ThreatTypes, DetectionMethods, NetworkMessageId
| order by Timestamp desc
```

### Endpoint network connections to URL or domain

```kql
let TargetDomain = "phishing.example.com"; // Replace with investigated domain or URL fragment
DeviceNetworkEvents
| where Timestamp > ago(14d)
| where RemoteUrl contains TargetDomain
| project Timestamp, DeviceName, InitiatingProcessAccountUpn, InitiatingProcessFileName,
          InitiatingProcessCommandLine, RemoteUrl, RemoteIP, RemotePort, ActionType
| order by Timestamp desc
```

### Messages containing a URL

```kql
let TargetDomain = "phishing.example.com"; // Replace with investigated domain or URL fragment
EmailUrlInfo
| where Timestamp > ago(14d)
| where Url contains TargetDomain
| join kind=leftouter (
    EmailEvents
    | project NetworkMessageId, SenderFromAddress, SenderDisplayName,
              RecipientEmailAddress, Subject, DeliveryAction, DeliveryLocation
) on NetworkMessageId
| project Timestamp, Url, NetworkMessageId, SenderFromAddress, SenderDisplayName,
          RecipientEmailAddress, Subject, DeliveryAction, DeliveryLocation
| order by Timestamp desc
```

</details>

## File and Hash Investigation

- Determine file origin: email attachment, browser download, removable media, network share, cloud sync, archive extraction, or dropped by process.
- Review hash reputation, signer, prevalence, first seen time, file path, execution count, parent process, and device spread.
- Check whether the file was delivered, downloaded, written, executed, blocked, quarantined, or remediated.
- Do not extract suspected malware on a normal workstation.

<details>
<summary>Detailed file and hash checks</summary>

- Search file profile in Defender XDR by SHA256, SHA1, MD5, filename, and path.
- Check global and tenant prevalence. Very high prevalence can support benign classification; rare prevalence increases suspicion but is not proof.
- Review signature and publisher, original filename, compilation metadata, file description, and known-good software context.
- Check delivery through `EmailAttachmentInfo` and related `EmailEvents`.
- Check download source with `DeviceFileEvents`, `DeviceNetworkEvents`, browser process lineage, and URL evidence.
- Check execution with `DeviceProcessEvents` and map parent/child processes.
- Check whether the file created scheduled tasks, services, registry keys, startup items, other files, or network connections.
- Detonate in a sandbox when reputation and telemetry are inconclusive.
- Quarantine or block the hash when malicious and still present or likely to recur.

</details>

<details>
<summary>KQL - File and hash investigation</summary>

### File activity by SHA256

```kql
let TargetSHA256 = "SHA256-HASH"; // Replace with investigated SHA256
union isfuzzy=true DeviceFileEvents, DeviceProcessEvents
| where Timestamp > ago(14d)
| where SHA256 =~ TargetSHA256
| project Timestamp, Type, DeviceName, ActionType, FileName, FolderPath, SHA256,
          InitiatingProcessAccountUpn, InitiatingProcessFileName,
          InitiatingProcessCommandLine, ReportId
| order by Timestamp desc
```

### Attachment delivery by SHA256

```kql
let TargetSHA256 = "SHA256-HASH"; // Replace with investigated SHA256
EmailAttachmentInfo
| where Timestamp > ago(14d)
| where SHA256 =~ TargetSHA256
| join kind=leftouter (
    EmailEvents
    | project NetworkMessageId, SenderFromAddress, SenderDisplayName,
              RecipientEmailAddress, Subject, DeliveryAction, DeliveryLocation
) on NetworkMessageId
| project Timestamp, NetworkMessageId, FileName, SHA256, SenderFromAddress,
          RecipientEmailAddress, Subject, DeliveryAction, DeliveryLocation
| order by Timestamp desc
```

### Process execution by filename

```kql
let TargetFileName = "payload.exe"; // Replace with investigated filename
DeviceProcessEvents
| where Timestamp > ago(14d)
| where FileName =~ TargetFileName or InitiatingProcessFileName =~ TargetFileName
| project Timestamp, DeviceName, AccountUpn, FileName, FolderPath, SHA256,
          ProcessCommandLine, InitiatingProcessFileName,
          InitiatingProcessCommandLine, InitiatingProcessParentFileName
| order by Timestamp desc
```

</details>

## Application and OAuth Investigation

- Review enterprise app, app registration, service principal, publisher, owner tenant, permission grants, consent type, and sign-in activity.
- Focus on new consent, broad Graph permissions, unverified publishers, multi-tenant apps, suspicious redirect URIs, and unusual service principal sign-ins.
- Check whether the app accessed mail, files, users, groups, directory data, or Azure resources after consent.
- Remove malicious consent and disable/restrict the app when abuse is likely.

<details>
<summary>Detailed application and consent checks</summary>

- Identify `APP-ID`, service principal object ID, app display name, publisher, app owner tenant ID, and consented permissions.
- Check whether consent was user consent, admin consent, delegated permission, or application permission.
- Review `AuditLogs` for `Consent to application`, `Add service principal`, `Update application`, `Add app role assignment`, and permission grant activity.
- Review `OAuthAppInfo` for app metadata and permission scope.
- Review service principal sign-ins and app activity by IP, resource, user, and timestamp.
- Check redirect URIs, certificate/secret additions, federated credentials, app owners, and reply URLs.
- Investigate whether the consenting user had privileged rights or whether admin consent was granted unexpectedly.
- Look for permissions such as `offline_access`, `Mail.Read`, `Mail.ReadWrite`, `Mail.Send`, `Files.Read.All`, `Sites.Read.All`, `Directory.ReadWrite.All`, `User.Read.All`, and role-management scopes.
- Disable or delete malicious service principals/app registrations only after recording permissions, owners, consent timestamps, and observed access.

</details>

<details>
<summary>KQL - Application, OAuth, and consent investigation</summary>

### OAuth app metadata

```kql
let AppNameFragment = "example app"; // Replace with investigated app name fragment
OAuthAppInfo
| where Timestamp > ago(30d)
| where AppName contains AppNameFragment
| extend AppIdentifier = tostring(column_ifexists("AppId", column_ifexists("OAuthAppId", "")))
| extend OwnerTenant = tostring(column_ifexists("AppOwnerTenantId", ""))
| extend PublisherName = tostring(column_ifexists("Publisher", ""))
| extend PermissionList = tostring(column_ifexists("Permissions", ""))
| extend ConsentState = tostring(column_ifexists("ConsentType", column_ifexists("PermissionsConsentState", "")))
| project Timestamp, AppName, AppIdentifier, OwnerTenant, PublisherName,
          PermissionList, ConsentState, AppOrigin
| order by Timestamp desc
```

### Consent and service principal changes

```kql
let TargetUser = "user@company.com"; // Replace with consenting or initiating user
AuditLogs
| where TimeGenerated > ago(30d)
| where ActivityDisplayName has_any ("Consent", "service principal", "application", "app role", "permission grant")
| extend InitiatedByUser = tostring(parse_json(tostring(InitiatedBy.user)).userPrincipalName)
| where InitiatedByUser =~ TargetUser or tostring(TargetResources) has TargetUser
| project TimeGenerated, ActivityDisplayName, OperationName, Result, InitiatedByUser,
          TargetResources, AdditionalDetails, CorrelationId
| order by TimeGenerated desc
```

### Service principal sign-ins

```kql
let TargetAppId = "APP-ID"; // Replace with app/client ID
AADServicePrincipalSignInLogs
| where TimeGenerated > ago(30d)
| where AppId == TargetAppId or ServicePrincipalId == TargetAppId
| extend ServicePrincipalNameValue = tostring(column_ifexists("ServicePrincipalName", ""))
| extend ResourceName = tostring(column_ifexists("ResourceDisplayName", ""))
| project TimeGenerated, AppId, ServicePrincipalId, ServicePrincipalNameValue,
          ResourceName, IPAddress, ResultType, ResultDescription,
          ConditionalAccessStatus, CorrelationId
| order by TimeGenerated desc
```

</details>

## Azure and Cloud Activity Investigation

- Review Azure Activity for caller, operation, resource group, subscription, result, caller IP, and correlation ID.
- Prioritize role assignments, policy changes, network exposure, storage access, Key Vault access, managed identity changes, automation, and resource deployment.
- Review Entra ID audit and Graph activity for identity-plane changes that explain cloud-plane activity.
- Rotate secrets and disable identities when token, service principal, managed identity, or credential exposure is likely.

<details>
<summary>Azure and cloud resource abuse checks</summary>

- Check Azure role assignments, privileged role activation, owner/contributor additions, and custom role changes.
- Check new or modified app registrations, service principals, federated credentials, certificates, secrets, and managed identities.
- Check storage account access, public exposure, SAS token creation, blob enumeration, and bulk downloads.
- Check Key Vault secret, key, and certificate reads; access policy changes; RBAC changes; firewall changes.
- Check network security group changes, public IP creation, firewall changes, exposed management ports, and inbound rule additions.
- Check VM extension execution, Run Command, automation accounts, Logic Apps, Functions, deployment scripts, and suspicious templates.
- Check diagnostic setting removal, logging disablement, policy exemptions, and Defender for Cloud alert suppression.
- Correlate Azure operations with the identity sign-in context and source IP.

</details>

<details>
<summary>KQL - Azure and cloud activity investigation</summary>

### Azure Activity by caller

```kql
let TargetCaller = "user@company.com"; // Replace with UPN, app ID, or caller value
AzureActivity
| where TimeGenerated > ago(30d)
| where Caller contains TargetCaller
| project TimeGenerated, Caller, CallerIpAddress, OperationNameValue, ActivityStatusValue,
          ResourceProviderValue, ResourceGroup, Resource, SubscriptionId,
          CategoryValue, CorrelationId, Properties
| order by TimeGenerated desc
```

### Azure role assignment changes

```kql
AzureActivity
| where TimeGenerated > ago(30d)
| where OperationNameValue has_any ("roleAssignments/write", "roleAssignments/delete",
                                    "roleDefinitions/write", "roleDefinitions/delete")
| project TimeGenerated, Caller, CallerIpAddress, OperationNameValue,
          ActivityStatusValue, ResourceGroup, Resource, SubscriptionId,
          CorrelationId, Properties
| order by TimeGenerated desc
```

### Graph activity by user or app

```kql
let TargetEntity = "user@company.com"; // Replace with UPN, app ID, or object ID
MicrosoftGraphActivityLogs
| where TimeGenerated > ago(30d)
| where UserId contains TargetEntity
    or AppId contains TargetEntity
    or ServicePrincipalId contains TargetEntity
| extend RequestMethodValue = tostring(column_ifexists("RequestMethod", ""))
| extend RequestUriValue = tostring(column_ifexists("RequestUri", column_ifexists("RequestUri_s", "")))
| extend ResponseStatus = tostring(column_ifexists("ResponseStatusCode", column_ifexists("ResponseStatusCode_d", "")))
| extend SourceIP = tostring(column_ifexists("IPAddress", column_ifexists("IpAddress", "")))
| extend UserAgentValue = tostring(column_ifexists("UserAgent", ""))
| project TimeGenerated, UserId, AppId, ServicePrincipalId, RequestMethodValue,
          RequestUriValue, ResponseStatus, SourceIP, UserAgentValue, CorrelationId
| order by TimeGenerated desc
```

</details>

## Data Access and Exfiltration Indicators

- Mass mailbox reads, mailbox search activity, or unusual `MailItemsAccessed`.
- High-volume SharePoint/OneDrive downloads, sync activity, external sharing, anonymous links, or access from new IPs.
- Power Automate flows or OAuth apps copying mail/files to external destinations.
- Storage blob enumeration, SAS creation, Key Vault secret reads, database export, or resource snapshot/export activity.
- Endpoint archive creation, staging directories, compression tools, cloud upload tools, or large outbound transfers.
- Repeated failed access followed by successful access to sensitive resources.

## Post-Containment Validation

- Confirm sessions were revoked and no new suspicious sign-ins occur.
- Confirm password reset or credential rotation completed where required.
- Confirm account is disabled if active abuse continues or confidence is high.
- Confirm malicious inbox rules, forwarding, delegates, and OAuth consent are removed.
- Confirm endpoint isolation, quarantine, scan, or remediation completed and persistence is gone.
- Confirm blocks for sender/domain/IP/URL/hash/app are active where appropriate.
- Continue monitoring for reauthentication, token reuse, new rules, outbound sends, endpoint callbacks, and repeated IP/app activity.

## Common Benign Explanations

- Corporate VPN, SASE, proxy, VDI, NAT gateway, mail gateway, or mobile carrier egress.
- Business travel or roaming where device, MFA, and post-authentication behavior remain normal.
- New managed device, device reimage, browser update, changed user agent, or Intune enrollment.
- Known service provider, administrator, automation, software deployment, vulnerability scanner, or monitoring tool.
- Mail archiving or security tooling that signs in, scans, rewrites, or replays content in expected ways.
- High-prevalence signed file from a trusted vendor and expected deployment path.
- Sender IP reputation noise where mail authentication, content, recipient behavior, and telemetry are otherwise benign.

## Final Analyst Review Before Closure or Escalation

- The earliest suspicious event and current investigation window are clear.
- All impacted entities are identified or explicitly listed as unknown.
- Sign-in, audit, mailbox, endpoint, app, IP, URL, file, and Azure evidence were checked where relevant.
- Benign explanations were validated with telemetry, not assumption.
- Suspicious indicators are separated from confirmed facts.
- Containment actions match evidence and confidence.
- Evidence gaps are documented: missing logs, unavailable mailbox audit, offline endpoint, incomplete retention, or unconfirmed user context.
- Monitoring items are clear: repeated sign-ins, token reuse, new mailbox rules, outbound sends, endpoint callbacks, app activity, and Azure changes.

# Cloudora CLD-0001 Dataset

Synthetic Microsoft Entra ID sign-in and audit logs, built for an identity
compromise investigation exercise. No real people, organisations, tenants, or
network addresses are represented.

Produced by `generate_cloudora_logs.py` using a fixed random seed, so the dataset
regenerates identically every time.

## Files

| File | Rows | Target table |
|---|---|---|
| `cloudora_signin_logs.csv` | 1,479 | `CloudoraSignIn_CL` |
| `cloudora_audit_logs.csv` | 51 | `CloudoraAudit_CL` |

## Scenario

Cloudora is a 150-person B2B HR software company based in London. The dataset
covers 8 days, from 2026-07-26 00:00 UTC to 2026-08-02 12:00 UTC. All timestamps
are UTC.

At 08:55 on 2026-08-02 the IT admin flags a sign-in on the CEO's account
(`daniel.reeve@cloudora.io`) that took place at 03:12 from an unexpected
location. The task is to confirm or dismiss the compromise, build the timeline,
find any persistence, and work out whether other accounts were affected.

The dataset also contains legitimate activity that will fire on a naive
detection query. Separating that from the real intrusion is part of the exercise.

## Sign-in log columns

| Column | Type | Notes |
|---|---|---|
| `TimeGenerated` | datetime | ISO 8601, UTC |
| `Id` | string | Unique sign-in event ID |
| `CorrelationId` | string | Links related events |
| `UserPrincipalName` | string | |
| `UserDisplayName` | string | |
| `UserId` | string | Entra object ID |
| `AppDisplayName` | string | Target application |
| `ClientAppUsed` | string | Browser, or Mobile Apps and Desktop clients |
| `IPAddress` | string | |
| `Location` | string | ISO 3166-1 alpha-2 country code |
| `Country` | string | Full country name |
| `City` | string | |
| `State` | string | |
| `AutonomousSystemNumber` | int | ASN of the source network |
| `NetworkISP` | string | |
| `DeviceOS` | string | |
| `DeviceBrowser` | string | |
| `UserAgent` | string | |
| `ResultType` | **string** | Entra result code. Must be ingested as string |
| `ResultDescription` | string | Empty on success |
| `ConditionalAccessStatus` | string | success, failure, or notApplied |
| `AuthenticationRequirement` | string | singleFactorAuthentication or multiFactorAuthentication |
| `MfaAuthMethod` | string | Empty where MFA was not performed |
| `RiskLevelDuringSignIn` | string | none, low, medium, high |
| `RiskState` | string | none, atRisk, dismissed, confirmedCompromised |
| `RiskEventTypes` | string | Comma-separated, may be empty |

### Result codes in this dataset

| Code | Meaning |
|---|---|
| `0` | Success |
| `50126` | Invalid username or password |
| `50074` | Strong authentication required |
| `50076` | MFA required by policy |
| `50140` | Keep me signed in interrupt |
| `50053` | Account locked after repeated failures |
| `53003` | Blocked by Conditional Access |

## Audit log columns

| Column | Type | Notes |
|---|---|---|
| `TimeGenerated` | datetime | |
| `Id`, `CorrelationId` | string | |
| `Category` | string | UserManagement, ApplicationManagement, RoleManagement, GroupManagement, DeviceManagement, MailboxConfiguration |
| `OperationName` | string | |
| `Result` | string | success or failure |
| `ResultReason` | string | Populated on failure |
| `InitiatedByUser` | string | |
| `InitiatedByIpAddress` | string | |
| `InitiatedByApp` | string | |
| `TargetResourceName` | string | |
| `TargetResourceType` | string | |
| `TargetUserPrincipalName` | string | |
| `ModifiedProperty` | string | |
| `OldValue`, `NewValue` | string | |

## Loading into Azure Data Explorer

1. At `dataexplorer.azure.com`, click **My cluster**, then **Create cluster**. The
   free tier is sufficient.
2. Create a database.
3. Right-click the database, then **Get data**, then **Local file**.
4. Set the table name to `CloudoraSignIn_CL`.
5. In the schema preview, confirm `TimeGenerated` is `datetime`, then click the
   `ResultType` column header and change its type to `string`.
6. Repeat for `cloudora_audit_logs.csv` into `CloudoraAudit_CL`.

### The ResultType problem

Entra result codes are all digits, so Azure Data Explorer will infer `long` for
that column. Nothing warns you about this. Queries such as
`where ResultType == "50126"` then return zero rows rather than an error, which
is easy to mistake for a data problem. Forcing the column to `string` during
ingestion avoids it. If you hit this after the fact, drop the table with
`.drop table CloudoraSignIn_CL` and load it again.

### Checks after loading

```kql
CloudoraSignIn_CL | count
// expect 1479

CloudoraSignIn_CL | where ResultType == "50126" | count
// expect 123. A result of 0 means ResultType was ingested as a number

CloudoraAudit_CL | count
// expect 51

CloudoraSignIn_CL
| summarize StartTime = min(TimeGenerated), EndTime = max(TimeGenerated)
// Azure Data Explorer has no global time picker, so every query needs its own
// time filter
```

## Regenerating the data

Run `generate_cloudora_logs.py` with Python 3.8 or later. It uses only the
standard library and takes a few seconds.

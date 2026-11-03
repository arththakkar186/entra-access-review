# Entra ID Access Review (Microsoft Graph + PowerShell)

A read-only PowerShell tool that produces an access review report from Microsoft Entra ID using the Microsoft Graph PowerShell SDK. Built to support SOX ITGC access reviews and joiner-mover-leaver clean-up.

## What it does

For every user in the tenant it reports:

- Account status (enabled or disabled) and user type (member or guest)
- Whether the account is licensed
- MFA registration state
- Last interactive sign-in and days since
- A **stale** flag for enabled accounts with no sign-in inside the threshold

Output is a timestamped CSV that a reviewer can hand straight to an auditor or use to drive account clean-up.

## Why it exists

Access reviews are often run by hand from exports that go out of date immediately. This pulls live data from Graph in one pass, builds an MFA lookup once instead of calling per user, and keeps everything read-only so it is safe to run against production.

## Usage

```powershell
# Install the modules once
Install-Module Microsoft.Graph.Authentication, Microsoft.Graph.Users, Microsoft.Graph.Reports -Scope CurrentUser

# Run a 60-day review with verbose output
.\Export-EntraAccessReview.ps1 -StaleDays 60 -Verbose

# Include guests and write to a specific path
.\Export-EntraAccessReview.ps1 -IncludeGuests -OutputPath C:\Reports\access-review.csv
```

## Permissions

Delegated, read-only scopes requested at run time:

- `User.Read.All`
- `AuditLog.Read.All`
- `UserAuthenticationMethod.Read.All`

Sign-in activity data requires an Entra ID P1 or P2 license.

## Notes

The script changes nothing in the tenant. It reads, reports, and disconnects.

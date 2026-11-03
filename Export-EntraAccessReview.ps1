<#
.SYNOPSIS
    Generates an Entra ID access review report for audit and governance.

.DESCRIPTION
    Connects to Microsoft Graph and exports a per-user access review of the
    tenant: account status, user type, licensing, last interactive sign-in,
    days since last sign-in, and multi-factor authentication registration
    state. Accounts that have not signed in within the staleness threshold
    are flagged so reviewers can action them during SOX ITGC access reviews
    or joiner-mover-leaver clean-up.

    Uses the Microsoft Graph PowerShell SDK (read-only scopes). Nothing is
    changed in the tenant; the script only reads and reports.

.PARAMETER StaleDays
    Number of days without an interactive sign-in before an enabled account
    is flagged as stale. Defaults to 90.

.PARAMETER OutputPath
    Path to the CSV report. Defaults to a timestamped file in the current
    directory.

.PARAMETER IncludeGuests
    Include B2B guest accounts in the report. Off by default.

.EXAMPLE
    .\Export-EntraAccessReview.ps1 -StaleDays 60 -Verbose

.EXAMPLE
    .\Export-EntraAccessReview.ps1 -IncludeGuests -OutputPath C:\Reports\access-review.csv

.NOTES
    Author : Arth Thakkar
    Scopes : User.Read.All, AuditLog.Read.All, UserAuthenticationMethod.Read.All
    Modules: Microsoft.Graph.Authentication, Microsoft.Graph.Users, Microsoft.Graph.Reports
    Graph sign-in activity requires an Entra ID P1 or P2 license.
#>

[CmdletBinding()]
param(
    [ValidateRange(1, 365)]
    [int]$StaleDays = 90,

    [string]$OutputPath = ".\EntraAccessReview_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv",

    [switch]$IncludeGuests
)

$ErrorActionPreference = 'Stop'

function Connect-Tenant {
    [CmdletBinding()]
    param([string[]]$Scopes)

    $context = Get-MgContext
    if (-not $context) {
        Write-Verbose "No existing Graph session. Connecting..."
        Connect-MgGraph -Scopes $Scopes -NoWelcome
    }
    else {
        $missing = $Scopes | Where-Object { $_ -notin $context.Scopes }
        if ($missing) {
            Write-Verbose "Reconnecting to add scopes: $($missing -join ', ')"
            Connect-MgGraph -Scopes $Scopes -NoWelcome
        }
    }
    Write-Verbose "Connected as $((Get-MgContext).Account)"
}

try {
    $requiredScopes = @(
        'User.Read.All'
        'AuditLog.Read.All'
        'UserAuthenticationMethod.Read.All'
    )
    Connect-Tenant -Scopes $requiredScopes

    # Build a lookup of MFA registration state so we do not call Graph per user.
    Write-Verbose "Retrieving authentication method registration details..."
    $mfaByUser = @{}
    Get-MgReportAuthenticationMethodUserRegistrationDetail -All |
        ForEach-Object { $mfaByUser[$_.Id] = $_.IsMfaRegistered }

    Write-Verbose "Retrieving users..."
    $userProperties = @(
        'Id', 'DisplayName', 'UserPrincipalName', 'AccountEnabled',
        'UserType', 'CreatedDateTime', 'AssignedLicenses', 'SignInActivity'
    )

    $users = Get-MgUser -All -Property $userProperties |
        Where-Object { $IncludeGuests -or $_.UserType -ne 'Guest' }

    $now = Get-Date
    $report = foreach ($user in $users) {
        $lastSignIn = $user.SignInActivity.LastSignInDateTime
        $daysSince = if ($lastSignIn) {
            [math]::Round(($now - $lastSignIn).TotalDays)
        } else {
            $null
        }

        $isStale = $user.AccountEnabled -and
                   ($null -eq $lastSignIn -or $daysSince -ge $StaleDays)

        [pscustomobject]@{
            DisplayName       = $user.DisplayName
            UserPrincipalName = $user.UserPrincipalName
            UserType          = $user.UserType
            AccountEnabled    = $user.AccountEnabled
            Licensed          = [bool]$user.AssignedLicenses.Count
            MfaRegistered     = [bool]$mfaByUser[$user.Id]
            CreatedDateTime   = $user.CreatedDateTime
            LastSignIn        = $lastSignIn
            DaysSinceSignIn   = $daysSince
            FlaggedStale      = $isStale
        }
    }

    $report |
        Sort-Object -Property FlaggedStale, DaysSinceSignIn -Descending |
        Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8

    $staleCount = ($report | Where-Object FlaggedStale).Count
    Write-Host "Access review complete." -ForegroundColor Green
    Write-Host "  Users reviewed : $($report.Count)"
    Write-Host "  Flagged stale  : $staleCount (no sign-in in $StaleDays+ days)"
    Write-Host "  Report         : $OutputPath"
}
catch {
    Write-Error "Access review failed: $($_.Exception.Message)"
    exit 1
}
finally {
    if (Get-MgContext) {
        Disconnect-MgGraph | Out-Null
        Write-Verbose "Disconnected from Microsoft Graph."
    }
}

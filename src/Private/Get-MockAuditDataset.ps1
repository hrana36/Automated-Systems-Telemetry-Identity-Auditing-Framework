function Get-MockAuditDataset {
    <#
    .SYNOPSIS
        Generates a realistic enterprise Microsoft Entra ID dataset for offline simulation and portfolio evaluation.
    #>
    [CmdletBinding()]
    param()

    $now = (Get-Date).ToUniversalTime()

    # 1. Directory Roles & Members
    $roles = @(
        [PSCustomObject]@{
            id          = "role-001"
            displayName = "Global Administrator"
            description = "Can manage all aspects of Microsoft Entra ID and Microsoft services."
            members     = @(
                [PSCustomObject]@{
                    id                = "usr-001"
                    userPrincipalName = "admin.corp@contoso.com"
                    displayName       = "Corporate BreakGlass Admin"
                    accountEnabled    = $true
                    signInActivity    = [PSCustomObject]@{
                        lastSignInDateTime = $now.AddDays(-120).ToString("o")
                    }
                    mfaEnrolled       = $true
                    isServiceAccount  = $false
                },
                [PSCustomObject]@{
                    id                = "usr-002"
                    userPrincipalName = "john.smith@contoso.com"
                    displayName       = "John Smith (SecOps)"
                    accountEnabled    = $true
                    signInActivity    = [PSCustomObject]@{
                        lastSignInDateTime = $now.AddDays(-2).ToString("o")
                    }
                    mfaEnrolled       = $true
                    isServiceAccount  = $false
                },
                [PSCustomObject]@{
                    id                = "usr-003"
                    userPrincipalName = "temp.consultant@contoso.com"
                    displayName       = "Temp External Consultant"
                    accountEnabled    = $true
                    signInActivity    = [PSCustomObject]@{
                        lastSignInDateTime = $now.AddDays(-65).ToString("o")
                    }
                    mfaEnrolled       = $false # High risk: No MFA on Global Admin!
                    isServiceAccount  = $false
                }
            )
        },
        [PSCustomObject]@{
            id          = "role-002"
            displayName = "Privileged Role Administrator"
            description = "Can manage role assignments in Microsoft Entra ID."
            members     = @(
                [PSCustomObject]@{
                    id                = "usr-004"
                    userPrincipalName = "legacy.sync@contoso.com"
                    displayName       = "Legacy Sync Service Account"
                    accountEnabled    = $true
                    signInActivity    = [PSCustomObject]@{
                        lastSignInDateTime = $now.AddDays(-180).ToString("o") # Inactive privileged account!
                    }
                    mfaEnrolled       = $false
                    isServiceAccount  = $true
                }
            )
        },
        [PSCustomObject]@{
            id          = "role-003"
            displayName = "Application Administrator"
            description = "Can create and manage all aspects of app registrations and enterprise apps."
            members     = @(
                [PSCustomObject]@{
                    id                = "usr-005"
                    userPrincipalName = "sarah.connor@contoso.com"
                    displayName       = "Sarah Connor (DevOps)"
                    accountEnabled    = $true
                    signInActivity    = [PSCustomObject]@{
                        lastSignInDateTime = $now.AddDays(-5).ToString("o")
                    }
                    mfaEnrolled       = $true
                    isServiceAccount  = $false
                }
            )
        }
    )

    # 2. Service Principals & Enterprise Applications
    $applications = @(
        [PSCustomObject]@{
            appId                = "app-001"
            displayName          = "Legacy ERP Integration Tool"
            createdDateTime      = $now.AddYears(-2).ToString("o")
            requiredResourceAccess = @(
                [PSCustomObject]@{
                    resourceAppId = "00000003-0000-0000-c000-000000000000" # Microsoft Graph
                    resourceAccess = @(
                        [PSCustomObject]@{ id = "1bfefb4e-e0b5-418b-a88f-73c46d2cc8e9"; type = "Role" }, # RoleManagement.ReadWrite.Directory (CRITICAL RISK)
                        [PSCustomObject]@{ id = "7ab1d382-f21e-4acd-a863-ba3e13f7da61"; type = "Role" }  # Directory.ReadWrite.All (HIGH RISK)
                    )
                }
            )
            passwordCredentials = @(
                [PSCustomObject]@{
                    keyId       = "sec-001"
                    displayName = "Production API Secret"
                    endDateTime = $now.AddYears(10).ToString("o") # Non-expiring / Excessive validity!
                }
            )
        },
        [PSCustomObject]@{
            appId                = "app-002"
            displayName          = "Cloud Expense Scanner"
            createdDateTime      = $now.AddMonths(-6).ToString("o")
            requiredResourceAccess = @(
                [PSCustomObject]@{
                    resourceAppId = "00000003-0000-0000-c000-000000000000"
                    resourceAccess = @(
                        [PSCustomObject]@{ id = "e1fe6dd8-ba31-4d61-89e7-88639da4683d"; type = "Role" } # User.Read.All
                    )
                }
            )
            passwordCredentials = @(
                [PSCustomObject]@{
                    keyId       = "sec-002"
                    displayName = "Scanner Secret"
                    endDateTime = $now.AddDays(-15).ToString("o") # Expired secret!
                }
            )
        },
        [PSCustomObject]@{
            appId                = "app-003"
            displayName          = "Automated Telemetry Collector"
            createdDateTime      = $now.AddMonths(-1).ToString("o")
            requiredResourceAccess = @(
                [PSCustomObject]@{
                    resourceAppId = "00000003-0000-0000-c000-000000000000"
                    resourceAccess = @(
                        [PSCustomObject]@{ id = "df0212de-b356-43ac-9324-2e655acf550b"; type = "Role" } # AuditLog.Read.All (Least privilege)
                    )
                }
            )
            passwordCredentials = @(
                [PSCustomObject]@{
                    keyId       = "sec-003"
                    displayName = "Auditor Cert Secret"
                    endDateTime = $now.AddDays(90).ToString("o")
                }
            )
        }
    )

    # 3. Directory Audit Logs (/auditLogs/directoryAudits)
    $auditLogs = @(
        [PSCustomObject]@{
            id                     = "audit-001"
            activityDateTime       = $now.AddHours(-3).ToString("o")
            activityDisplayName    = "Add member to role"
            category               = "RoleManagement"
            result                 = "success"
            initiatedBy            = [PSCustomObject]@{
                user = [PSCustomObject]@{
                    userPrincipalName = "temp.consultant@contoso.com"
                    ipAddress         = "198.51.100.45"
                }
            }
            targetResources        = @(
                [PSCustomObject]@{
                    displayName = "Global Administrator"
                    type        = "Role"
                    modifiedProperties = @(
                        [PSCustomObject]@{
                            displayName = "Role.DisplayName"
                            newValue    = '"Global Administrator"'
                        }
                    )
                }
            )
        },
        [PSCustomObject]@{
            id                     = "audit-002"
            activityDateTime       = $now.AddHours(-18).ToString("o")
            activityDisplayName    = "Consent to application"
            category               = "ApplicationManagement"
            result                 = "success"
            initiatedBy            = [PSCustomObject]@{
                user = [PSCustomObject]@{
                    userPrincipalName = "unknown.external@partner.com"
                    ipAddress         = "203.0.113.12"
                }
            }
            targetResources        = @(
                [PSCustomObject]@{
                    displayName = "Unverified MultiTenant Daemon"
                    type        = "Application"
                    modifiedProperties = @(
                        [PSCustomObject]@{
                            displayName = "ConsentType"
                            newValue    = '"AllPrincipals"'
                        }
                    )
                }
            )
        },
        [PSCustomObject]@{
            id                     = "audit-003"
            activityDateTime       = $now.AddHours(-48).ToString("o")
            activityDisplayName    = "Update user"
            category               = "UserManagement"
            result                 = "success"
            initiatedBy            = [PSCustomObject]@{
                user = [PSCustomObject]@{
                    userPrincipalName = "john.smith@contoso.com"
                    ipAddress         = "10.0.4.15"
                }
            }
            targetResources        = @(
                [PSCustomObject]@{
                    displayName = "john.smith@contoso.com"
                    type        = "User"
                }
            )
        }
    )

    return @{
        TenantId      = "72f988bf-86f1-41af-91ab-2d7cd011db47"
        TenantName    = "Contoso Global Enterprise (Simulated)"
        Roles         = $roles
        Applications  = $applications
        AuditLogs     = $auditLogs
        ExtractedAt   = $now.ToString("o")
    }
}

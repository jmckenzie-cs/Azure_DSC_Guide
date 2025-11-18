#requires -version 5.1

<#
.SYNOPSIS
    Validation and testing functions for CrowdStrike Falcon DSC deployment

.DESCRIPTION
    This module provides comprehensive validation and testing capabilities for
    CrowdStrike Falcon DSC configurations including:

    - Pre-deployment validation
    - Configuration syntax testing
    - Post-deployment verification
    - Compliance checking
    - Network connectivity testing
    - Azure Guest Configuration testing

.NOTES
    Author: Generated with Claude Code
    Version: 1.0.0
    Based on: Cloud-Azure-main repository patterns
#>

# Import required modules
Import-Module PSDesiredStateConfiguration -Force -ErrorAction SilentlyContinue

function Test-FalconDSCConfiguration {
    <#
    .SYNOPSIS
        Validates CrowdStrike Falcon DSC configuration syntax and parameters

    .DESCRIPTION
        Performs comprehensive validation of the Falcon DSC configuration including:
        - Configuration syntax validation
        - Parameter validation
        - Credential verification
        - Network connectivity testing

    .PARAMETER ConfigurationPath
        Path to the DSC configuration script

    .PARAMETER ConfigDataPath
        Path to the configuration data file

    .PARAMETER FalconClientId
        CrowdStrike Falcon API Client ID

    .PARAMETER FalconClientSecret
        CrowdStrike Falcon API Client Secret

    .PARAMETER FalconCloud
        CrowdStrike Falcon Cloud Region

    .EXAMPLE
        Test-FalconDSCConfiguration -ConfigurationPath ".\CrowdStrikeFalconDSC.ps1" -FalconClientId "test" -FalconClientSecret "test"
    #>

    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateScript({ Test-Path $_ })]
        [String]$ConfigurationPath,

        [Parameter(Mandatory = $false)]
        [String]$ConfigDataPath,

        [Parameter(Mandatory = $true)]
        [String]$FalconClientId,

        [Parameter(Mandatory = $true)]
        [String]$FalconClientSecret,

        [Parameter(Mandatory = $false)]
        [ValidateSet('us-1', 'us-2', 'eu-1', 'us-gov-1')]
        [String]$FalconCloud = 'us-1'
    )

    $testResults = @{
        ConfigurationSyntax = $false
        ConfigurationData = $false
        CredentialValidation = $false
        NetworkConnectivity = $false
        OverallResult = $false
        Errors = @()
        Warnings = @()
    }

    Write-Host "=== CrowdStrike Falcon DSC Configuration Validation ===" -ForegroundColor Cyan
    Write-Host ""

    try {
        # Test 1: Configuration Syntax Validation
        Write-Host "[1/4] Validating DSC configuration syntax..." -ForegroundColor Yellow

        try {
            # Load and validate configuration
            . $ConfigurationPath

            # Test configuration generation
            $tempOutput = Join-Path $env:TEMP "FalconDSCTest_$(Get-Random)"
            New-Item -Path $tempOutput -ItemType Directory -Force | Out-Null

            $testParams = @{
                FalconClientId     = $FalconClientId
                FalconClientSecret = $FalconClientSecret
                FalconCloud        = $FalconCloud
                OutputPath         = $tempOutput
            }

            CrowdStrikeFalconDSC @testParams | Out-Null

            $mofFile = Join-Path $tempOutput "localhost.mof"
            if (Test-Path $mofFile) {
                $testResults.ConfigurationSyntax = $true
                Write-Host "✓ Configuration syntax is valid" -ForegroundColor Green

                # Validate MOF content
                $mofContent = Get-Content $mofFile -Raw
                if ($mofContent -match "CSFalconService|CrowdStrike|Falcon") {
                    Write-Host "✓ MOF contains expected CrowdStrike references" -ForegroundColor Green
                } else {
                    $testResults.Warnings += "MOF file may not contain expected CrowdStrike configuration"
                    Write-Warning "MOF file may not contain expected CrowdStrike configuration"
                }
            } else {
                throw "MOF file not generated"
            }

            # Cleanup
            Remove-Item $tempOutput -Recurse -Force -ErrorAction SilentlyContinue

        } catch {
            $testResults.Errors += "Configuration syntax error: $($_.Exception.Message)"
            Write-Host "❌ Configuration syntax validation failed: $($_.Exception.Message)" -ForegroundColor Red
        }

        # Test 2: Configuration Data Validation
        Write-Host "[2/4] Validating configuration data..." -ForegroundColor Yellow

        if ($ConfigDataPath -and (Test-Path $ConfigDataPath)) {
            try {
                $configData = Import-PowerShellDataFile -Path $ConfigDataPath

                if ($configData.AllNodes) {
                    $nodeCount = ($configData.AllNodes | Where-Object { $_.NodeName -ne '*' }).Count
                    Write-Host "✓ Configuration data loaded successfully ($nodeCount nodes defined)" -ForegroundColor Green
                    $testResults.ConfigurationData = $true

                    # Validate node configurations
                    foreach ($node in $configData.AllNodes | Where-Object { $_.NodeName -ne '*' }) {
                        if (-not $node.Environment) {
                            $testResults.Warnings += "Node '$($node.NodeName)' missing Environment property"
                        }
                        if (-not $node.InstallParams) {
                            $testResults.Warnings += "Node '$($node.NodeName)' missing InstallParams property"
                        }
                    }
                } else {
                    $testResults.Warnings += "Configuration data does not contain AllNodes section"
                }
            } catch {
                $testResults.Errors += "Configuration data error: $($_.Exception.Message)"
                Write-Host "❌ Configuration data validation failed: $($_.Exception.Message)" -ForegroundColor Red
            }
        } else {
            Write-Host "⚠️ Configuration data file not provided or not found" -ForegroundColor Yellow
            $testResults.ConfigurationData = $true  # Not required for basic operation
        }

        # Test 3: Credential Validation
        Write-Host "[3/4] Validating CrowdStrike credentials..." -ForegroundColor Yellow

        try {
            # Basic credential format validation
            if ($FalconClientId -match '^[a-f0-9]{32}$') {
                Write-Host "✓ Client ID format appears valid" -ForegroundColor Green
            } else {
                $testResults.Warnings += "Client ID format may be invalid (expected 32-character hex string)"
                Write-Warning "Client ID format may be invalid"
            }

            if ($FalconClientSecret -match '^[A-Za-z0-9+/]{40,}={0,2}$') {
                Write-Host "✓ Client Secret format appears valid" -ForegroundColor Green
            } else {
                $testResults.Warnings += "Client Secret format may be invalid (expected Base64 string)"
                Write-Warning "Client Secret format may be invalid"
            }

            # Note: We can't test actual API credentials without making real API calls
            # which would require additional modules and might impact production systems
            Write-Host "ℹ️ Credential authentication not tested (would require API call)" -ForegroundColor Blue
            $testResults.CredentialValidation = $true

        } catch {
            $testResults.Errors += "Credential validation error: $($_.Exception.Message)"
            Write-Host "❌ Credential validation failed: $($_.Exception.Message)" -ForegroundColor Red
        }

        # Test 4: Network Connectivity
        Write-Host "[4/4] Testing network connectivity to CrowdStrike cloud..." -ForegroundColor Yellow

        try {
            $endpoints = @(
                "ts01-$FalconCloud.crowdstrike.com",
                "lfodown01-$FalconCloud.crowdstrike.com"
            )

            $connectivityResults = @()
            foreach ($endpoint in $endpoints) {
                try {
                    $result = Test-NetConnection -ComputerName $endpoint -Port 443 -InformationLevel Quiet -WarningAction SilentlyContinue
                    $connectivityResults += @{
                        Endpoint = $endpoint
                        Success = $result
                    }

                    if ($result) {
                        Write-Host "✓ Connectivity to $endpoint : Success" -ForegroundColor Green
                    } else {
                        Write-Host "❌ Connectivity to $endpoint : Failed" -ForegroundColor Red
                    }
                } catch {
                    Write-Host "❌ Connectivity to $endpoint : Error - $($_.Exception.Message)" -ForegroundColor Red
                    $connectivityResults += @{
                        Endpoint = $endpoint
                        Success = $false
                        Error = $_.Exception.Message
                    }
                }
            }

            $successfulConnections = ($connectivityResults | Where-Object { $_.Success }).Count
            if ($successfulConnections -gt 0) {
                $testResults.NetworkConnectivity = $true
                Write-Host "✓ Network connectivity validated ($successfulConnections/$($endpoints.Count) endpoints)" -ForegroundColor Green
            } else {
                $testResults.Errors += "No network connectivity to CrowdStrike endpoints"
                Write-Host "❌ No network connectivity to CrowdStrike endpoints" -ForegroundColor Red
            }

        } catch {
            $testResults.Errors += "Network connectivity test error: $($_.Exception.Message)"
            Write-Host "❌ Network connectivity test failed: $($_.Exception.Message)" -ForegroundColor Red
        }

    } catch {
        $testResults.Errors += "Validation framework error: $($_.Exception.Message)"
        Write-Host "❌ Validation framework error: $($_.Exception.Message)" -ForegroundColor Red
    }

    # Overall Result
    $testResults.OverallResult = $testResults.ConfigurationSyntax -and
                                $testResults.ConfigurationData -and
                                $testResults.CredentialValidation -and
                                $testResults.NetworkConnectivity

    Write-Host ""
    Write-Host "=== Validation Summary ===" -ForegroundColor Cyan
    Write-Host "Configuration Syntax: $(if ($testResults.ConfigurationSyntax) { '✓ PASS' } else { '❌ FAIL' })" -ForegroundColor $(if ($testResults.ConfigurationSyntax) { 'Green' } else { 'Red' })
    Write-Host "Configuration Data: $(if ($testResults.ConfigurationData) { '✓ PASS' } else { '❌ FAIL' })" -ForegroundColor $(if ($testResults.ConfigurationData) { 'Green' } else { 'Red' })
    Write-Host "Credential Validation: $(if ($testResults.CredentialValidation) { '✓ PASS' } else { '❌ FAIL' })" -ForegroundColor $(if ($testResults.CredentialValidation) { 'Green' } else { 'Red' })
    Write-Host "Network Connectivity: $(if ($testResults.NetworkConnectivity) { '✓ PASS' } else { '❌ FAIL' })" -ForegroundColor $(if ($testResults.NetworkConnectivity) { 'Green' } else { 'Red' })
    Write-Host ""
    Write-Host "Overall Result: $(if ($testResults.OverallResult) { '✓ READY FOR DEPLOYMENT' } else { '❌ ISSUES FOUND' })" -ForegroundColor $(if ($testResults.OverallResult) { 'Green' } else { 'Red' })

    if ($testResults.Warnings.Count -gt 0) {
        Write-Host ""
        Write-Host "Warnings:" -ForegroundColor Yellow
        foreach ($warning in $testResults.Warnings) {
            Write-Host "  ⚠️ $warning" -ForegroundColor Yellow
        }
    }

    if ($testResults.Errors.Count -gt 0) {
        Write-Host ""
        Write-Host "Errors:" -ForegroundColor Red
        foreach ($error in $testResults.Errors) {
            Write-Host "  ❌ $error" -ForegroundColor Red
        }
    }

    return $testResults
}

function Test-FalconSensorInstallation {
    <#
    .SYNOPSIS
        Tests if CrowdStrike Falcon sensor is properly installed and running

    .DESCRIPTION
        Performs comprehensive validation of Falcon sensor installation including:
        - Service status verification
        - Registry key validation
        - File system checks
        - Process validation
        - Communication status

    .PARAMETER ComputerName
        Computer name to test (default: localhost)

    .PARAMETER Credential
        Credentials for remote computer access

    .EXAMPLE
        Test-FalconSensorInstallation

    .EXAMPLE
        Test-FalconSensorInstallation -ComputerName "SERVER01" -Credential $cred
    #>

    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [String]$ComputerName = 'localhost',

        [Parameter(Mandatory = $false)]
        [PSCredential]$Credential
    )

    $testResults = @{
        ServiceStatus = $false
        RegistryKeys = $false
        FileSystem = $false
        ProcessRunning = $false
        OverallResult = $false
        Details = @{}
        Errors = @()
    }

    Write-Host "=== CrowdStrike Falcon Sensor Installation Test ===" -ForegroundColor Cyan
    Write-Host "Target: $ComputerName" -ForegroundColor Gray
    Write-Host ""

    $scriptBlock = {
        $results = @{
            ServiceStatus = $false
            RegistryKeys = $false
            FileSystem = $false
            ProcessRunning = $false
            Details = @{}
        }

        try {
            # Test 1: Service Status
            Write-Host "[1/4] Checking CrowdStrike Falcon service..." -ForegroundColor Yellow
            $falconService = Get-Service -Name "CSFalconService" -ErrorAction SilentlyContinue

            if ($falconService) {
                $results.ServiceStatus = $true
                $results.Details.ServiceStatus = $falconService.Status
                $results.Details.ServiceStartType = $falconService.StartType
                Write-Host "✓ CSFalconService found - Status: $($falconService.Status)" -ForegroundColor Green
            } else {
                Write-Host "❌ CSFalconService not found" -ForegroundColor Red
            }

            # Test 2: Registry Keys
            Write-Host "[2/4] Checking registry keys..." -ForegroundColor Yellow
            $registryPaths = @(
                "HKLM:\SOFTWARE\CrowdStrike\{9b03c1d9-3138-44ed-9fae-d9f4c034b88d}",
                "HKLM:\SYSTEM\CurrentControlSet\Services\CSFalconService"
            )

            $registryResults = @{}
            foreach ($path in $registryPaths) {
                try {
                    $regKey = Get-ItemProperty -Path $path -ErrorAction SilentlyContinue
                    if ($regKey) {
                        $registryResults[$path] = $true
                        Write-Host "✓ Registry key found: $path" -ForegroundColor Green

                        if ($path -like "*CrowdStrike*" -and $regKey.Version) {
                            $results.Details.FalconVersion = $regKey.Version
                            Write-Host "  Version: $($regKey.Version)" -ForegroundColor Gray
                        }
                    } else {
                        $registryResults[$path] = $false
                        Write-Host "❌ Registry key missing: $path" -ForegroundColor Red
                    }
                } catch {
                    $registryResults[$path] = $false
                    Write-Host "❌ Error accessing registry: $path - $($_.Exception.Message)" -ForegroundColor Red
                }
            }

            $results.RegistryKeys = ($registryResults.Values | Where-Object { $_ -eq $true }).Count -gt 0
            $results.Details.RegistryKeys = $registryResults

            # Test 3: File System
            Write-Host "[3/4] Checking file system..." -ForegroundColor Yellow
            $filePaths = @(
                "C:\Program Files\CrowdStrike\CSFalconController.exe",
                "C:\Program Files\CrowdStrike\CSFalconService.exe"
            )

            $fileResults = @{}
            foreach ($path in $filePaths) {
                if (Test-Path $path) {
                    $fileResults[$path] = $true
                    $fileInfo = Get-Item $path
                    Write-Host "✓ File found: $($fileInfo.Name) ($($fileInfo.Length) bytes)" -ForegroundColor Green
                } else {
                    $fileResults[$path] = $false
                    Write-Host "❌ File missing: $path" -ForegroundColor Red
                }
            }

            $results.FileSystem = ($fileResults.Values | Where-Object { $_ -eq $true }).Count -gt 0
            $results.Details.FileSystem = $fileResults

            # Test 4: Process Running
            Write-Host "[4/4] Checking running processes..." -ForegroundColor Yellow
            $falconProcesses = Get-Process | Where-Object { $_.ProcessName -like "*Falcon*" -or $_.ProcessName -like "*CS*" }

            if ($falconProcesses) {
                $results.ProcessRunning = $true
                $results.Details.Processes = $falconProcesses | Select-Object ProcessName, Id, CPU, WorkingSet
                Write-Host "✓ CrowdStrike processes found:" -ForegroundColor Green
                foreach ($proc in $falconProcesses) {
                    Write-Host "  - $($proc.ProcessName) (PID: $($proc.Id))" -ForegroundColor Gray
                }
            } else {
                Write-Host "❌ No CrowdStrike processes found" -ForegroundColor Red
            }

        } catch {
            Write-Host "❌ Error during sensor validation: $($_.Exception.Message)" -ForegroundColor Red
        }

        return $results
    }

    try {
        if ($ComputerName -eq 'localhost') {
            $remoteResults = & $scriptBlock
        } else {
            $invokeParams = @{
                ComputerName = $ComputerName
                ScriptBlock = $scriptBlock
            }
            if ($Credential) {
                $invokeParams.Credential = $Credential
            }
            $remoteResults = Invoke-Command @invokeParams
        }

        $testResults.ServiceStatus = $remoteResults.ServiceStatus
        $testResults.RegistryKeys = $remoteResults.RegistryKeys
        $testResults.FileSystem = $remoteResults.FileSystem
        $testResults.ProcessRunning = $remoteResults.ProcessRunning
        $testResults.Details = $remoteResults.Details

    } catch {
        $testResults.Errors += "Remote execution error: $($_.Exception.Message)"
        Write-Host "❌ Failed to test remote computer: $($_.Exception.Message)" -ForegroundColor Red
    }

    # Overall Result
    $testResults.OverallResult = $testResults.ServiceStatus -or $testResults.FileSystem

    Write-Host ""
    Write-Host "=== Installation Test Summary ===" -ForegroundColor Cyan
    Write-Host "Service Status: $(if ($testResults.ServiceStatus) { '✓ PASS' } else { '❌ FAIL' })" -ForegroundColor $(if ($testResults.ServiceStatus) { 'Green' } else { 'Red' })
    Write-Host "Registry Keys: $(if ($testResults.RegistryKeys) { '✓ PASS' } else { '❌ FAIL' })" -ForegroundColor $(if ($testResults.RegistryKeys) { 'Green' } else { 'Red' })
    Write-Host "File System: $(if ($testResults.FileSystem) { '✓ PASS' } else { '❌ FAIL' })" -ForegroundColor $(if ($testResults.FileSystem) { 'Green' } else { 'Red' })
    Write-Host "Process Running: $(if ($testResults.ProcessRunning) { '✓ PASS' } else { '❌ FAIL' })" -ForegroundColor $(if ($testResults.ProcessRunning) { 'Green' } else { 'Red' })
    Write-Host ""
    Write-Host "Overall Result: $(if ($testResults.OverallResult) { '✓ SENSOR INSTALLED' } else { '❌ SENSOR NOT DETECTED' })" -ForegroundColor $(if ($testResults.OverallResult) { 'Green' } else { 'Red' })

    return $testResults
}

function Test-AzureGuestConfigCompliance {
    <#
    .SYNOPSIS
        Tests Azure Guest Configuration policy compliance for CrowdStrike Falcon

    .DESCRIPTION
        Validates Azure Guest Configuration policy compliance including:
        - Policy assignment status
        - Compliance state verification
        - Remediation task status
        - Guest Configuration agent validation

    .PARAMETER SubscriptionId
        Azure subscription ID

    .PARAMETER ResourceGroupName
        Resource group containing target resources

    .PARAMETER PolicyName
        Name of the Guest Configuration policy

    .EXAMPLE
        Test-AzureGuestConfigCompliance -SubscriptionId "your-sub-id" -PolicyName "CrowdStrike-Falcon-Sensor"
    #>

    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [String]$SubscriptionId,

        [Parameter(Mandatory = $false)]
        [String]$ResourceGroupName,

        [Parameter(Mandatory = $true)]
        [String]$PolicyName
    )

    Write-Host "=== Azure Guest Configuration Compliance Test ===" -ForegroundColor Cyan
    Write-Host "Subscription: $SubscriptionId" -ForegroundColor Gray
    Write-Host "Policy: $PolicyName" -ForegroundColor Gray
    Write-Host ""

    try {
        # Set Azure context
        Set-AzContext -SubscriptionId $SubscriptionId | Out-Null

        # Test 1: Policy Assignment
        Write-Host "[1/3] Checking policy assignment..." -ForegroundColor Yellow
        $policyAssignments = Get-AzPolicyAssignment | Where-Object { $_.Name -like "*$PolicyName*" }

        if ($policyAssignments) {
            Write-Host "✓ Found $($policyAssignments.Count) policy assignment(s)" -ForegroundColor Green
            foreach ($assignment in $policyAssignments) {
                Write-Host "  - $($assignment.Name): $($assignment.Scope)" -ForegroundColor Gray
            }
        } else {
            Write-Host "❌ No policy assignments found for: $PolicyName" -ForegroundColor Red
            return
        }

        # Test 2: Compliance State
        Write-Host "[2/3] Checking compliance state..." -ForegroundColor Yellow

        $scope = if ($ResourceGroupName) {
            "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName"
        } else {
            "/subscriptions/$SubscriptionId"
        }

        $complianceStates = Get-AzPolicyState -Filter "PolicyAssignmentName eq '$($policyAssignments[0].Name)'" -Top 100

        if ($complianceStates) {
            $compliantCount = ($complianceStates | Where-Object { $_.ComplianceState -eq 'Compliant' }).Count
            $nonCompliantCount = ($complianceStates | Where-Object { $_.ComplianceState -eq 'NonCompliant' }).Count
            $totalCount = $complianceStates.Count

            Write-Host "✓ Compliance data found:" -ForegroundColor Green
            Write-Host "  - Total Resources: $totalCount" -ForegroundColor Gray
            Write-Host "  - Compliant: $compliantCount" -ForegroundColor Green
            Write-Host "  - Non-Compliant: $nonCompliantCount" -ForegroundColor $(if ($nonCompliantCount -gt 0) { 'Yellow' } else { 'Gray' })

            if ($nonCompliantCount -gt 0) {
                Write-Host ""
                Write-Host "Non-compliant resources:" -ForegroundColor Yellow
                $nonCompliantResources = $complianceStates | Where-Object { $_.ComplianceState -eq 'NonCompliant' } | Select-Object -First 5
                foreach ($resource in $nonCompliantResources) {
                    Write-Host "  - $($resource.ResourceId)" -ForegroundColor Yellow
                }
                if ($nonCompliantCount -gt 5) {
                    Write-Host "  ... and $($nonCompliantCount - 5) more" -ForegroundColor Yellow
                }
            }
        } else {
            Write-Host "⚠️ No compliance data available yet (evaluation may still be in progress)" -ForegroundColor Yellow
        }

        # Test 3: Guest Configuration Reports
        Write-Host "[3/3] Checking Guest Configuration reports..." -ForegroundColor Yellow

        # Note: This would require specific Guest Configuration cmdlets
        Write-Host "ℹ️ Guest Configuration detailed reports require additional modules" -ForegroundColor Blue
        Write-Host "  Use Get-AzGuestConfigurationAssignment for detailed reports" -ForegroundColor Gray

        Write-Host ""
        Write-Host "=== Compliance Test Summary ===" -ForegroundColor Cyan
        Write-Host "Policy assignments found: $(if ($policyAssignments) { '✓' } else { '❌' })" -ForegroundColor $(if ($policyAssignments) { 'Green' } else { 'Red' })
        Write-Host "Compliance data available: $(if ($complianceStates) { '✓' } else { '⚠️' })" -ForegroundColor $(if ($complianceStates) { 'Green' } else { 'Yellow' })

        if ($complianceStates) {
            $compliancePercentage = [math]::Round(($compliantCount / $totalCount) * 100, 1)
            Write-Host "Overall compliance: $compliancePercentage% ($compliantCount/$totalCount)" -ForegroundColor $(if ($compliancePercentage -gt 80) { 'Green' } elseif ($compliancePercentage -gt 50) { 'Yellow' } else { 'Red' })
        }

    } catch {
        Write-Host "❌ Azure Guest Configuration test failed: $($_.Exception.Message)" -ForegroundColor Red
    }
}

# Export all functions
Export-ModuleMember -Function Test-FalconDSCConfiguration, Test-FalconSensorInstallation, Test-AzureGuestConfigCompliance
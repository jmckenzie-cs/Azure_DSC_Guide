#requires -version 5.1
#requires -modules Az.Accounts, Az.Profile, Az.GuestConfiguration, Az.KeyVault

<#
.SYNOPSIS
    Deployment script for CrowdStrike Falcon sensor using Azure DSC Guest Configuration

.DESCRIPTION
    This script packages and deploys the CrowdStrike Falcon DSC configuration as an Azure
    Guest Configuration policy. It handles:

    - DSC package creation and validation
    - Azure Guest Configuration package upload
    - Policy definition creation
    - Policy assignment to Azure resources
    - Secure credential management via Azure Key Vault

.PARAMETER SubscriptionId
    Azure subscription ID where the policy will be deployed

.PARAMETER ResourceGroupName
    Resource group for storing Guest Configuration artifacts

.PARAMETER StorageAccountName
    Storage account for Guest Configuration packages

.PARAMETER KeyVaultName
    Key Vault containing CrowdStrike credentials

.PARAMETER FalconCloud
    CrowdStrike cloud region (us-1, us-2, eu-1, us-gov-1)

.PARAMETER PolicyName
    Name for the Guest Configuration policy

.PARAMETER Environment
    Target environment (Development, Staging, Production)

.PARAMETER AssignmentScope
    Scope for policy assignment (subscription, resource group, or specific resources)

.EXAMPLE
    .\Deploy-FalconGuestConfig.ps1 -SubscriptionId "your-sub-id" -ResourceGroupName "rg-falcon-guestconfig" -KeyVaultName "kv-falcon-creds" -FalconCloud "us-1"

.EXAMPLE
    # Deploy to specific resource group
    .\Deploy-FalconGuestConfig.ps1 -SubscriptionId "your-sub-id" -ResourceGroupName "rg-falcon-guestconfig" -KeyVaultName "kv-falcon-creds" -AssignmentScope "/subscriptions/your-sub-id/resourceGroups/rg-servers"

.NOTES
    Prerequisites:
    1. Az PowerShell modules installed
    2. Authenticated to Azure (Connect-AzAccount)
    3. Contributor access to target subscription/resources
    4. Key Vault with Falcon credentials stored as secrets:
       - falcon-client-id
       - falcon-client-secret
    5. Guest Configuration provider registered in subscription

    Author: Generated with Claude Code
    Version: 1.0.0
    Based on: Cloud-Azure-main repository patterns
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [String]$SubscriptionId,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [String]$ResourceGroupName,

    [Parameter(Mandatory = $false)]
    [String]$StorageAccountName = "stfalconguestconfig$(Get-Random -Maximum 9999)",

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [String]$KeyVaultName,

    [Parameter(Mandatory = $false)]
    [ValidateSet('us-1', 'us-2', 'eu-1', 'us-gov-1')]
    [String]$FalconCloud = 'us-1',

    [Parameter(Mandatory = $false)]
    [String]$PolicyName = "CrowdStrike-Falcon-Sensor-Deployment",

    [Parameter(Mandatory = $false)]
    [ValidateSet('Development', 'Staging', 'Production')]
    [String]$Environment = 'Production',

    [Parameter(Mandatory = $false)]
    [String]$AssignmentScope,

    [Parameter(Mandatory = $false)]
    [String]$Location = "East US",

    [Parameter(Mandatory = $false)]
    [Switch]$WhatIf
)

# Error handling
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

# Script paths
$ScriptRoot = $PSScriptRoot
$DSCConfigPath = Join-Path $ScriptRoot "CrowdStrikeFalconDSC.ps1"
$ConfigDataPath = Join-Path $ScriptRoot "FalconDSCConfigData.psd1"
$TempPath = Join-Path $env:TEMP "FalconGuestConfig"

Write-Host "=== CrowdStrike Falcon Azure Guest Configuration Deployment ===" -ForegroundColor Cyan
Write-Host "Subscription: $SubscriptionId" -ForegroundColor Gray
Write-Host "Resource Group: $ResourceGroupName" -ForegroundColor Gray
Write-Host "Key Vault: $KeyVaultName" -ForegroundColor Gray
Write-Host "Environment: $Environment" -ForegroundColor Gray
Write-Host "Falcon Cloud: $FalconCloud" -ForegroundColor Gray
Write-Host ""

try {
    # Step 1: Validate prerequisites
    Write-Host "[1/8] Validating prerequisites..." -ForegroundColor Yellow

    # Check if DSC configuration file exists
    if (-not (Test-Path $DSCConfigPath)) {
        throw "DSC configuration file not found: $DSCConfigPath"
    }

    # Check Azure connection
    $azContext = Get-AzContext -ErrorAction SilentlyContinue
    if (-not $azContext) {
        Write-Host "Not connected to Azure. Please run Connect-AzAccount first." -ForegroundColor Red
        exit 1
    }

    # Set subscription context
    Set-AzContext -SubscriptionId $SubscriptionId | Out-Null
    Write-Host "✓ Connected to subscription: $((Get-AzContext).Subscription.Name)" -ForegroundColor Green

    # Check for required modules
    $requiredModules = @('Az.GuestConfiguration', 'Az.Storage', 'Az.KeyVault', 'Az.Resources')
    foreach ($module in $requiredModules) {
        if (-not (Get-Module -Name $module -ListAvailable)) {
            throw "Required module not installed: $module. Please run 'Install-Module $module -Force'"
        }
    }
    Write-Host "✓ Required modules available" -ForegroundColor Green

    # Step 2: Create temporary working directory
    Write-Host "[2/8] Setting up working directory..." -ForegroundColor Yellow
    if (Test-Path $TempPath) {
        Remove-Item $TempPath -Recurse -Force
    }
    New-Item -Path $TempPath -ItemType Directory -Force | Out-Null
    Write-Host "✓ Working directory created: $TempPath" -ForegroundColor Green

    # Step 3: Retrieve credentials from Key Vault
    Write-Host "[3/8] Retrieving credentials from Key Vault..." -ForegroundColor Yellow

    try {
        $falconClientIdSecret = Get-AzKeyVaultSecret -VaultName $KeyVaultName -Name "falcon-client-id" -AsPlainText
        $falconClientSecretSecret = Get-AzKeyVaultSecret -VaultName $KeyVaultName -Name "falcon-client-secret" -AsPlainText

        if (-not $falconClientIdSecret -or -not $falconClientSecretSecret) {
            throw "Falcon credentials not found in Key Vault. Ensure 'falcon-client-id' and 'falcon-client-secret' secrets exist."
        }
        Write-Host "✓ Credentials retrieved from Key Vault" -ForegroundColor Green
    }
    catch {
        throw "Failed to retrieve credentials from Key Vault '$KeyVaultName': $($_.Exception.Message)"
    }

    # Step 4: Create resource group and storage account
    Write-Host "[4/8] Setting up Azure resources..." -ForegroundColor Yellow

    # Create resource group if it doesn't exist
    $rg = Get-AzResourceGroup -Name $ResourceGroupName -ErrorAction SilentlyContinue
    if (-not $rg) {
        if ($WhatIf) {
            Write-Host "WHATIF: Would create resource group: $ResourceGroupName" -ForegroundColor Magenta
        } else {
            $rg = New-AzResourceGroup -Name $ResourceGroupName -Location $Location
            Write-Host "✓ Created resource group: $ResourceGroupName" -ForegroundColor Green
        }
    } else {
        Write-Host "✓ Using existing resource group: $ResourceGroupName" -ForegroundColor Green
    }

    # Create storage account for Guest Configuration packages
    $storageAccount = Get-AzStorageAccount -ResourceGroupName $ResourceGroupName -Name $StorageAccountName -ErrorAction SilentlyContinue
    if (-not $storageAccount) {
        if ($WhatIf) {
            Write-Host "WHATIF: Would create storage account: $StorageAccountName" -ForegroundColor Magenta
        } else {
            $storageAccount = New-AzStorageAccount -ResourceGroupName $ResourceGroupName -Name $StorageAccountName -Location $Location -SkuName "Standard_LRS" -Kind "StorageV2"
            Write-Host "✓ Created storage account: $StorageAccountName" -ForegroundColor Green
        }
    } else {
        Write-Host "✓ Using existing storage account: $StorageAccountName" -ForegroundColor Green
    }

    # Step 5: Generate DSC configuration
    Write-Host "[5/8] Generating DSC configuration..." -ForegroundColor Yellow

    # Load the DSC configuration
    . $DSCConfigPath

    # Create configuration with credentials
    $configOutputPath = Join-Path $TempPath "DSCConfig"
    New-Item -Path $configOutputPath -ItemType Directory -Force | Out-Null

    # Load configuration data
    $configData = Import-PowerShellDataFile -Path $ConfigDataPath

    # Generate MOF for localhost (Guest Configuration uses localhost)
    $dscParams = @{
        FalconClientId     = $falconClientIdSecret
        FalconClientSecret = $falconClientSecretSecret
        FalconCloud        = $FalconCloud
        OutputPath         = $configOutputPath
    }

    # Add environment-specific parameters
    $envNode = $configData.AllNodes | Where-Object { $_.Environment -eq $Environment -and $_.NodeName -ne '*' } | Select-Object -First 1
    if ($envNode) {
        if ($envNode.InstallParams) { $dscParams['InstallParams'] = $envNode.InstallParams }
        if ($envNode.SensorTags) { $dscParams['SensorTags'] = $envNode.SensorTags }
    }

    Write-Host "Generating configuration with parameters:" -ForegroundColor Gray
    Write-Host "  - Falcon Cloud: $FalconCloud" -ForegroundColor Gray
    Write-Host "  - Environment: $Environment" -ForegroundColor Gray
    Write-Host "  - Install Params: $($dscParams.InstallParams)" -ForegroundColor Gray
    Write-Host "  - Sensor Tags: $($dscParams.SensorTags)" -ForegroundColor Gray

    if ($WhatIf) {
        Write-Host "WHATIF: Would generate DSC configuration MOF" -ForegroundColor Magenta
    } else {
        CrowdStrikeFalconDSC @dscParams
        Write-Host "✓ DSC configuration generated" -ForegroundColor Green
    }

    # Step 6: Create Guest Configuration package
    Write-Host "[6/8] Creating Guest Configuration package..." -ForegroundColor Yellow

    $packageName = "CrowdStrikeFalcon$Environment"
    $packageVersion = "1.0.$(Get-Date -Format 'yyyyMMdd')"
    $packagePath = Join-Path $TempPath "$packageName.zip"

    if ($WhatIf) {
        Write-Host "WHATIF: Would create Guest Configuration package: $packageName" -ForegroundColor Magenta
    } else {
        # Create the Guest Configuration package
        $mofPath = Join-Path $configOutputPath "localhost.mof"

        if (-not (Test-Path $mofPath)) {
            throw "MOF file not found: $mofPath"
        }

        # Create package using New-GuestConfigurationPackage
        $packageParams = @{
            Name          = $packageName
            Configuration = $mofPath
            Path          = $TempPath
            Version       = $packageVersion
            Type          = 'AuditAndSet'  # This ensures remediation capability
        }

        $package = New-GuestConfigurationPackage @packageParams
        Write-Host "✓ Guest Configuration package created: $($package.Path)" -ForegroundColor Green
    }

    # Step 7: Upload package and create policy
    Write-Host "[7/8] Publishing Guest Configuration policy..." -ForegroundColor Yellow

    if ($WhatIf) {
        Write-Host "WHATIF: Would upload package and create policy definition" -ForegroundColor Magenta
    } else {
        # Upload package to storage and create policy
        $policyParams = @{
            PackagePath      = $package.Path
            ResourceGroupName = $ResourceGroupName
            StorageAccountName = $StorageAccountName
        }

        # Publish the Guest Configuration policy
        $policy = Publish-GuestConfigurationPackage @policyParams
        Write-Host "✓ Policy definition created: $($policy.PolicyId)" -ForegroundColor Green

        # Create policy assignment
        if (-not $AssignmentScope) {
            $AssignmentScope = "/subscriptions/$SubscriptionId"
        }

        $assignmentName = "$PolicyName-Assignment-$Environment"
        $assignmentParams = @{
            Name               = $assignmentName
            PolicyDefinitionId = $policy.PolicyId
            Scope              = $AssignmentScope
            Location           = $Location
        }

        # Add managed identity for remediation
        $assignmentParams['IdentityType'] = 'SystemAssigned'

        $assignment = New-AzPolicyAssignment @assignmentParams
        Write-Host "✓ Policy assigned to scope: $AssignmentScope" -ForegroundColor Green
        Write-Host "  Assignment Name: $assignmentName" -ForegroundColor Gray
    }

    # Step 8: Validation and next steps
    Write-Host "[8/8] Deployment completed successfully!" -ForegroundColor Yellow

    Write-Host ""
    Write-Host "=== Deployment Summary ===" -ForegroundColor Cyan
    if (-not $WhatIf) {
        Write-Host "Policy Definition ID: $($policy.PolicyId)" -ForegroundColor White
        Write-Host "Policy Assignment: $assignmentName" -ForegroundColor White
        Write-Host "Assignment Scope: $AssignmentScope" -ForegroundColor White
        Write-Host "Package Version: $packageVersion" -ForegroundColor White
    }
    Write-Host ""
    Write-Host "Next Steps:" -ForegroundColor Yellow
    Write-Host "1. Policy evaluation may take 15-30 minutes to begin" -ForegroundColor Gray
    Write-Host "2. Monitor compliance in Azure Policy portal" -ForegroundColor Gray
    Write-Host "3. Use remediation tasks for non-compliant resources" -ForegroundColor Gray
    Write-Host "4. Check CrowdStrike Falcon console for new sensors" -ForegroundColor Gray
    Write-Host ""

    if (-not $WhatIf) {
        Write-Host "Azure Portal Links:" -ForegroundColor Yellow
        Write-Host "Policy Compliance: https://portal.azure.com/#blade/Microsoft_Azure_Policy/PolicyMenuBlade/Compliance" -ForegroundColor Blue
        Write-Host "Guest Configuration: https://portal.azure.com/#blade/Microsoft_Azure_Policy/PolicyMenuBlade/GuestConfiguration" -ForegroundColor Blue
    }

} catch {
    Write-Host ""
    Write-Host "❌ Deployment failed: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host ""
    Write-Host "Troubleshooting tips:" -ForegroundColor Yellow
    Write-Host "1. Verify Azure permissions (Contributor role required)" -ForegroundColor Gray
    Write-Host "2. Check Key Vault access and secret names" -ForegroundColor Gray
    Write-Host "3. Ensure Guest Configuration provider is registered" -ForegroundColor Gray
    Write-Host "4. Validate DSC configuration syntax" -ForegroundColor Gray

    exit 1
} finally {
    # Cleanup temporary files
    if (Test-Path $TempPath) {
        Remove-Item $TempPath -Recurse -Force -ErrorAction SilentlyContinue
    }
}

# Helper function to validate Guest Configuration prerequisites
function Test-GuestConfigurationPrerequisites {
    param([string]$SubscriptionId)

    Write-Host "Validating Guest Configuration prerequisites..." -ForegroundColor Yellow

    # Check if Guest Configuration provider is registered
    $gcProvider = Get-AzResourceProvider -ProviderNamespace "Microsoft.GuestConfiguration" |
                  Where-Object { $_.RegistrationState -eq "Registered" }

    if (-not $gcProvider) {
        Write-Warning "Microsoft.GuestConfiguration provider not registered. Registering now..."
        Register-AzResourceProvider -ProviderNamespace "Microsoft.GuestConfiguration"
        Write-Host "✓ Guest Configuration provider registered" -ForegroundColor Green
    } else {
        Write-Host "✓ Guest Configuration provider is registered" -ForegroundColor Green
    }
}

# Call prerequisite validation
if (-not $WhatIf) {
    Test-GuestConfigurationPrerequisites -SubscriptionId $SubscriptionId
}
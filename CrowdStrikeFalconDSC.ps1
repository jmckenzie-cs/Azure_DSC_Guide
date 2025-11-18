#requires -version 5.1
#requires -modules PSDesiredStateConfiguration

<#
.SYNOPSIS
    PowerShell DSC Configuration for CrowdStrike Falcon Sensor deployment

.DESCRIPTION
    This DSC configuration script deploys the CrowdStrike Falcon sensor using the official
    installation scripts from CrowdStrike's GitHub repository. It supports both regular
    PowerShell DSC and Azure DSC Guest Configuration scenarios.

    Based on deployment patterns from Cloud-Azure-main repository:
    - Uses official falcon_windows_install.ps1 script
    - Supports secure credential handling
    - Includes validation and compliance checking
    - Compatible with Azure Policy Guest Configuration

.PARAMETER FalconClientId
    CrowdStrike Falcon API Client ID (secure string)

.PARAMETER FalconClientSecret
    CrowdStrike Falcon API Client Secret (secure string)

.PARAMETER FalconCloud
    CrowdStrike Falcon Cloud Region (us-1, us-2, eu-1, us-gov-1)

.PARAMETER InstallParams
    Additional installation parameters (e.g., "/install /quiet /norestart")

.PARAMETER SensorTags
    Optional sensor grouping tags for organization

.PARAMETER EnableLogging
    Enable detailed installation logging

.EXAMPLE
    # Basic configuration
    CrowdStrikeFalconDSC -FalconClientId "your-client-id" -FalconClientSecret "your-secret" -FalconCloud "us-1"

.EXAMPLE
    # Configuration with custom parameters
    CrowdStrikeFalconDSC -FalconClientId "your-client-id" -FalconClientSecret "your-secret" -FalconCloud "us-1" -InstallParams "/install /quiet /norestart NO_START=1" -SensorTags "Production,WebServers"

.NOTES
    Author: Generated with Claude Code
    Version: 1.0.0
    Compatible with: Windows Server 2016+, Windows 10+
    DSC Version: 5.1+

    Security considerations:
    - Credentials should be encrypted or stored securely
    - Use Azure Key Vault integration for production deployments
    - Validate network connectivity to CrowdStrike cloud before deployment
#>

Configuration CrowdStrikeFalconDSC
{
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [String]$FalconClientId,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [String]$FalconClientSecret,

        [Parameter(Mandatory = $false)]
        [ValidateSet('us-1', 'us-2', 'eu-1', 'us-gov-1')]
        [String]$FalconCloud = 'us-1',

        [Parameter(Mandatory = $false)]
        [String]$InstallParams = '/install /quiet /norestart',

        [Parameter(Mandatory = $false)]
        [String]$SensorTags = '',

        [Parameter(Mandatory = $false)]
        [Bool]$EnableLogging = $true,

        [Parameter(Mandatory = $false)]
        [String]$TempPath = $env:TEMP
    )

    # Import required DSC resources
    Import-DscResource -ModuleName PSDesiredStateConfiguration

    Node localhost
    {
        # Ensure TLS 1.2 is available for script downloads
        Registry EnableTLS12
        {
            Key       = 'HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319'
            ValueName = 'SchUseStrongCrypto'
            ValueData = '1'
            ValueType = 'Dword'
            Ensure    = 'Present'
        }

        Registry EnableTLS12Wow64
        {
            Key       = 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v4.0.30319'
            ValueName = 'SchUseStrongCrypto'
            ValueData = '1'
            ValueType = 'Dword'
            Ensure    = 'Present'
        }

        # Create logging directory if logging is enabled
        if ($EnableLogging)
        {
            File FalconLogDirectory
            {
                DestinationPath = "C:\Windows\Temp\FalconDSC"
                Type            = 'Directory'
                Ensure          = 'Present'
            }
        }

        # Download the CrowdStrike installation script
        Script DownloadFalconScript
        {
            DependsOn  = '[Registry]EnableTLS12'
            GetScript  = {
                $scriptPath = Join-Path $using:TempPath 'falcon_windows_install.ps1'
                @{
                    GetScript  = $GetScript
                    SetScript  = $SetScript
                    TestScript = $TestScript
                    Result     = (Test-Path $scriptPath)
                }
            }
            SetScript  = {
                $scriptUrl = 'https://raw.githubusercontent.com/CrowdStrike/falcon-scripts/main/powershell/install/falcon_windows_install.ps1'
                $scriptPath = Join-Path $using:TempPath 'falcon_windows_install.ps1'

                try {
                    Write-Verbose "Downloading CrowdStrike Falcon installation script from: $scriptUrl"
                    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

                    # Download with retry logic
                    $maxRetries = 3
                    $retryCount = 0
                    $downloaded = $false

                    while (-not $downloaded -and $retryCount -lt $maxRetries) {
                        try {
                            Invoke-WebRequest -Uri $scriptUrl -OutFile $scriptPath -UseBasicParsing -ErrorAction Stop
                            $downloaded = $true
                            Write-Verbose "Script downloaded successfully to: $scriptPath"
                        }
                        catch {
                            $retryCount++
                            Write-Warning "Download attempt $retryCount failed: $($_.Exception.Message)"
                            if ($retryCount -lt $maxRetries) {
                                Start-Sleep -Seconds (5 * $retryCount)
                            }
                        }
                    }

                    if (-not $downloaded) {
                        throw "Failed to download installation script after $maxRetries attempts"
                    }

                    # Verify script was downloaded and has content
                    if (-not (Test-Path $scriptPath) -or (Get-Item $scriptPath).Length -eq 0) {
                        throw "Downloaded script is empty or not found"
                    }
                }
                catch {
                    $errorMsg = "Failed to download CrowdStrike installation script: $($_.Exception.Message)"
                    Write-Error $errorMsg
                    if ($using:EnableLogging) {
                        $errorMsg | Out-File -FilePath "C:\Windows\Temp\FalconDSC\download_error.log" -Append
                    }
                    throw
                }
            }
            TestScript = {
                $scriptPath = Join-Path $using:TempPath 'falcon_windows_install.ps1'
                $exists = Test-Path $scriptPath

                if ($exists) {
                    # Check if script is recent (less than 24 hours old) and has content
                    $scriptFile = Get-Item $scriptPath
                    $isRecent = (Get-Date) - $scriptFile.LastWriteTime -lt (New-TimeSpan -Hours 24)
                    $hasContent = $scriptFile.Length -gt 0

                    return $isRecent -and $hasContent
                }

                return $false
            }
        }

        # Install CrowdStrike Falcon Sensor
        Script InstallFalconSensor
        {
            DependsOn  = '[Script]DownloadFalconScript'
            GetScript  = {
                # Check if Falcon is installed by looking for the service and registry
                $falconService = Get-Service -Name "CSFalconService" -ErrorAction SilentlyContinue
                $falconRegistry = Get-ItemProperty -Path "HKLM:\SOFTWARE\CrowdStrike\{9b03c1d9-3138-44ed-9fae-d9f4c034b88d}" -ErrorAction SilentlyContinue

                $isInstalled = ($null -ne $falconService) -and ($null -ne $falconRegistry)
                $version = if ($falconRegistry) { $falconRegistry.Version } else { "Not installed" }

                @{
                    GetScript  = $GetScript
                    SetScript  = $SetScript
                    TestScript = $TestScript
                    Result     = @{
                        Installed = $isInstalled
                        Version   = $version
                        Service   = if ($falconService) { $falconService.Status } else { "Not found" }
                    }
                }
            }
            SetScript  = {
                $scriptPath = Join-Path $using:TempPath 'falcon_windows_install.ps1'
                $logPath = if ($using:EnableLogging) { "C:\Windows\Temp\FalconDSC\falcon_install.log" } else { $null }

                try {
                    if ($using:EnableLogging) {
                        Start-Transcript -Path $logPath -Append
                        Write-Host "Starting CrowdStrike Falcon installation..."
                        Write-Host "Timestamp: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
                        Write-Host "Script Path: $scriptPath"
                        Write-Host "Falcon Cloud: $using:FalconCloud"
                        Write-Host "Install Parameters: $using:InstallParams"
                        if ($using:SensorTags) {
                            Write-Host "Sensor Tags: $using:SensorTags"
                        }
                    }

                    # Validate script exists
                    if (-not (Test-Path $scriptPath)) {
                        throw "Installation script not found at: $scriptPath"
                    }

                    # Prepare installation parameters
                    $installArgs = @{
                        FalconClientId     = $using:FalconClientId
                        FalconClientSecret = $using:FalconClientSecret
                        FalconCloud        = $using:FalconCloud
                        Verbose           = $true
                    }

                    # Add optional parameters
                    if ($using:InstallParams) {
                        $installArgs['InstallParams'] = $using:InstallParams
                    }

                    if ($using:SensorTags) {
                        $installArgs['SensorTags'] = $using:SensorTags
                    }

                    Write-Verbose "Executing CrowdStrike Falcon installation script..."

                    # Execute the installation script
                    & $scriptPath @installArgs

                    # Wait for service to be available
                    $timeout = 120 # 2 minutes
                    $timer = 0
                    do {
                        Start-Sleep -Seconds 5
                        $timer += 5
                        $service = Get-Service -Name "CSFalconService" -ErrorAction SilentlyContinue
                    } while ($null -eq $service -and $timer -lt $timeout)

                    if ($null -eq $service) {
                        Write-Warning "CSFalconService not found after installation. This may be normal for NO_START installations."
                    } else {
                        Write-Host "CrowdStrike Falcon service status: $($service.Status)"
                    }

                    if ($using:EnableLogging) {
                        Write-Host "CrowdStrike Falcon installation completed successfully"
                        Write-Host "Timestamp: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
                        Stop-Transcript
                    }
                }
                catch {
                    $errorMsg = "CrowdStrike Falcon installation failed: $($_.Exception.Message)"
                    Write-Error $errorMsg

                    if ($using:EnableLogging) {
                        $errorMsg | Out-File -FilePath "C:\Windows\Temp\FalconDSC\install_error.log" -Append
                        if (Get-Command Stop-Transcript -ErrorAction SilentlyContinue) {
                            Stop-Transcript
                        }
                    }
                    throw
                }
            }
            TestScript = {
                # Test if CrowdStrike Falcon is properly installed and configured
                try {
                    # Check for Falcon service
                    $falconService = Get-Service -Name "CSFalconService" -ErrorAction SilentlyContinue

                    # Check for Falcon registry entries
                    $falconRegistry = Get-ItemProperty -Path "HKLM:\SOFTWARE\CrowdStrike\{9b03c1d9-3138-44ed-9fae-d9f4c034b88d}" -ErrorAction SilentlyContinue

                    # Check for Falcon executable
                    $falconExe = Test-Path "C:\Program Files\CrowdStrike\CSFalconController.exe"

                    # For NO_START installations, service might not exist but files should
                    if ($using:InstallParams -match "NO_START") {
                        # For golden image scenarios, just check if files exist
                        $isInstalled = $falconExe -and ($null -ne $falconRegistry)
                        Write-Verbose "NO_START installation detected. Checking files only: $isInstalled"
                        return $isInstalled
                    } else {
                        # For normal installations, check service and files
                        $isInstalled = ($null -ne $falconService) -and $falconExe -and ($null -ne $falconRegistry)
                        Write-Verbose "Standard installation check. Service: $(if ($falconService) { 'Present' } else { 'Missing' }), Exe: $falconExe, Registry: $(if ($falconRegistry) { 'Present' } else { 'Missing' })"
                        return $isInstalled
                    }
                }
                catch {
                    Write-Verbose "Error checking Falcon installation status: $($_.Exception.Message)"
                    return $false
                }
            }
        }

        # Validate network connectivity to CrowdStrike cloud (optional validation)
        Script ValidateConnectivity
        {
            DependsOn  = '[Script]InstallFalconSensor'
            GetScript  = {
                @{
                    GetScript  = $GetScript
                    SetScript  = $SetScript
                    TestScript = $TestScript
                    Result     = "Connectivity validation"
                }
            }
            SetScript  = {
                # This is informational only - log connectivity status
                $endpoints = @(
                    "ts01-$using:FalconCloud.crowdstrike.com",
                    "lfodown01-$using:FalconCloud.crowdstrike.com"
                )

                foreach ($endpoint in $endpoints) {
                    try {
                        $result = Test-NetConnection -ComputerName $endpoint -Port 443 -InformationLevel Quiet
                        $status = if ($result) { "Success" } else { "Failed" }
                        Write-Verbose "Connectivity to $endpoint : $status"

                        if ($using:EnableLogging) {
                            "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') - Connectivity to $endpoint : $status" |
                                Out-File -FilePath "C:\Windows\Temp\FalconDSC\connectivity.log" -Append
                        }
                    }
                    catch {
                        Write-Verbose "Error testing connectivity to $endpoint : $($_.Exception.Message)"
                    }
                }
            }
            TestScript = {
                # Always return true as this is just informational validation
                return $true
            }
        }
    }
}

# Helper function to create configuration data for different environments
function New-FalconDSCConfigurationData {
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet('Development', 'Staging', 'Production')]
        [String]$Environment,

        [Parameter(Mandatory = $false)]
        [String[]]$NodeNames = @('localhost')
    )

    $baseConfig = @{
        AllNodes = @(
            @{
                NodeName = '*'
                PSDscAllowPlainTextPassword = $false
                PSDscAllowDomainUser = $true
            }
        )
    }

    # Add environment-specific settings
    switch ($Environment) {
        'Development' {
            $envConfig = @{
                InstallParams = '/install /quiet /norestart NO_START=1'
                SensorTags = 'Development,NonProd'
                EnableLogging = $true
            }
        }
        'Staging' {
            $envConfig = @{
                InstallParams = '/install /quiet /norestart'
                SensorTags = 'Staging,NonProd'
                EnableLogging = $true
            }
        }
        'Production' {
            $envConfig = @{
                InstallParams = '/install /quiet /norestart'
                SensorTags = 'Production'
                EnableLogging = $true
            }
        }
    }

    # Add nodes with environment configuration
    foreach ($nodeName in $NodeNames) {
        $nodeConfig = @{
            NodeName = $nodeName
        }

        # Merge environment config
        foreach ($key in $envConfig.Keys) {
            $nodeConfig[$key] = $envConfig[$key]
        }

        $baseConfig.AllNodes += $nodeConfig
    }

    return $baseConfig
}

# Export functions for module use
Export-ModuleMember -Function CrowdStrikeFalconDSC, New-FalconDSCConfigurationData
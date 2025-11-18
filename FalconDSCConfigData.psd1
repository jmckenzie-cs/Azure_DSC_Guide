# Configuration Data for CrowdStrike Falcon DSC Deployment
# This file contains environment-specific settings and secure credential management examples

@{
    AllNodes = @(
        @{
            # Global settings applied to all nodes
            NodeName = '*'

            # Security settings
            PSDscAllowPlainTextPassword = $false
            PSDscAllowDomainUser = $true

            # Common Falcon settings
            FalconCloud = 'us-1'  # Change as needed: us-1, us-2, eu-1, us-gov-1
            EnableLogging = $true
            TempPath = $env:TEMP

            # Certificate thumbprint for credential encryption (replace with your certificate)
            # CertificateFile = "C:\Certificates\DSCEncryption.cer"
            # Thumbprint = "YOUR_CERTIFICATE_THUMBPRINT_HERE"
        }

        # Development Environment Nodes
        @{
            NodeName = 'DEV-WEB01'
            Environment = 'Development'
            InstallParams = '/install /quiet /norestart NO_START=1'  # Golden image mode
            SensorTags = 'Development,WebServer,NonProd'
            Role = 'WebServer'
        }

        @{
            NodeName = 'DEV-DB01'
            Environment = 'Development'
            InstallParams = '/install /quiet /norestart NO_START=1'
            SensorTags = 'Development,Database,NonProd'
            Role = 'Database'
        }

        # Staging Environment Nodes
        @{
            NodeName = 'STAGE-WEB01'
            Environment = 'Staging'
            InstallParams = '/install /quiet /norestart'
            SensorTags = 'Staging,WebServer,NonProd'
            Role = 'WebServer'
        }

        @{
            NodeName = 'STAGE-DB01'
            Environment = 'Staging'
            InstallParams = '/install /quiet /norestart'
            SensorTags = 'Staging,Database,NonProd'
            Role = 'Database'
        }

        # Production Environment Nodes
        @{
            NodeName = 'PROD-WEB01'
            Environment = 'Production'
            InstallParams = '/install /quiet /norestart'
            SensorTags = 'Production,WebServer,Critical'
            Role = 'WebServer'
        }

        @{
            NodeName = 'PROD-WEB02'
            Environment = 'Production'
            InstallParams = '/install /quiet /norestart'
            SensorTags = 'Production,WebServer,Critical'
            Role = 'WebServer'
        }

        @{
            NodeName = 'PROD-DB01'
            Environment = 'Production'
            InstallParams = '/install /quiet /norestart'
            SensorTags = 'Production,Database,Critical'
            Role = 'Database'
        }

        # Azure Virtual Desktop Nodes
        @{
            NodeName = 'AVD-SESSION*'  # Wildcard for multiple session hosts
            Environment = 'Production'
            InstallParams = '/install /quiet /norestart'
            SensorTags = 'AVD,SessionHost,VirtualDesktop'
            Role = 'SessionHost'
        }

        # Azure Dev Box Nodes
        @{
            NodeName = 'DEVBOX-*'  # Wildcard for Dev Box instances
            Environment = 'Development'
            InstallParams = '/install /quiet /norestart NO_START=1'  # May want NO_START for dev boxes
            SensorTags = 'DevBox,Development,Developer'
            Role = 'DevBox'
        }

        # Azure ML Compute Instances
        @{
            NodeName = 'ML-COMPUTE*'
            Environment = 'Production'
            InstallParams = '/install /quiet /norestart'
            SensorTags = 'MachineLearning,Compute,DataScience'
            Role = 'MLCompute'
        }
    )
}

<#
.SYNOPSIS
    Configuration data for CrowdStrike Falcon DSC deployments

.DESCRIPTION
    This configuration data file provides environment-specific settings for different
    deployment scenarios including:

    - Development: NO_START mode for golden images
    - Staging: Standard installation with staging tags
    - Production: Full installation with production tags
    - AVD: Virtual desktop session hosts
    - DevBox: Developer environments
    - ML Compute: Azure Machine Learning instances

.NOTES
    Security Considerations:
    1. Use certificate-based encryption for credentials in production
    2. Store actual credentials in Azure Key Vault or similar secure store
    3. Use managed identities where possible
    4. Encrypt configuration MOF files

    Usage Examples:

    # Generate configuration for specific environment
    CrowdStrikeFalconDSC -ConfigurationData .\FalconDSCConfigData.psd1 -FalconClientId $ClientId -FalconClientSecret $Secret

    # Generate configuration for specific nodes
    CrowdStrikeFalconDSC -ConfigurationData .\FalconDSCConfigData.psd1 -FalconClientId $ClientId -FalconClientSecret $Secret -OutputPath ".\MOFs\Production"

    Environment-specific tags help with:
    - Sensor organization and management
    - Policy application
    - Reporting and compliance
    - Incident response and investigations
#>
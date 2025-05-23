﻿#
# Module manifest for module 'SCEPman'
#
# Date: 2024-01-05
#

@{

# Script module or binary module file associated with this manifest.
RootModule = 'SCEPman.psm1'

# Version number of this module.
ModuleVersion = '1.6.0.0'

# Supported PSEditions
# CompatiblePSEditions = @()

# ID used to uniquely identify this module
GUID = '50259d0c-c14e-4762-a2d6-916f38332847'

# Author of this module
Author = 'glueckkanja-gab'

# Company or vendor of this module
CompanyName = 'glueckkanja-gab'

# Copyright statement for this module
Copyright = '(c) 2024 glueckkanja-gab AG. All rights reserved.'

# Description of the functionality provided by this module
Description = 'CMDlets to manage SCEPman (https://scepman.com/) installations'

# Minimum version of the Windows PowerShell engine required by this module
#PowerShellVersion = ''

# Name of the Windows PowerShell host required by this module
# PowerShellHostName = ''

# Minimum version of the Windows PowerShell host required by this module
# PowerShellHostVersion = ''

# Minimum version of Microsoft .NET Framework required by this module. This prerequisite is valid for the PowerShell Desktop edition only.
# DotNetFrameworkVersion = ''

# Minimum version of the common language runtime (CLR) required by this module. This prerequisite is valid for the PowerShell Desktop edition only.
# CLRVersion = ''

# Processor architecture (None, X86, Amd64) required by this module
# ProcessorArchitecture = ''

# Modules that must be imported into the global environment prior to importing this module
# RequiredModules = @()

# Assemblies that must be loaded prior to importing this module
# RequiredAssemblies = @()

# Script files (.ps1) that are run in the caller's environment prior to importing this module.
# ScriptsToProcess = @()

# Type files (.ps1xml) to be loaded when importing this module
# TypesToProcess = @()

# Format files (.ps1xml) to be loaded when importing this module
# FormatsToProcess = @()

# Modules to import as nested modules of the module specified in RootModule/ModuleToProcess
# NestedModules = @()

# Functions to export from this module, for best performance, do not use wildcards and do not delete the entry, use an empty array if there are no functions to export.
FunctionsToExport = @(
    'Complete-SCEPmanInstallation',
    'New-SCEPmanDeploymentSlot',
    'New-SCEPmanClone',
    'Register-SCEPmanCertMaster',
    'Register-SCEPmanApiClient',
    'New-IntermediateCA',
    'Get-IntermediateCaPolicy',
    'Set-IntermediateCaPolicy',
    'Reset-IntermediateCaPolicy',
    'Sync-IntuneCertificate',
    'Update-CertificateViaEST'
)

# Cmdlets to export from this module, for best performance, do not use wildcards and do not delete the entry, use an empty array if there are no cmdlets to export.
CmdletsToExport = @()

# Variables to export from this module
VariablesToExport = '*'

# Aliases to export from this module, for best performance, do not use wildcards and do not delete the entry, use an empty array if there are no aliases to export.
AliasesToExport = @()

# DSC resources to export from this module
# DscResourcesToExport = @()

# List of all modules packaged with this module
# ModuleList = @()

# List of all files packaged with this module
FileList = @( 'SCEPman.psm1' )

# Private data to pass to the module specified in RootModule/ModuleToProcess. This may also contain a PSData hashtable with additional module metadata used by PowerShell.
PrivateData = @{

    PSData = @{

        # Tags applied to this module. These help with module discovery in online galleries.
        Tags = @('SCEP', 'Configuration')

        # A URL to the license for this module.
        LicenseUri = 'https://raw.githubusercontent.com/scepman/scepman-psmodule/main/LICENSE'

        # A URL to the main website for this project.
        ProjectUri = 'https://scepman.com/'

        # A URL to an icon representing this module.
        IconUri = 'https://raw.githubusercontent.com/scepman/scepman-psmodule/main/SCEPman/scepman-icon.png'

        # ReleaseNotes of this module
        # ReleaseNotes = ''

    } # End of PSData hashtable

} # End of PrivateData hashtable

# HelpInfo URI of this module
HelpInfoURI = 'https://docs.scepman.com/scepman-deployment/permissions/post-installation-config'

# Default prefix for commands exported from this module. Override the default prefix using Import-Module -Prefix.
# DefaultCommandPrefix = ''

}


#
# Module manifest for module 'Utility'
#
# Generated by: Dmitry Gancho
#
# Generated on: 12/7/2015
#

@{

# Script module or binary module file associated with this manifest.
RootModule = 'Utility'

# Version number of this module.
ModuleVersion = '12.7'

# ID used to uniquely identify this module
GUID = '8a2b997a-92a8-4adb-9e29-3bb5c2f22f82'

# Author of this module
Author = 'Dmitry Gancho'

# Company or vendor of this module
CompanyName = 'CenturyLink Cloud'

# Copyright statement for this module
Copyright = '(c) 2015 CenturyLink Cloud. All rights reserved.'

# Description of the functionality provided by this module
Description = 'Collection of general-purpose helper functions.'

# Minimum version of the Windows PowerShell engine required by this module
# PowerShellVersion = ''

# Name of the Windows PowerShell host required by this module
# PowerShellHostName = ''

# Minimum version of the Windows PowerShell host required by this module
# PowerShellHostVersion = ''

# Minimum version of Microsoft .NET Framework required by this module
# DotNetFrameworkVersion = ''

# Minimum version of the common language runtime (CLR) required by this module
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

# Functions to export from this module
FunctionsToExport = 'Add-PSModulePath', 'Publish-ThisModule', 'Get-ModuleHelp', 
               'Test-Module', 'Test-Elevated', 'Set-PSWindowTitle', 'Test-IPv4', 
               'Test-TCPPort', 'Test-Target', 'Invoke-ScriptBlock', 'Invoke-Async', 
               'Stop-Async', 'ConvertTo-Regex', 'ConvertFrom-JsonToHashtable', 
               'Out-Clip', 'Out-Voice', 'Get-ScreenSaverTimeout', 
               'Set-ScreenSaverTimeout', 'Get-ScreenShot', 'Set-WindowStyle'

# Cmdlets to export from this module
CmdletsToExport = '*'

# Variables to export from this module
VariablesToExport = '*'

# Aliases to export from this module
AliasesToExport = '*'

# DSC resources to export from this module
# DscResourcesToExport = @()

# List of all modules packaged with this module
# ModuleList = @()

# List of all files packaged with this module
# FileList = @()

# Private data to pass to the module specified in RootModule/ModuleToProcess. This may also contain a PSData hashtable with additional module metadata used by PowerShell.
PrivateData = @{

    PSData = @{

        # Tags applied to this module. These help with module discovery in online galleries.
        # Tags = @()

        # A URL to the license for this module.
        # LicenseUri = ''

        # A URL to the main website for this project.
        # ProjectUri = ''

        # A URL to an icon representing this module.
        # IconUri = ''

        # ReleaseNotes of this module
        # ReleaseNotes = ''

    } # End of PSData hashtable


    # KB
    KB = ''

} # End of PrivateData hashtable

# HelpInfo URI of this module
# HelpInfoURI = ''

# Default prefix for commands exported from this module. Override the default prefix using Import-Module -Prefix.
# DefaultCommandPrefix = ''

}


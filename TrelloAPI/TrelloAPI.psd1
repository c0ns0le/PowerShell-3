#
# Module manifest for module 'TrelloAPI'
#
# Generated by: Dmitry Gancho, dmitry.gancho@ctl.io
#
# Generated on: 12/7/2015
#

@{

# Script module or binary module file associated with this manifest.
RootModule = 'TrelloAPI'

# Version number of this module.
ModuleVersion = '12.7'

# ID used to uniquely identify this module
GUID = '8dc283a3-fb9f-4a4b-9eaf-7fe11aafbf7f'

# Author of this module
Author = 'Dmitry Gancho, dmitry.gancho@ctl.io'

# Company or vendor of this module
CompanyName = 'CenturyLink Cloud'

# Copyright statement for this module
Copyright = '(c) 2015 CenturyLink Cloud. All rights reserved.'

# Description of the functionality provided by this module
Description = 'Interaction with Trello objects via API.'

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
RequiredModules = @('Credential')

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
FunctionsToExport = 'Get-TrellokApiBaseUri', 'New-TrelloApiSession', 'Get-TrelloObject', 
               'Get-TrelloCardObjects', 'Get-TrelloBoardObjects', 
               'Search-TrelloObjects', 'New-TrelloCard', 'Update-TrelloCard', 
               'Import-TrelloCredential', 'Set-useUnsafeHeaderParsing'

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
    KB = 'http://developers.trello.com/advanced-reference'

} # End of PrivateData hashtable

# HelpInfo URI of this module
# HelpInfoURI = ''

# Default prefix for commands exported from this module. Override the default prefix using Import-Module -Prefix.
# DefaultCommandPrefix = ''

}


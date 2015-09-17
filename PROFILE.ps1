
<#
.NOTES
    Author: Dmitry Gancho
            dmitry@ganco.com
    Last Edit: 9/4/2015
#>


#region FUNCTIONS


    function Set-PsWindowTitle {
        $elevated = if (([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {' (elevated)'}
        $title = @(
            "$($env:USERNAME.ToLower())$elevated on $($env:COMPUTERNAME.ToUpper())",
            "$($Host.Name) $($Host.Version)",
            "$((Get-Date).ToLongDateString())"
        )
        $Host.UI.RawUI.set_WindowTitle($title -join ' ~ ')
    } #function



    function Copy-Profile {
    <#
        http://blogs.technet.com/b/heyscriptingguy/archive/2012/05/21/understanding-the-six-powershell-profiles.aspx
        Description                          : Path
        Current User, Current Host - console : $Home\[My ]Documents\WindowsPowerShell\Profile.ps1
        Current User, All Hosts              : $Home\[My ]Documents\Profile.ps1
        All Users, Current Host - console    : $PsHome\Microsoft.PowerShell_profile.ps1
        All Users, All Hosts                 : $PsHome\Profile.ps1
        Current user, Current Host - ISE     : $Home\[My ]Documents\WindowsPowerShell\Microsoft.P owerShellISE_profile.ps1
        All users, Current Host - ISE        : $PsHome\Microsoft.PowerShellISE_profile.ps1
    #>
        
        param ([string]$SourceItem)

        # see definitions above
        $Path = "$HOME\Documents\WindowsPowerShell"
        $DestinationItem = "$Path\PROFILE.ps1"
        # create folder if not yet there
        if (-not (Test-Path $Path)) {
            New-Item -ItemType Directory -Path $Path -Force
        } #if
        # copy profile if not self
        if ($SourceItem -ne $DestinationItem) {
            Copy-Item -Path $SourceItem -Destination $DestinationItem -Force -PassThru | Out-Null
        } #if
    }



    function Global:Load-Profile {

        $MyHomeDriveName = 'Z'
        $MyHomePath      = '\\localhost\Z'
        $MyPsProfile     = "$MyHomeDriveName`:\PS\profile\MyProfile.ps1"

        # Verify drive is mapped
        if ((Get-PSDrive -Name $MyHomeDriveName -ErrorAction Ignore) -eq $null) {
            if (Test-Path $MyHomePath) {
                New-PSDrive -Name $MyHomeDriveName -PSProvider FileSystem -Root $MyHomePath -Persist -Scope Global #| Out-Null
            }
        }

        # Invoke profile
        if (Test-Path -Path $MyPsProfile) {
            Invoke-Expression -Command $MyPsProfile
        } else {
            Write-Warning "Unable to load '$MyPsProfile'"
        }
    }



#endregion


#region ACTIONS

    # SET POLICY
    Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy Bypass -Force

    # SET STRICT MODE
    Set-StrictMode -Version Latest

    # SET TITLE
    Set-PSWindowTitle

    # COPY THIS SRIPT TO DESIRED LOCATION
    $CurrentScript = $MyInvocation.MyCommand.Definition
    Copy-Profile -SourceItem $CurrentScript

    # INVOKE MAIN PROFILE SCRIPT
    Load-Profile

#endregion


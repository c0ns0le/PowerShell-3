<#
    .DESCRIPTION
        Interaction with Slack via API.

    .REQUIRED MODULES
        Credential

    .FUNCTIONS
        Get-SlackPresence
        Set-SlackPresence

    .NOTES
        Company : CenturyLink Cloud
        Author  : Dmitry Gancho, dmitry.gancho@ctl.io

    .LINK
        https://api.slack.com/community

    .SERVICE
        # F8 line below to generate module manifest and copy files of this module to destination folder
        Publish-ThisModule -Destination "$env:USERPROFILE\Documents\GitHub\toolbox\Team Scripts\Dmitry Gancho"
#>


function Get-SlackPresence {
<#
    .SYNOPSIS
        Gets current presence state of authenticated user in Slack
    .DESCRIPTION
        Gets current presence state of authenticated user in Slack
    .EXAMPLE
        Get-SlackPresence
    .LINK
        https://api.slack.com/methods/users.getPresence
#>
    [CmdletBinding()]param()
    # base uri
    $base = 'https://slack.com/api'
    # get token
    $token = Import-Credential -FriendlyName Slack -EntryName Token
    # get current presence
    $params = @{
        Uri = "$base/users.getPresence"
        Body = @{token=$token}
        ErrorAction = 'Stop'
    }
    Write-Verbose "Invoke-RestMethod params :`n$(ConvertTo-Json $params)"
    $response = Invoke-RestMethod @params
    Write-Verbose "Invoke-RestMethod response :`n$(ConvertTo-Json $response)"
    $response
}


function Set-SlackPresence {
<#
    .SYNOPSIS
        Sets presence state of authenticated user in Slack
    .PARAMETER Presence
        Either 'auto' (sets presence to available) or 'away'
    .EXAMPLE
        Set-SlackPresence -Presence auto
    .EXAMPLE
        Set-SlackPresence -Presence Away
    .LINK
        https://api.slack.com/methods/users.setPresence
#>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory,Position=0)]
        [ValidateSet('auto','away')]
        [string]$Presence
    )
    # param presence is case-sensitive in Slack API
    $Presence = $Presence.ToLower()
    # base uri
    $base = 'https://slack.com/api'
    # get token
    $token = Import-Credential -FriendlyName Slack -EntryName Token
    $params = @{
        Uri = "$base/users.setPresence"
        Body = @{
            token = $token
            presence = $Presence
            set_active = $true
        }
        ErrorAction = 'Stop'
    }
    Write-Verbose "Invoke-RestMethod params :`n$(ConvertTo-Json $params)"
    $response = Invoke-RestMethod @params
    Write-Verbose "Invoke-RestMethod response :`n$(ConvertTo-Json $response)"
    $response
}


# *** Aliases and Export ***
Export-ModuleMember -Function *

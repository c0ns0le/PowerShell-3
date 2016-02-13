
<#
    .DESCRIPTION
        Interaction with ZenDesk objects via API.

    .REQUIRED MODULES
        Credential

    .FUNCTIONS
        Get-ZenDeskApiBaseUri
        New-ZenDeskApiSession
        Get-ZenDeskVoiceAvailability
        Set-ZenDeskVoiceAvailability
        New-ZenDeskTicket
        Get-ZenDeskTicket
        Get-ZenDeskTicketComments
        Get-ZenDeskObject
        Search-ZenDeskObjects
        Send-ZenDeskUpload
        Remove-ZenDeskUpload
        Get-ZenDeskAttachment
        Import-ZenDeskCredential

    .NOTES
        Company : CenturyLink Cloud
        Author  : Dmitry Gancho, dmitry.gancho@ctl.io

    .LINK
        https://developer.zendesk.com/rest_api

    .SERVICE
        # F8 line below to generate module manifest and copy contents of this module folder to destination folder.
        Publish-ThisModule #-Destination "$env:USERPROFILE\Documents\GitHub\toolbox\Team Scripts\Dmitry Gancho"
#>



function Get-ZenDeskApiBaseUri {
    return 'https://t3n.zendesk.com/api/v2'
}



function New-ZenDeskApiSession {
    $base = Get-ZenDeskApiBaseUri
    $token = Import-ZenDeskCredential -Type Token
    $params = @{
        Uri = "$base.json"
        Headers = @{Authorization = "Bearer $token"}
        SessionVariable = 'WebSession'
        ErrorAction = 'Stop'
    }
    Write-Verbose "Invoke-RestMethod params:`n$(ConvertTo-Json $params)"
    $response = Invoke-RestMethod @params
    Write-Verbose "Invoke-RestMethod response:`n$(ConvertTo-Json $response)"
    return $WebSession
}



function Get-ZenDeskVoiceAvailability {
<#
    .SYNOPSIS
        Gets voice availability of a user in ZenDesk
    .EXAMPLE
        Get-ZenDeskVoiceAvailability
    .EXAMPLE
        Set-ZenDeskVoiceAvailability -UserId me
    .LINK
        https://developer.zendesk.com/rest_api/docs/voice-api/voice#getting-availability
#>
    [CmdletBinding()]
    param (
        [Parameter()]
        [string]$UserId,

        [Parameter()][Alias('ws')]
        [Microsoft.PowerShell.Commands.WebRequestSession]$WebSession = (New-ZenDeskApiSession)
    )
    $base = Get-ZenDeskApiBaseUri
    # get user id if not provided
    if (-not $UserId) {
        $UserId = Get-ZenDeskObject -ObjectType User -ObjectId me | Select-Object -ExpandProperty Id
    }
    # set uri
    $uri = "$base/channels/voice/availabilities/$UserId.json"
    # get current availability
    $params = @{
        Uri = $uri
        WebSession = $WebSession
        ErrorAction = 'Stop'
    }
    Write-Verbose "Invoke-RestMethod params:`n$(ConvertTo-Json $params)"
    $response = Invoke-RestMethod @params
    Write-Verbose "Invoke-RestMethod response:`n$(ConvertTo-Json $response)"
    return $response.availability
}



function Set-ZenDeskVoiceAvailability {
<#
    .SYNOPSIS
        Sets voice availability of a user in ZenDesk
    .EXAMPLE
        Set-ZenDeskVoiceAvailability -Available
    .EXAMPLE
        Set-ZenDeskVoiceAvailability -Unvailable -UserId me
    .LINK
        https://developer.zendesk.com/rest_api/docs/voice-api/voice#updating-availability
#>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory,ParameterSetName='true')]
        [switch]$Available,

        [Parameter(Mandatory,ParameterSetName='false')]
        [switch]$Unavailable,

        [Parameter()]
        [string]$UserId,

        [Parameter()][Alias('ws')]
        [Microsoft.PowerShell.Commands.WebRequestSession]$WebSession = (New-ZenDeskApiSession)
    )
    $base = Get-ZenDeskApiBaseUri
    # get user id if not provided
    if (-not $UserId) {
        $UserId = Get-ZenDeskObject -ObjectType User -ObjectId me | Select-Object -ExpandProperty Id
    }
    # set uri
    $uri = "$base/channels/voice/availabilities/$UserId.json"
    # get desired availability
    $desired = switch ($PSCmdlet.ParameterSetName) {
        true  {$true }
        false {$false}
    }
    # set availability
    $body = @{
        availability = @{
            via = 'phone'
            available = $desired
        }
    } | ConvertTo-Json -Compress
    $params = @{
        Uri = $uri
        Method = 'PUT'
        Body = $body
        ContentType = 'application/json'
        WebSession = $WebSession
        ErrorAction = 'Stop'
    }
    Write-Verbose "Invoke-RestMethod params:`n$(ConvertTo-Json $params)"
    $response = Invoke-RestMethod @params
    Write-Verbose "Invoke-RestMethod response:`n$(ConvertTo-Json $response)"
    return $response.availability
}



function Get-ZenDeskTicket {
    param (
        [Parameter(Mandatory,Position=0)][Alias('id')]
        [string]$TicketId,

        [Parameter()][Alias('ws')]
        [Microsoft.PowerShell.Commands.WebRequestSession]$WebSession = (New-ZenDeskApiSession)
    )
    $base = Get-ZenDeskApiBaseUri
    $params = @{
        Uri = "$base/tickets/$TicketId.json"
        WebSession = $WebSession
        ErrorAction = 'Stop'
    }
    Write-Verbose "Invoke-RestMethod params:`n$(ConvertTo-Json $params)"
    $response = Invoke-RestMethod @params
    Write-Verbose "Invoke-RestMethod response:`n$(ConvertTo-Json $response)"
    if ($response -is [PSCustomObject]) {
        return $response.ticket
    } else {
        Write-Host "Ticket '$TicketId' not found"
        return $null
    }
}



function Get-ZenDeskTicketComments {
    param (
        [Parameter(Mandatory,Position=0)][Alias('id')]
        [string]$TicketId,

        [Parameter()][Alias('ws')]
        [Microsoft.PowerShell.Commands.WebRequestSession]$WebSession = (New-ZenDeskApiSession)
    )
    $base = Get-ZenDeskApiBaseUri
    $params = @{
        Uri = "$base/tickets/$TicketId/comments.json"
        WebSession = $WebSession
        ErrorAction = 'Stop'
    }
    Write-Verbose "Invoke-RestMethod params:`n$(ConvertTo-Json $params)"
    $response = Invoke-RestMethod @params
    Write-Verbose "Invoke-RestMethod response:`n$(ConvertTo-Json $response)"
    return $response
}



function Get-ZenDeskObject {
<#
    .EXAMPLE
        Get-ZenDeskObject -ObjectType Ticket -ObjectId 1195886
    .EXAMPLE
        Get-ZenDeskObject -ObjectType Organization -ObjectId 45004593
    .EXAMPLE
        Get-ZenDeskObject -ObjectType User -ObjectId 373344350
    .LINK
        https://developer.zendesk.com/rest_api/docs/core/introduction
#>
    param (
        [Parameter(Mandatory,Position=0)][Alias('id')]
        [string]$ObjectId,

        [Parameter(Mandatory)][Alias('type')]
        [ValidateSet('User','Group','Ticket','Organization')]
        [string]$ObjectType,

        [Parameter()][Alias('ws')]
        [Microsoft.PowerShell.Commands.WebRequestSession]$WebSession = (New-ZenDeskApiSession)
    )
    $base = Get-ZenDeskApiBaseUri
    $type = $ObjectType.ToLower() + 's'
    $params = @{
        Uri = "$base/$type/$ObjectId.json"
        WebSession = $WebSession
        ErrorAction = 'Stop'
    }
    Write-Verbose "Invoke-RestMethod params:`n$(ConvertTo-Json $params)"
    $response = Invoke-RestMethod @params
    Write-Verbose "Invoke-RestMethod response:`n$(ConvertTo-Json $response)"
    if ($response -is [PSCustomObject]) {
        return $response.$ObjectType
    } else {
        Write-Host "$ObjectType '$ObjectId' not found"
        return $null
    }
}



function Search-ZenDeskObjects {
<#
    .EXAMPLE
        Search-ZenDeskObjects -Query 'MECA'
    .EXAMPLE
        Search-ZenDeskObjects -ObjectType Tickets -Query 'fieldvalue:MECA created>2015-09-10'
    .EXAMPLE
        Search-ZenDeskObjects -ObjectType Tickets -Query 'subject:"Your Chat Transcript" created>2015-10-01 created<2015-10-30' 
    .LINK
        https://support.zendesk.com/hc/en-us/articles/203663226
#>
    param (
        [Parameter(Mandatory,Position=0)][Alias('qry')]
        [string]$Query,

        [Parameter()][Alias('type')]
        [ValidateSet('Tickets','Users','Organizations','Groups')]
        [string]$ObjectType,

        [Parameter()][Alias('ws')]
        [Microsoft.PowerShell.Commands.WebRequestSession]$WebSession = (New-ZenDeskApiSession)
    )
    $base = Get-ZenDeskApiBaseUri
    $uri = "$base/search.json?query=$Query"
    if ($ObjectType) {
        $type = $ObjectType.Trim('s')
        $Query = "type:$type " + $Query
    }
    $params = @{
        Uri = $uri
        WebSession = $WebSession
        ErrorAction = 'Stop'
    }
    Write-Verbose "Invoke-RestMethod params:`n$(ConvertTo-Json $params)"
    $response = Invoke-RestMethod @params
    Write-Verbose "Invoke-RestMethod response:`n$(ConvertTo-Json $response)"
    return $response
}



function Send-ZenDeskUpload {
<#
    curl -u username:password -H "Content-Type: application/binary" \
       --data-binary @file.dat -X POST \
       "https://helpdesk.zendesk.com/api/v2/uploads.json?filename=myfile.dat&token={optional_token}"
    $allowedFileTypes = ‘images/jpeg’,’image/png’,’image/jpeg’,’image/gif’,‘application/pdf’,‘application/x-pdf’
#>
    param (
        [Parameter(Mandatory,Position=0)][Alias('file')]
        [string[]]$FilePath,

        [Parameter()][Alias('ws')]
        [Microsoft.PowerShell.Commands.WebRequestSession]$WebSession = (New-ZenDeskApiSession)
    )
    $base = Get-ZenDeskApiBaseUri
    $uri = "$base/uploads.json"
    # upload an attachment
    $token = $null
    $FilePath | % {
        $filecont = Get-Content -Path $_ -Raw
        $filename = Split-Path -Path $_ -Leaf
        $conttype = switch -Regex ($filename -split '\.' | select -Last 1) {
            'jpeg|jpg' {’image/jpeg’     }
            'png'      {'image/png'      }
            'gif'      {'image/gif'      }
            'pdf'      {‘application/pdf’}
            default    {$null            }
        }
        $params = @{
            Uri = "$base/uploads.json?filename=$filename&token=$token"
            Method = 'POST'
            Body = $filecont
            ContentType = $conttype
            WebSession = $WebSession
            ErrorAction = 'Stop'
        }
        Write-Verbose "Invoke-RestMethod params:`n$(ConvertTo-Json $params)"
        $response = Invoke-RestMethod @params
        Write-Verbose "Invoke-RestMethod response:`n$(ConvertTo-Json $response)"
        $token = $response.upload.token
    }
    return $response.upload
}



function Remove-ZenDeskUpload {
    param (
        [Parameter(Mandatory,Position=0)]
        [PSCustomObject]$Upload,

        [Parameter()][Alias('ws')]
        [Microsoft.PowerShell.Commands.WebRequestSession]$WebSession = (New-ZenDeskApiSession)
    )
    $base = Get-ZenDeskApiBaseUri
    $token = $Upload.token
    $params = @{
        Uri = "$base/uploads/$token.json"
        Method = 'DELETE'
        WebSession = $WebSession
        ErrorAction = 'Stop'
    }
    Write-Verbose "Invoke-RestMethod params:`n$(ConvertTo-Json $params)"
    $response = Invoke-RestMethod @params
    Write-Verbose "Invoke-RestMethod response:`n$(ConvertTo-Json $response)"
}



function Get-ZenDeskAttachment {
    param (
        [Parameter(Mandatory,Position=0)]
        [Alias('id')]
        [string]$AttachmentId,

        [Parameter()][Alias('ws')]
        [Microsoft.PowerShell.Commands.WebRequestSession]$WebSession = (New-ZenDeskApiSession)
    )
    $base = Get-ZenDeskApiBaseUri
    $token = $Upload.token
    $params = @{
        Uri = "$base/attachments/$AttachmentId.json"
        WebSession = $WebSession
        ErrorAction = 'Stop'
    }
    Write-Verbose "Invoke-RestMethod params:`n$(ConvertTo-Json $params)"
    $response = Invoke-RestMethod @params
    Write-Verbose "Invoke-RestMethod response:`n$(ConvertTo-Json $response)"
    return $response.Attachments
}



function New-ZenDeskTicket {
<#
    https://developer.zendesk.com/rest_api/docs/core/tickets#creating-tickets
    JSON format for TicketData:
    $TicketData = @{
        ticket = @{
            subject  = [string]$Subject
            group_id = [string]$GroupId
            type     = [string]('incident'|'problem'|'task')$Type
            priority = [string]('urgent'|'high'|'normal'|'low')$Priority
            status   = [string]('new,|'open'|'pending'|'hold'|'solved'|'closed')$Status: optional, default 'open'
            comment  = @{
                body = [string]$Message
            }
            custom_fields = @(
                @{
                    id = 20321291
                    value = 'T3N'
                }
                @{
                    id = 21619801
                    value = 'manual_task'
                }
                @{
                    id = 24305619
                    value = 'impact_n_a'
                }
                @{
                    id = 20321657
                    value = 'T3N'
                }
            )
        }
    } | ConvertTo-Json -Depth 3 -Compress
#>    
    param (
        [Parameter(Mandatory)][Alias('data')]
        [String]$TicketData,

        [Parameter()][Alias('ws')]
        [Microsoft.PowerShell.Commands.WebRequestSession]$WebSession = (New-ZenDeskApiSession)
    )
    # invoke POST method to create new ticket
    $base = Get-ZenDeskApiBaseUri
    $uri = "$base/tickets.json"
    $params = @{
        Uri = $uri
        Body = $TicketData
        Method = 'POST'
        ContentType = 'application/json'
        WebSession = $WebSession
        ErrorAction = 'Stop'
    }
    Write-Verbose "Invoke-RestMethod params:`n$(ConvertTo-Json $params)"
    $response = Invoke-RestMethod @params
    Write-Verbose "Invoke-RestMethod response:`n$(ConvertTo-Json $response)"
    return $response.ticket
}



function Import-ZenDeskCredential {
<#
    .SYNOPSIS
        Returns ZenDesk [PSCredential]UserCredentials or [string]Secret or [string]Token
    .DESCRIPTION
        Returns ZenDesk [PSCredential]UserCredentials or [string]Secret or [string]Token
        Source HKCU:\Environment\Credentials\ZenDesk
        If not found, then:
        - User: Inquire interactively
        - Secret: hardcoded
        - Token: invoked from url 'https://t3n.zendesk.com/oauth/tokens' using User Credentials and Secret
    .EXAMPLE
        Get-ZenDeskCredential -Type User
    .EXAMPLE
        Get-ZenDeskCredential -Type Secret
    .EXAMPLE
        Get-ZenDeskCredential -Type Token
    .PARAMETER Type
        Either 'User' or 'Secret' or 'Token'
    .NOTES
        Author: Dmitry Gancho
                dmitry.gancho@ctl.io
        Last edit: 10/2/2015
        https://developer.zendesk.com/rest_api/docs/core/introduction#security-and-authentication
    .LINK
#>
    param (
        [ValidateSet('User','Secret','Token')]
        [string]$Type='User'
    ) #param

    function New-ZenDeskToken {
        param (
            [Parameter(Mandatory)]
            [string]$UserName,
            [Parameter(Mandatory)]
            [string]$Password,
            [Parameter(Mandatory)]
            [string]$Secret
        ) #param
        $headers = [System.Collections.Generic.Dictionary[string,string]]::new()
        $headers.Add('Accepts','application/json')
        $body = @{
            grant_type    = 'password'
            client_id     = 'ZenDeskQueueMonitor'
            client_secret = $Secret
            scope         = 'read write'
            username      = $UserName
            password      = $Password
        } | ConvertTo-Json
        #$url = 'https://t3n.zendesk.com/oauth/tokens' -- defined in upper scope
        $params = @{
             Method = 'Post'
             Uri = $TokenUrl
             Headers = $headers
             Body = $body
             ContentType = 'application/json'
             ErrorAction  = 'Stop'
        }
        try {
            Write-Verbose "Invoke-RestMethod params:`n$(ConvertTo-Json $params)"
            $response = Invoke-RestMethod @params
            Write-Verbose "Invoke-RestMethod response:`n$(ConvertTo-Json $response)"
            return $response.access_token
        } catch {
            #Write-Verbose $Error[0].Exception.Message
            return $null
        }
    } #function

    # HARDCODED VARIABLES:
    $FriendlyName  = 'ZenDesk'
    $TokenUrl      = 'https://t3n.zendesk.com/oauth/tokens'

    switch ($Type) {
        User {
            $cred = Import-Credential -FriendlyName $FriendlyName -NewIfNotFound
            return $cred
        }
        Secret {
            $secret = Import-Credential -FriendlyName $FriendlyName -EntryName Secret
            if (-not $secret) {
                $secret = Read-Host -Prompt "ZenDesk Secret : "
                if ($secret) {
                    Export-Credential -FriendlyName $FriendlyName -EntryName Secret -EntryValue $secret
                    $secret = Import-ZenDeskCredential -Type Secret
                }
            } #if
            return $secret
        } #Sectet
        Token {
            $token = Import-Credential -FriendlyName $FriendlyName -EntryName Token
            if (-not $token) {
                $cred = Import-ZenDeskCredential -Type User
                try {
                    $user = $cred.UserName
                    $pass = $cred.GetNetworkCredential().Password
                } catch {
                    return $null
                }
                $secret = Import-ZenDeskCredential -Type Secret
                if ($user -and $pass -and $secret) {
                    $token = New-ZenDeskToken -UserName $user -Password $pass -Secret $secret
                    if ($token) {
                        Export-Credential -FriendlyName $FriendlyName -EntryName Token -EntryValue $token
                    }
                }
            }
            return $token
        }
        default {
            return
        }
    } #switch

}



# *** Aliases and Export ***
Export-ModuleMember -Function *

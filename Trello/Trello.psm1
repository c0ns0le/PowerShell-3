<#
.DESCRIPTION
    Interaction with Trello objects via API.

.REQUIRED MODULES
    Credential

.FUNCTIONS
    Get-TrellokApiBaseUri
    New-TrelloApiSession
    Get-TrelloObject
    Get-TrelloCardObjects
    Get-TrelloBoardObjects
    Search-TrelloObjects
    New-TrelloCard
    Update-TrelloCard
    Move-TrelloCard
    Import-TrelloCredential
    Set-useUnsafeHeaderParsing

.NOTES
    Company : CenturyLink Cloud
    Author  : Dmitry Gancho, dmitry.gancho@ctl.io

.LINK
    http://developers.trello.com/advanced-reference

.SERVICE
    # F8 line below to generate module manifest and copy contents of this module folder to destination folder.
    Publish-ThisModule #-Destination "$env:USERPROFILE\Documents\GitHub\toolbox\Team Scripts\Dmitry Gancho"
#>



function Get-TrelloApiBaseUri {
<#
.SYNOPSIS
    Return base (root) URI to Trello API
.DESCRIPTION
    Author   : Dmitry Gancho
    Last edit: 11/10/2015
.EXAMPLE
    Get-TrelloApiBaseUri
.INPUTS
    none
.OUTPUTS
    [string]
.LINK
#>
    [cmdletbinding()]param()
    return 'https://api.trello.com/1'
}



function New-TrelloApiSession {
<#
.SYNOPSIS
    Creates new authenticated WebSession to Trello API.
    If credential are not available from Regsitry, they are inquired from User interacively
.DESCRIPTION
    Author   : Dmitry Gancho
    Last edit: 11/10/2015
.EXAMPLE
    New-TrelloApiSession
.INPUTS
    none
.OUTPUTS
    [Microsoft.PowerShell.Commands.WebRequestSession]
.LINK
#>
    [cmdletbinding()]param()
    $base = Get-TrelloApiBaseUri
    $cred = Import-Credential -FriendlyName Trello -As HashTable
    $uri = "$base/client.js"
#    $authstring = "Bearer $token"
    $params = @{
        Uri = $uri
        Headers = @{
            #Authorization = $authstring
            Key = $cred.Key
            Token = $cred.Token
        }
        SessionVariable = 'WebSession'
        ErrorAction = 'Stop'
    }
    Set-useUnsafeHeaderParsing
    Write-Verbose "Invoke-RestMethod params:`n$(ConvertTo-Json $params)"
    $response = Invoke-RestMethod @params
    Write-Verbose "Invoke-RestMethod response:`n$(ConvertTo-Json $response)"
    return $WebSession
}



function Get-TrelloObject {
<#
.SYNOPSIS
    Get an object from Trello via API.
.DESCRIPTION
    Author   : Dmitry Gancho
    Last edit: 11/10/2015
.PARAMETER ObjectId
    Required.
    ID of Trello object
.PARAMETER ObjectType
    Required.
    Type of Trello object.
    One of 'Member','Board','Card','Label','List','Organization'
.PARAMETER WebSession
    Optional.
    Authenticated Trello WebSession
.EXAMPLE
    Get-TrelloObject -Id <ObjectOD> -Type Board
.INPUTS
    [string]
    [string]
    [Microsoft.PowerShell.Commands.WebRequestSession]
.OUTPUTS
    [Object]
.LINK
#>

    [cmdletbinding()]
    param (
        [Parameter(Mandatory,Position=0)][Alias('id')]
        [string]$ObjectId,

        [Parameter(Mandatory)][Alias('type')]
        [ValidateSet('Member','Board','Card','Label','List','Organization')]
        [string]$ObjectType,

        [Parameter()][Alias('ws')]
        [Microsoft.PowerShell.Commands.WebRequestSession]$WebSession = (New-TrelloApiSession)
    )
    $base = Get-TrelloApiBaseUri
    $ObjectType = $ObjectType.ToLower()
    $uri = "$base/$ObjectType`s/$ObjectId"
    $uri += '?key='   + $WebSession.Headers.Key
    $uri += '&token=' + $WebSession.Headers.Token

    $params = @{
        Uri = $uri
        WebSession = $WebSession
        ErrorAction = 'Stop'
    }
    Set-useUnsafeHeaderParsing
    Write-Verbose "Invoke-RestMethod params:`n$(ConvertTo-Json $params)"
    $response = Invoke-RestMethod @params
    Write-Verbose "Invoke-RestMethod response:`n$(ConvertTo-Json $response)"
    return $response
}



function Get-TrelloCardObjects {
<#
.SYNOPSIS
    Get objects from from a Trello Card via API.
.DESCRIPTION
    Author   : Dmitry Gancho
    Last edit: 11/10/2015
.PARAMETER CardId
    Required.
    ID of Trello Card
.PARAMETER ObjectType
    Required.
    Type of Trello Card object.
    One of 'Actions','Attachments','Checklists','Members','Stickers'
.PARAMETER WebSession
    Optional.
    Authenticated Trello WebSession
.EXAMPLE
    Get-TrelloCardObjects -CardId <CardId> -Type Members
.INPUTS
    [string]
    [string]
    [Microsoft.PowerShell.Commands.WebRequestSession]
.OUTPUTS
    [Object[]]
.LINK
#>
    [cmdletbinding()]
    param (
        [Parameter(Mandatory,Position=0)][Alias('id')]
        [string]$CardId,

        [Parameter(Mandatory)][Alias('type')]
        [ValidateSet('Actions','Attachments','Checklists','Members','Stickers')]
        [string]$ObjectType,

        [Parameter()][Alias('ws')]
        [Microsoft.PowerShell.Commands.WebRequestSession]$WebSession = (New-TrelloApiSession)
    )
    $base = Get-TrelloApiBaseUri
    $ObjectType = $ObjectType.ToLower()
    $uri = "$base/cards/$CardId/$ObjectType"
    $uri += '?key='   + $WebSession.Headers.Key
    $uri += '&token=' + $WebSession.Headers.Token

    $params = @{
        Uri = $uri
        WebSession = $WebSession
        ErrorAction = 'Stop'
    }
    Set-useUnsafeHeaderParsing
    Write-Verbose "Invoke-RestMethod params:`n$(ConvertTo-Json $params)"
    $response = Invoke-RestMethod @params
    Write-Verbose "Invoke-RestMethod response:`n$(ConvertTo-Json $response)"
    return $response
}



function Get-TrelloBoardObjects {
<#
.SYNOPSIS
    Get objects from from a Trello Board via API.
.DESCRIPTION
    Author   : Dmitry Gancho
    Last edit: 11/10/2015
.PARAMETER BoardId
    Required.
    ID of Trello Board
.PARAMETER ObjectType
    Required.
    Type of Trello Board object.
    One of 'Labels','Lists'
.PARAMETER WebSession
    Optional.
    Authenticated Trello WebSession
.EXAMPLE
    Get-TrelloBoardObjects -BoardId <BoardId> -Type Labels
.INPUTS
    [string]
    [string]
    [Microsoft.PowerShell.Commands.WebRequestSession]
.OUTPUTS
    [Object[]]
.LINK
#>
    [cmdletbinding()]
    param (
        [Parameter(Mandatory,Position=0)][Alias('board')]
        [string]$BoardId,

        [Parameter(Mandatory)][Alias('type')]
        [ValidateSet('Labels','Lists')]
        [string]$ObjectType,

        [Parameter()][Alias('ws')]
        [Microsoft.PowerShell.Commands.WebRequestSession]$WebSession = (New-TrelloApiSession)
    )
    $base = Get-TrelloApiBaseUri
    $ObjectType = $ObjectType.ToLower()
    $uri = "$base/boards/$BoardId/$ObjectType"
    $uri += '?key='   + $WebSession.Headers.Key
    $uri += '&token=' + $WebSession.Headers.Token

    $params = @{
        Uri = $uri
        WebSession = $WebSession
        ErrorAction = 'Stop'
    }
    Set-useUnsafeHeaderParsing
    Write-Verbose "Invoke-RestMethod params:`n$(ConvertTo-Json $params)"
    $response = Invoke-RestMethod @params
    Write-Verbose "Invoke-RestMethod response:`n$(ConvertTo-Json $response)"
    return $response
}



function Search-TrelloObjects {
<#
.SYNOPSIS
    Search for Trello objects via API.
.DESCRIPTION
    Author   : Dmitry Gancho
    Last edit: 11/10/2015
.PARAMETER Query
    Required.
    Search query.
.PARAMETER ObjectType
    Optional. Default: 'Cards'
    Type of Trello objects.
    One of 'Members','Actions','Boards','Cards','Labels','Organizations'
.PARAMETER WebSession
    Optional.
    Authenticated Trello WebSession
.EXAMPLE
    Search-TrelloObjects -ObjectType Cards -Query "cloud-lse repo" | select -exp cards
.INPUTS
    [string]
    [string]
    [Microsoft.PowerShell.Commands.WebRequestSession]
.OUTPUTS
    [Object[]]
.LINK
    https://developers.trello.com/advanced-reference/search
#>
    [cmdletbinding()]
    param (
        [Parameter(Mandatory,Position=0)][Alias('qry')]
        [string]$Query,

        [Parameter()][Alias('type')]
        [ValidateSet('Members','Actions','Boards','Cards','Labels','Organizations')]
        [string]$ObjectType='Cards',

        [Parameter()][Alias('ws')]
        [Microsoft.PowerShell.Commands.WebRequestSession]$WebSession = (New-TrelloApiSession)
    )
    $base = Get-TrelloApiBaseUri
    $ObjectType = $ObjectType.ToLower()
    $uri  = "$base/search"
    $uri += "?query=$Query"
    $uri += "&modelTypes=$ObjectType"
    $uri += '&key='   + $WebSession.Headers.Key
    $uri += '&token=' + $WebSession.Headers.Token

    $params = @{
        Uri = $uri
        WebSession = $WebSession
        ErrorAction = 'Stop'
    }
    Set-useUnsafeHeaderParsing
    Write-Verbose "Invoke-RestMethod params:`n$(ConvertTo-Json $params)"
    $response = Invoke-RestMethod @params
    Write-Verbose "Invoke-RestMethod response:`n$(ConvertTo-Json $response)"
    return $response
}



function New-TrelloCard {
<#
.SYNOPSIS
    Create new Trello Card via API.
.DESCRIPTION
    Author   : Dmitry Gancho
    Last edit: 11/10/2015
.PARAMETER Name
    Required.
    Card Name.
.PARAMETER Description
    Optional.
    Card Description.
.PARAMETER ListId
    Required.
    Trello List ID, where Card will be created.
.PARAMETER WebSession
    Optional.
    Authenticated Trello WebSession
.EXAMPLE
    New-TrelloCard -Name NewCard -ListId <ListID>
.INPUTS
    [string]
    [string]
    [string]
    [Microsoft.PowerShell.Commands.WebRequestSession]
.OUTPUTS
    [Object]
.LINK
#>
    [cmdletbinding()]
    param (
        [Parameter(Mandatory)]
        [string]$Name,

        [Parameter()]
        [string]$Description,

        [Parameter(Mandatory)]
        [string]$ListId,

        [Parameter()][Alias('ws')]
        [Microsoft.PowerShell.Commands.WebRequestSession]$WebSession = (New-ZenDeskApiSession)
    )
    # create new card
    $base = Get-TrelloApiBaseUri
    $uri  = "$base/cards"
    $uri += '?idList='   + $ListId
    $uri += '&name='     + $Name
    $uri += '&desc='     + $Description
    $uri += '&key='      + $WebSession.Headers.Key
    $uri += '&token='    + $WebSession.Headers.Token
    $params = @{
        Method = 'POST'
        Uri = $uri
        ErrorAction = 'Stop'
    }
    Set-useUnsafeHeaderParsing
    Write-Verbose "Invoke-RestMethod params:`n$(ConvertTo-Json $params)"
    $response = Invoke-RestMethod @params
    Write-Verbose "Invoke-RestMethod response:`n$(ConvertTo-Json $response)"
    return $response
}



function Update-TrelloCard {
<#
.SYNOPSIS
    Update existing Trello Card via API.
.DESCRIPTION
    Author   : Dmitry Gancho
    Last edit: 11/10/2015
.PARAMETER CardId
    Required.
    Card Name.
.PARAMETER Description
    Required.
    Card Description.
.PARAMETER Comment
    Optional.
    Card Comment.
.PARAMETER WebSession
    Optional.
    Authenticated Trello WebSession
.EXAMPLE
    Update-TrelloCard -CardId <CardId> -ListId <ListID> -Description <Description>
.INPUTS
    [string]
    [string]
    [string]
    [Microsoft.PowerShell.Commands.WebRequestSession]
.OUTPUTS
    [Object]
.LINK
#>
    [cmdletbinding()]
    param (
        [Parameter(Mandatory)]
        [string]$CardId,

        [Parameter(Mandatory)]
        [string]$Description,

        [Parameter()]
        [string]$Comment,

        [Parameter()][Alias('ws')]
        [Microsoft.PowerShell.Commands.WebRequestSession]$WebSession = (New-ZenDeskApiSession)
    )
    $base = Get-TrelloApiBaseUri
    $uri  = "$base/cards/$CardId"
    $uri += '?desc='  + $Description
    $uri += '&key='   + $WebSession.Headers.Key
    $uri += '&token=' + $WebSession.Headers.Token
    $params = @{
        Method = 'PUT'
        Uri = $uri
        ErrorAction = 'Stop'
    }
    Set-useUnsafeHeaderParsing
    Write-Verbose "Invoke-RestMethod params:`n$(ConvertTo-Json $params)"
    $response = Invoke-RestMethod @params
    Write-Verbose "Invoke-RestMethod response:`n$(ConvertTo-Json $response)"

    if ($Comment) {
        $uri  = "$base/cards/$CardId/actions/comments"
        $uri += '?text='  + $Comment
        $uri += '&key='   + $WebSession.Headers.Key
        $uri += '&token=' + $WebSession.Headers.Token
        $params = @{
            Method = 'POST'
            Uri = $uri
            ErrorAction = 'Stop'
        }
        Write-Verbose "Invoke-RestMethod params:`n$(ConvertTo-Json $params)"
        $response = Invoke-RestMethod @params
        Write-Verbose "Invoke-RestMethod response:`n$(ConvertTo-Json $response)"
    }

    return $response

}



function Move-TrelloCard {
<#
.SYNOPSIS
    Move existing Trello Card to a List via API.
.DESCRIPTION
    Author   : Dmitry Gancho
    Last edit: 12/8/2015
.PARAMETER CardId
    Required.
    Card Id.
.PARAMETER ListId
    Required.
    List Id the Card to be moved to.
.PARAMETER WebSession
    Optional.
    Authenticated Trello WebSession
.EXAMPLE
    $CardName = 'cloud-lse repo not syncing'
    $MoveToListName = 'Done'
    $BoardName = 'Customer Care'
    $CardId = Search-TrelloObjects -ObjectType Cards -Query $CardName | select -exp cards | select -exp Id
    $BoardId = Search-TrelloObjects -ObjectType Boards -Query $BoardName | select -exp boards | where name -eq $BoardName | select -exp Id
    $ListId = Get-TrelloBoardObjects -BoardId $BoardId -ObjectType Lists | where name -eq $MoveToListName | select -exp Id
    Move-TrelloCard -CardId $CardId -ListId $ListId
.INPUTS
    [string]
    [string]
    [string]
    [Microsoft.PowerShell.Commands.WebRequestSession]
.OUTPUTS
    [Object]
.LINK
    https://developers.trello.com/advanced-reference/card#put-1-cards-card-id-or-shortlink-idlist
#>
    [cmdletbinding()]
    param (
        [Parameter(Mandatory)]
        [string]$CardId,

        [Parameter(Mandatory)]
        [string]$ListId,

        [Parameter()][Alias('ws')]
        [Microsoft.PowerShell.Commands.WebRequestSession]$WebSession = (New-ZenDeskApiSession)
    )
    $base = Get-TrelloApiBaseUri
    # PUT /1/cards/[card id or shortlink]/idList
    $uri  = "$base/cards/$CardId/$ListId"
    $uri += '&key='   + $WebSession.Headers.Key
    $uri += '&token=' + $WebSession.Headers.Token
    $params = @{
        Method = 'PUT'
        Uri = $uri
        ErrorAction = 'Stop'
    }
    Set-useUnsafeHeaderParsing
    Write-Verbose "Invoke-RestMethod params:`n$(ConvertTo-Json $params)"
    $response = Invoke-RestMethod @params
    Write-Verbose "Invoke-RestMethod response:`n$(ConvertTo-Json $response)"

    return $response

}



function Import-TrelloCredential {
<#
.SYNOPSIS
    Import Trello Credential or Key or Secret or Token from HKCU:\Environment\Credentials\Trello
    If not found, then:
    - User: inquire interactively
    - Key,Secret: from 'https://trello.com/app-key'
    - Token: from 'https://trello.com/1/authorize'
.DESCRIPTION
    Author: Dmitry Gancho
    Last edit: 10/3/2015
.PARAMETER Type
    Optional. Default = 'User'
    Either 'User' or 'Key' or 'Secret' or 'Token'
.EXAMPLE
    Get-TrelloCredential -Type User
.EXAMPLE
    Get-TrelloCredential -Type Key
.EXAMPLE
    Get-TrelloCredential -Type Secret
.EXAMPLE
    Get-TrelloCredential -Type Token
.LINK
#>
    [cmdletbinding()]
    param (
        [ValidateSet('User','Key','Secret','Token')]
        [string]$Type='User'
    ) #param


    function New-TrelloKeySecretToken {

        param (
            [Parameter(Mandatory)]
            [string]$UserName,
            [Parameter(Mandatory)]
            [string]$Password
        ) #param

        $loginUrl = 'https://trello.com/login'
        $keyUrl   = 'https://trello.com/app-key'
        $tokenUrl = 'https://trello.com/1/authorize'

        # login with IE
        $ie = New-Object -ComObject InternetExplorer.Application
        #$ie.visible = $true
        # https://msdn.microsoft.com/en-us/library/dd565688%28v=vs.85%29.aspx
        [void]$ie.navigate($loginUrl)
        # wait for ie.document to load
        $n=0; while ($ie.busy -and ($n -lt 100)) {$n++; sleep -m 100}
        $n=0; while (!$ie.document -and ($n -lt 50)) {$n++; sleep -m 100}
        Start-Sleep -Seconds 1

        # if redirected to 'Log in' page
        if ($ie.Document.title -like '*Log in*') {
            $inputs = $ie.document.body.getElementsByTagName('input')
            ($inputs | ? Id -EQ user    ).Value = $UserName
            ($inputs | ? Id -EQ password).Value = $Password
            ($inputs | ? id -EQ login   ).Click()
            # wait for ie.document to load
            $n=0; while ($ie.busy -and ($n -lt 100)) {$n++; sleep -m 100}
            $n=0; while (!$ie.document -and ($n -lt 50)) {$n++; sleep -m 100}
            Start-Sleep -Seconds 1
            if ($ie.Document.title -like '*Log in*') {
                $errMessage  = "`nERROR: Invalid Trello credential"
                $errMessage += "`nUserName: '$username' | Password: '$password'"
                Write-Host -Object $errMessage -ForegroundColor Red
                $ie.visible = $true
                break
            }
        } #if

        # get key and secret
        [void]$ie.Navigate($keyUrl)
        $n=0; while ($ie.busy -and ($n -lt 50)) {$n++; sleep -m 100}
        $n=0; while (!$ie.document -and ($n -lt 50)) {$n++; sleep -m 100}
        Start-Sleep -Seconds 1
        $inputs = $ie.document.body.getElementsByTagName('input')
        $output = @{
            Key    = $inputs | ? Id -Like Key    | select -exp value
            Secret = $inputs | ? Id -Like Secret | select -exp value
        } #@

        # get token
        $tokenUrl += '?key=' + $output.Key
        $tokenUrl += '&name=' + $username + '-TRELLO-API-TOKEN'
        $tokenUrl += '&expiration=never'
        $tokenUrl += '&response_type=token'
        $tokenUrl += '&scope=read,write'
        [void]$ie.Navigate($tokenUrl)
        $n=0; while ($ie.busy -and ($n -lt 50)) {$n++; sleep -m 100}
        $n=0; while (!$ie.document -and ($n -lt 50)) {$n++; sleep -m 100}
        Start-Sleep -Seconds 1

        # find button 'Allow' and click
        $btn = $ie.document.body.getElementsByClassName('primary') | ? Name -EQ Approve
        [void]$btn.click()
        $n=0; while ($ie.busy -and ($n -lt 50)) {$n++; sleep -m 100}
        $n=0; while (!$ie.document -and ($n -lt 50)) {$n++; sleep -m 100}
        $output.Token = ($ie.document.body.getElementsByTagName('pre') | select -exp outerText).Trim()

        [void]$ie.Quit()
        return $output
    } #function


    # HARDCODED VARIABLES:
    $FriendlyName = 'Trello'

    switch -Regex ($Type) {
        'User' {
            $output = Import-Credential -FriendlyName $FriendlyName -NewIfNotFound
            return $output
        } #User
        'Key|Secret|Token' {
            $propName = $_
            $trelloProp = Import-Credential -FriendlyName $friendlyName -EntryName $propName
            if (-not $trelloProp) {
                $cred = Import-TrelloCredential -Type User
                try {
                    $user = $cred.UserName
                    $pass = $cred.GetNetworkCredential().Password
                } catch {
                    return $null
                }
                if ($user -and $pass) {
                    $KeySecretToken = New-TrelloKeySecretToken -UserName $user -Password $pass
                    Export-Credential -FriendlyName $friendlyName -HashTable $KeySecretToken
                    $trelloProp = Import-TrelloCredential -Type $propName
                }
            } #if
            return $trelloProp
        } #Key|Secret|Token
        default {
            return
        } #default
    } #switch
}



function Set-useUnsafeHeaderParsing {
<#
.SYNOPSIS
    Set useUnsafeHeaderParsing flag to to ignore the protocol violations and avoid Trello requests to fail as a result
    Error example: "The server committed a protocol violation. Section=ResponseHeader Detail=CR must be followed by LF"
.DESCRIPTION
    Author   : Dmitry Gancho
    Last edit: 11/10/2015
.EXAMPLE
    Set-useUnsafeHeaderParsing
.INPUTS
    none
.OUTPUTS
    none
.LINK
    https://social.technet.microsoft.com/Forums/security/en-US/8ca2eb90-63fe-4f60-9f00-344fc321383b/simple-invokewebrequest-produces-protocol-violation-when-attempting-to-xml-login-to-a-web-based?forum=winserverpowershell
#>
    [CmdletBinding()]param()
    $netAssembly = [Reflection.Assembly]::GetAssembly([System.Net.Configuration.SettingsSection])
    if ($netAssembly) {
        $bindingFlags = [Reflection.BindingFlags]"Static,GetProperty,NonPublic"
        $settingsType = $netAssembly.GetType('System.Net.Configuration.SettingsSectionInternal')
        $instance = $settingsType.InvokeMember('Section',$bindingFlags,$null,$null,@())
        if ($instance) {
            $bindingFlags = 'NonPublic','Instance'
            $useUnsafeHeaderParsingField = $settingsType.GetField('useUnsafeHeaderParsing',$bindingFlags)
            if($useUnsafeHeaderParsingField) {
                $useUnsafeHeaderParsingField.SetValue($instance,$true)
            }
        }
    }
}





# *** Aliases and Export ***
Export-ModuleMember -Function *


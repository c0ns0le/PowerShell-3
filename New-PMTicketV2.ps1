
<#
    .SYNOPSIS
    Creates new PM Ticket in ZenDesk and corresponding Trello Card
    .DESCRIPTION
    Creates new PM Ticket in ZenDesk and corresponding Trello Card.
    Allows to search existing ZenDesk tickets and Trello cards
    Module 'Credential.psm1' is required and must be in the same directory
    .EXAMPLE
    New-PMTicketV2.ps1
    .EXAMPLE
    New-PMTicketV2.ps1 -Log
    .PARAMETER Log
    Saves ExecutionLog.xml on user's desktop
    .NOTES
    Author: Dmitry Gancho, dmitry.gancho@ctl.io
    Last edit: 10/9/2015
    Version 1.7.1
    .LINK
    https://support.ctl.io/hc/en-us/articles/205236003
        
#>


[CmdletBinding()]
param(
    [switch]$Log = $false
)


#region LIBRARY


    function Out-Log {
        # logging function that saves log in case of errors
        # to be moved out to a module
        # saves log to a file if
        # - Save switch is on, or
        # - Type is TerminatingError
        [CmdLetBinding(DefaultParameterSetName='log')]
        param (
            [Parameter(Mandatory,Position=0,ValueFromPipeline,ParameterSetName='log')]
            [String]$Message,
            [Parameter(ParameterSetName='log')]
            [ValidateSet('TerminatingError','Error','Warning','Verbose')]
            [string]$Type='Verbose',
            [Parameter(ParameterSetName='log')]
            [switch]$PassThru=$false,
            [Parameter()]
            [switch]$New=$false,
            [Parameter(ParameterSetName='stop')]
            [switch]$Stop=$false,
            [Parameter(ParameterSetName='save')]
            [switch]$Save=$false
        )

        # create log variable if not exist
        if ($New -or -not (Test-Path -Path Variable:ExecutionLog)) {
            New-Variable -Name ExecutionLog -Scope Script -Force
            $Script:ExecutionLog = @{
                Header = @{
                    Date          = (Get-Date -Format d)
                    User          = "$Env:USERDOMAIN\$Env:USERNAME"
                    Computer      = $env:COMPUTERNAME
                    PSVersion     = $PSVersionTable.PSVersion
                    #ScriptName    = $MyInvocation.ScriptName
                    PSCommandPath = $MyInvocation.PSCommandPath
                }
                Log = [System.Collections.ArrayList]::new()
            }
            Out-Log -Message "Log Started"
        }

        # add entry
        $Script:ExecutionLog.Log += [PSCUstomObject]@{
            Time     = (Get-Date -Format T)
            Type     = $Type
            Message  = "$(if ($Message) {$Message} else {"Empty Message. Out-Log switches New:{0} Save:{1} Stop:{2}" -f $New,$Save,$Stop})"
            Position = "$($MyInvocation.ScriptName):$($MyInvocation.ScriptLineNumber)"
            #Path     = "$($MyInvocation.PSCommandPath)"
        }
        
        if ($Type -eq 'TerminatingError' -or $Save -or $Stop) {
            # save log?
            if ($Type -eq 'TerminatingError' -or $Save) {
                $path = "$env:USERPROFILE\Desktop\ExecutionLog.xml"
                Export-Clixml -InputObject $Script:ExecutionLog -Path $path -Depth 5 -Force
                Remove-Variable -Name ExecutionLog -Scope Script -Force -ErrorAction SilentlyContinue
                if ($Type -eq 'TerminatingError') {
                    # try get real name from the script
                        $path = $MyInvocation.PSCommandPath
                        if ($path -and (Test-Path -Path $path) -and $(
                            Select-String -Path $path -Pattern (".*Aut"+"hor .*|.*Ow"+"ner .*") -ErrorAction SilentlyContinue | `
                            Tee-Object -Variable results
                        ))   {$developer = $results[0].Line.Trim()}
                        else {$developer = 'Developer'}
                    $errmsg  = "`nTerminating Error. Please e-mail 'ExecutionLog.xml' from your desktop to script $developer"
                    $errmsg += "`n$Message"
                    Write-Host $errmsg -ForegroundColor Red
                }
            }
        }
    } #function


    
    function Set-useUnsafeHeaderParsing {
        # Set useUnsafeHeaderParsing flag to to ignore the protocol violations and avoid Trello requests to fail as a result
        # error example: The server committed a protocol violation. Section=ResponseHeader Detail=CR must be followed by LF
        # ref: https://social.technet.microsoft.com/Forums/security/en-US/8ca2eb90-63fe-4f60-9f00-344fc321383b/simple-invokewebrequest-produces-protocol-violation-when-attempting-to-xml-login-to-a-web-based?forum=winserverpowershell
        [CmdletBinding()] param()
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
                } #if
            } #if
        } #if
    } #function



    function Import-ScriptModule {
        # Import module from the directory
        [CmdletBinding()]
        param (
            [Parameter(Mandatory)]
            [ValidateNotNullOrEmpty()]
            [string]$Name,
            [switch]$Optional=$false,
            [switch]$Force=$false
        )

        # if module alredy loaded and not Force, return
        $module = Get-Module -Name $Name
        if ([bool]$module -and -not $Force) {
            Out-Log -Message "Module '$Name' already loaded"
            return
        }

        # check at script location and import from there if found
        # else try import from $env:PSModulePath
        Out-Log -Message "`$MyInvocation.PSCommandPath: $($MyInvocation.PSCommandPath)"
        if ($MyInvocation.PSCommandPath -and (Test-Path -Path $MyInvocation.PSCommandPath)) {
            $scriptDir = [System.IO.Path]::GetDirectoryName($MyInvocation.PSCommandPath)
        } else {
            $scriptDir = Get-Location | Select-Object -ExpandProperty Path
        }

        if (Test-Path -Path "$scriptDir\$Name*") {
            try {
                $module = Import-Module "$scriptDir\$Name" -PassThru -Force -ErrorAction Stop
                Out-Log -Message "Imported Module '$($module.Path)'"
                return
            } catch {
                $logmsg  = "Module '$Name' found at '$scriptDir' but failed to import"
                $logmsg += "`n" + (Get-Item -Path $scriptDir\$Name | Out-String)
                Out-Log -Message $logmsg -Type Warning
            }
        } else {
            $logmsg  = "Module '$Name' not found at '$scriptDir'. Attempting to import from '`$env:PSModulePath'"
            $logmsg += "`n" + ($env:PSModulePath -split ";")
            Out-Log -Message $logmsg -Type Warning
            try {
                $module = Import-Module $Name -PassThru -Force -ErrorAction Stop
                Out-Log -Message "Imported Module '$($module.Path)'"
                return
            } catch {
                if ($Optional) {
                    Out-Log -Message "Module '$Name' not imported" -Type Warning
                    return
                } else {
                    Out-Log -Message "Module '$Name' not imported" -Type TerminatingError
                    break
                }
            }
        }
    } #function



    function Connect-ZenDeskApi {
        # https://developer.zendesk.com/rest_api/docs/core/introduction
        Out-Log -Message "Connecting ZenDesk API"

        # HARDCODED VARIABLES
        $groupname = 'Triage queue'

        # required ZenDesk credentials:
        # UserName,Token
        Out-Log -Message "Getting ZenDesk UserName"
        $username = Import-ZenDeskCredential -Type User | Select-Object -ExpandProperty UserName
        Out-Log -Message "ZenDesk UserName: $username"

        Out-Log -Message "Getting ZenDesk Token"
        $token = Import-ZenDeskCredential -Type Token
        Out-Log -Message "ZenDesk Token: $token"
        if (-not $token) {
            $errMessage  = "`nERROR Unable to get ZenDesk token. Verify your ZenDesk credential`n"
            $errMessage += "UserName: $(Import-Credential -FriendlyName ZenDesk -EntryName UserName) | "
            $errMessage += "Password: $(Import-Credential -FriendlyName ZenDesk -EntryName Password)"
            Out-Log -Message $errMessage -Type TerminatingError
            break
        }

        # find ZenDesk User and Group
        Out-Log -Message "Getting ZenDesk User $username and Group $groupname objects"
        $headers = New-Object -TypeName 'System.Collections.Generic.Dictionary[[String],[String]]'
        $headers.Add('Accepts','application/json')
        Out-Log -Message "Headers: Accepts:$($headers.Accepts)"
        $headers.Add('Authorization',"Bearer $token")
        Out-Log -Message "Headers: Authorization:$($headers.Authorization)"
        try {
            # find User
            $url = "https://t3n.zendesk.com/api/v2/users.json?query=email:$username"
            $response = Invoke-RestMethod -Method Get -Headers $headers -Uri $url -ContentType application/json -ErrorAction Stop
            if ($response.count -ne 1) {
                $errMessage  = "`nFailed to identify ZenDesk User '$username'"
                $errMessage += "`nZenDesk response: $response"
                Out-Log -Message $errMessage -Type TerminatingError
                break
            } else {
                $user = $response | Select-Object -ExpandProperty Users
                Out-Log -Message "$user"
            }
            # find Group
            $url = 'https://t3n.zendesk.com/api/v2/groups/assignable.json'
            $response = Invoke-RestMethod -Method Get -Headers $headers -Uri $url -ContentType application/json -ErrorAction Stop
            $group = $response | Select-Object -ExpandProperty groups | Where-Object {$_.Name -EQ $groupname}
            if (-not $group) {
                $errMessage  = "`nFailed to identify assignable ZenDesk Group '$groupname'"
                $errMessage += "`nZenDesk response: $response"
                Out-Log -Message $errMessage -Type TerminatingError
                break
            } else {
                Out-Log -Message "$group"
            }
        } catch {
            $errMessage  = "`nFailed calling ZenDesk GET method"
            $errMessage += "`nURL: $url"
            $errMessage += "`nERROR: " + $Error[0].Exception.Message
            Out-Log -Message $errMessage -Type TerminatingError
            break
        }

        # output
        $Data.ZenDesk = @{
            Headers = $headers
            User    = $user
            Group   = $group
        } #@

    } #function



    function Connect-TrelloApi {
        # http://developers.trello.com/advanced-reference

        # HARDCODED VARIABLES
        $boardName = 'Customer Care'
        $listName  = 'New Tasks- Backlog'

        # required Trello credentials:
        # UserName,Key,Token
        Out-Log -Message "Connecting Trello API"
        Out-Log -Message "Getting Trello UserName"
        $username = Import-TrelloCredential -Type User | Select-Object -ExpandProperty UserName -ErrorAction SilentlyContinue
        Out-Log -Message "Trello UserName: $username"
        if (-not $username) {
            $errMessage = "`nERROR: Failed to get Trello UserName"
            Out-Log -Message $errMessage -Type TerminatingError
            break
        }
        Out-Log -Message "Getting Trello Key"
        $key = Import-TrelloCredential -Type Key
        Out-Log -Message "Trello Key: $key"
        if (-not $key) {
            $errMessage = "`nERROR: Failed to get Trello Key"
            Out-Log -Message $errMessage -Type TerminatingError
            break
        }
        Out-Log -Message "Getting Trello Token"
        $token = Import-TrelloCredential -Type Token
        Out-Log -Message "Trello Token: $token"
        if (-not $token) {
            $errMessage = "`nERROR: Failed to get Trello Token"
            Out-Log -Message $errMessage -Type TerminatingError
            break
        }

        Out-Log -Message "Setting useUnsafeHeaderParsing flag"
        Set-useUnsafeHeaderParsing

        try {
            # get board
            Out-Log -Message "Getting Trello board $boardName"
            $url = "https://api.trello.com/1/members/$username/boards?key=$key&token=$token&fields=id,name"
            $response = Invoke-RestMethod -Method Get -Uri $url -ContentType application/json -ErrorAction Stop
            $board = $response | Where-Object {$_.Name -EQ $boardName}
            Out-Log -Message "$board"
            if (-not $board) {
                $errMessage = "`nERROR: Unable to get Trello board '$boardName'"
                Out-Log -Message $errMessage -Type TerminatingError
                break
            }
            $boardId = $board.id
            # get labels
            Out-Log -Message "Getting Trello labels"
            $url = "https://api.trello.com/1/boards/$boardId/labels?key=$key&token=$token&fields=id,color,name"
            [array]$labels = Invoke-RestMethod -Method Get -Uri $url -ContentType application/json -ErrorAction Stop
            if ($labels.count -eq 0) {
                [array]$labels = @{
                    id = $null
                    color = 'Red'
                    name = 'Documentation'
                }
            }
            Out-Log -Message "Labels: $($labels.name -join ',')"
            # get list
            Out-Log -Message "Getting Trello list"
            $url = "https://api.trello.com/1/boards/$boardId/lists?key=$key&token=$token&fields=id,name"
            $lists = Invoke-RestMethod -Method Get -Uri $url -ContentType application/json -ErrorAction Stop
            $list = $lists | Where-Object {$_.Name -EQ $listName}
            Out-Log -Message "$list"
            if (-not $list) {
                $errMessage = "`nERROR: Unable to get Trello list '$listName'"
                Out-Log -Message $errMessage -Type TerminatingError
                break
            }
        } catch {
            $errMessage  = "`nFailed calling Trello method:"
            $errMessage += "`nGET URL: $url"
            $errMessage += "`nERROR: " + $Error[0].Exception.Message
            Out-Log -Message $errMessage -Type TerminatingError
            break
        }

        # output
        $Data.Trello = @{
            Key    = $key
            Token  = $token
            Board  = $board
            Labels = $labels
            List   = $list
            Lists  = $lists
        } #@

    } #function



    function New-ZenDeskTicket {

        function ConvertTo-JsonCompatible {
            param ([string]$string)
            $string -replace "\\","\\" -replace "'","\u0027" -replace """","\"""
        } #function

        $userId  = $Data.ZenDesk.User.id
        $groupid = $Data.ZenDesk.Group.id
        $headers = $Data.ZenDesk.Headers
        $subject =  ConvertTo-JsonCompatible -string $Data.Form.Controls.Item('Subject').Text
        $message = 'Trello card: ' + $Data.Trello.Card.ShortUrl
        $message += "`n`n" + $Data.Form.Controls.Item('Body').Text
        $body    = (ConvertTo-JsonCompatible -string $message) -replace "`n","\n"
        $url     = 'https://t3n.zendesk.com/api/v2/tickets.json'
        $ticketdata = @"
        {"ticket": { "subject":  "$subject", "group_id": "$groupid", "type": "problem", "priority": "low", "comment":  { "body": "$body" },
        "custom_fields":
        [{"id": 20321291,"value": "T3N"},
        {"id":  21619801,"value": "manual_task"},
        {"id":  24305619,"value": "impact_n_a"},
        {"id":  20321657,"value": "T3N"}]
        }
        }
"@
        # invoke POST method to create new ticket
        try {
            Out-Log -Message "Creating new ZenDesk ticket"
            $response = Invoke-RestMethod -Uri $url -Method Post -Headers $headers -Body $ticketdata -ContentType application/json -ErrorAction Stop
            $Data.ZenDesk.Ticket = $response | Select-Object -ExpandProperty ticket
            Out-Log -Message "$($Data.ZenDesk.Ticket)"
        } catch {
            $errMessage  = "`nFailed calling Trello method"
            $errMessage += "`nPOST URL: $url"
            $errMessage += "`nERROR: " + $Error[0].Exception.Message
            Out-Log -Message $errMessage -Type TerminatingError
            break
        }
    } #function



    function New-TrelloCard {
        
        # https://developers.trello.com/apis

        #$trelloBoardId      = $Data.Trello.Board.id
        $trelloLabels       = $Data.Trello.Labels
        $trelloListId       = $Data.Trello.List.id
        $trelloKey          = $Data.Trello.Key
        $trelloToken        = $Data.Trello.Token
        $newCardName        = $Data.Form.Controls.Item('Subject').Text
        $newCardLabels      = $Data.Form.Controls.Find('TrelloLabel',$true) | Where-Object {$_.Checked -eq $true} | Select-Object -ExpandProperty Text
        #$newCardDescription = 'https://t3n.zendesk.com/agent/tickets/' + $Data.ZenDesk.Ticket.id
        $newCardLabelIds    = ($trelloLabels | Where-Object {$_.Name -Match ($newCardLabels -join '|')}).id -join ','

        # create new card
        $url  = 'https://api.trello.com/1/cards/'
        $url += '?idList='   + $trelloListId
        $url += '&name='     + $newCardName
        #$url += '&desc='     + $newCardDescription
        $url += '&key='      + $trelloKey
        $url += '&token='    + $trelloToken
        $url += '&idLabels=' + $newCardLabelIds

        # create new Trello card
        try {
            Out-Log -Message "Creating new Trello card"
            $response = Invoke-RestMethod -Method Post -Uri $url -ContentType application/json -ErrorAction Stop
            $Data.Trello.Card = $response
            Out-Log -Message "$($Data.Trello.Card)"
        } catch {
            $errMessage  = "`nFailed calling Trello method"
            $errMessage += "`nPOST URL: $url"
            $errMessage += "`nERROR: " + $Error[0].Exception.Message
            Out-Log -Message $errMessage -Type TerminatingError
            break
        }

    } #function



    function Update-TrelloCard {
        
        $trelloKey       = $Data.Trello.Key
        $trelloToken     = $Data.Trello.Token

        # update Description
        $cardDescription = 'ZenDesk Ticket: https://t3n.zendesk.com/agent/tickets/' + $Data.ZenDesk.Ticket.id
        $url  = 'https://api.trello.com/1/cards/' + $data.Trello.Card.id
        $url += '?desc='  + $cardDescription
        $url += '&key='   + $trelloKey
        $url += '&token=' + $trelloToken
        try {
            Out-Log -Message "Updating Trello card description"
            $response = Invoke-RestMethod -Method Put -Uri $url -ContentType application/json -ErrorAction Stop
            $Data.Trello.Card = $response
            Out-Log -Message "$($Data.Trello.Card)"
        } catch {
            $errMessage  = "`nFailed calling Trello method:"
            $errMessage += "`nPOST URL: $url"
            $errMessage += "`nERROR: " + $Error[0].Exception.Message
            Out-Log -Message $errMessage -Type TerminatingError
            break
        }

        # add Comment
        $cardComments = $Data.Form.Controls.Item('Body').Text
        $url  = 'https://api.trello.com/1/cards/' + $data.Trello.Card.id + '/actions/comments'
        $url += '?text='  + $cardComments
        $url += '&key='   + $trelloKey
        $url += '&token=' + $trelloToken
        try {
            Out-Log -Message "Updating Trello card description"
            $response = Invoke-RestMethod -Method Post -Uri $url -ContentType application/json -ErrorAction Stop
            $Data.Trello.Comment = $response
            Out-Log -Message "$($Data.Trello.Comment)"
        } catch {
            $errMessage  = "`nFailed calling Trello method:"
            $errMessage += "`nPOST URL: $url"
            $errMessage += "`nERROR: " + $Error[0].Exception.Message
            Out-Log -Message $errMessage -Type TerminatingError
            break
        }
    } #function



    function New-PMDialog {

        Out-Log -Message "Creating new GUI dialog"
        [void][System.Reflection.Assembly]::LoadWithPartialName('System.Drawing')
        [void][System.Reflection.Assembly]::LoadWithPartialName('System.Windows.Forms')
        # enable rich visual styles in PowerShell console mode
        [System.Windows.Forms.Application]::EnableVisualStyles()

        $Title = "PM Ticket / Trello Card Creation"

        # main Form
        $form = New-Object System.Windows.Forms.Form 
        $form.Font = New-Object System.Drawing.Font('Verdana',8)
        $form.Icon = [system.drawing.icon]::ExtractAssociatedIcon("$PSHOME\powershell.exe")
        $form.Text = $Title
        $form.Size = New-Object System.Drawing.Size(500,600) 
        $form.FormBorderStyle = 'FixedDialog' # prevent resize
        $form.StartPosition = 'CenterScreen'
        $form.KeyPreview = $True

        # Subject label
        $control = New-Object System.Windows.Forms.Label
        $control.Text = "Title / Description:"
        $control.Location = New-Object System.Drawing.Size(10,20) 
        $control.Size = New-Object System.Drawing.Size(280,20) 
        $form.Controls.Add($control) 

        # Subject text
        $control = New-Object System.Windows.Forms.TextBox
        $control.Name = 'Subject'
        $control.Text = 'PM: '
        $control.Location = New-Object System.Drawing.Size(10,40)
        $control.Size = New-Object System.Drawing.Size(470,10)
        $form.Controls.Add($control)

        # Body label
        $control = New-Object System.Windows.Forms.Label
        $control.Text = "First Comment:"
        $control.Location = New-Object System.Drawing.Size(10,70) 
        $control.Size = New-Object System.Drawing.Size(280,20) 
        $form.Controls.Add($control) 

        # Body text
        $control = New-Object System.Windows.Forms.RichTextBox 
        $control.Name = 'Body'
        $control.Multiline = $true
        $control.Location = New-Object System.Drawing.Size(10,90) 
        $control.Size = New-Object System.Drawing.Size(470,250)
        $form.Controls.Add($control)

        # Trello label
        $control = New-Object System.Windows.Forms.Label
        $control.Text = "Trello Labels:"
        $control.Location = New-Object System.Drawing.Size(10,350) 
        $control.Size = New-Object System.Drawing.Size(280,20) 
        $form.Controls.Add($control) 

        # Trello checkboxes (categories)
        $colOffset  = 20
        $colSpacing = 220
        $colIndex   = 0
        $colNumber  = 2
        $rowOffset  = 370
        $rowSpacing = 20
        $rowIndex   = 0
        $Data.Trello.Labels | Foreach-Object {
            $control = New-Object System.Windows.Forms.CheckBox
            $control.Name = 'TrelloLabel'
            $control.Text = $_.Name
            $col = $colOffset + $colIndex * $colSpacing
            $row = $rowOffset + $rowIndex * $rowSpacing
            $control.Location = New-Object System.Drawing.Size($col,$row)
            $colIndex ++
            if ($colIndex -eq $colNumber) {
                $colIndex = 0
                $rowIndex ++
            } #if
            $control.Size = New-Object System.Drawing.Size(200,20)
            $form.Controls.Add($control) 
        } #%

        # ZenDesk link label
        $control = New-Object System.Windows.Forms.Label
        $control.Name = 'ZenDeskLinkLabel'
        $control.Text = 'ZenDesk Ticket:'
        $control.Visible = $false
        $control.Location = New-Object System.Drawing.Size(10,430) 
        $control.Size = New-Object System.Drawing.Size(120,20) 
        $form.Controls.Add($control) 

        # ZenDesk link
        $control = New-Object System.Windows.Forms.LinkLabel
        $control.Name = 'ZenDeskLink'
        $control.Visible = $false
        $control.Location = New-Object System.Drawing.Size(130,430)
        $control.Size = New-Object System.Drawing.Size(360,20) 
        $form.Controls.Add($control) 

        # Trello link label
        $control = New-Object System.Windows.Forms.Label
        $control.Name = 'TrelloLinkLabel'
        $control.Text = 'Trello Card:'
        $control.Visible = $false
        $control.Location = New-Object System.Drawing.Size(10,455) 
        $control.Size = New-Object System.Drawing.Size(120,20) 
        $form.Controls.Add($control) 

        # Trello link
        $control = New-Object System.Windows.Forms.LinkLabel
        $control.Name = 'TrelloLink'
        $control.Visible = $false
        $control.Location = New-Object System.Drawing.Size(130,455)
        $control.Size = New-Object System.Drawing.Size(360,20) 
        $form.Controls.Add($control) 

        # Search ZenDesk button
        $control = New-Object System.Windows.Forms.Button
        $control.Name = 'SearchZenDesk'
        $control.Text = 'Search ZenDesk'
        $control.Enabled = $false
        $control.Location = New-Object System.Drawing.Size(10,490)
        $control.Size = New-Object System.Drawing.Size(145,30)
        $form.Controls.Add($control)

        # Search Trello button
        $control = New-Object System.Windows.Forms.Button
        $control.Name = 'SearchTrello'
        $control.Text = 'Search Trello'
        $control.Enabled = $false
        $control.Location = New-Object System.Drawing.Size(165,490)
        $control.Size = New-Object System.Drawing.Size(145,30)
        $form.Controls.Add($control)

        # Publish button
        $control = New-Object System.Windows.Forms.Button
        $control.Name = 'Publish'
        $control.Text = 'Create ZenDesk Ticket and Trello Card'
        $control.Enabled = $false
        $control.Location = New-Object System.Drawing.Size(10,530)
        $control.Size = New-Object System.Drawing.Size(300,30)
        $form.Controls.Add($control)

        # Close button
        $control = New-Object System.Windows.Forms.Button
        $control.Text = 'Close'
        $control.Location = New-Object System.Drawing.Size(400,530)
        $control.Size = New-Object System.Drawing.Size(80,30)
        $form.CancelButton = $control
        $form.Controls.Add($control)

        # populate the Form
        $Data.Form = $form
        Out-Log -Message "Completed"

    } #function



    function New-SearchResultsDialog {
        param (
            [object]$results
        )

        function Get-SearchZenDeskResultsText {
            $ticket = @{
                Name = 'Ticket'
                Expression = {'https://t3n.zendesk.com/agent/tickets/' + $_.id}
            }
            $subject = @{
                Name = 'Subject'
                Expression = {$_.subject}
            }
            $message = @{
                Name = 'Message'
                Expression = {$_.description -replace "\n",' '}
            }
            $assignee = @{
                Name = 'Assignee'
                Expression = {
                    if ($_.assignee_id) {
                        $url = "https://t3n.zendesk.com/api/v2/users/$($_.assignee_id).json"
                        try {
                            Out-Log "GET URL: $url"
                            $response = Invoke-RestMethod -Uri $url -Method Get -Headers $headers -ContentType application/json -ErrorAction Stop
                            $response.user.name
                        } catch {
                            $errMessage = "`nERROR: $($Error[0].Exception.Message)"
                            Out-Log -Message $errMessage -Type Error
                            $null
                        }
                    } else {
                        $url = "https://t3n.zendesk.com/api/v2/groups/$($_.group_id).json"
                        try {
                            Out-Log "GET URL: $url"
                            $response = Invoke-RestMethod -Uri $url -Method Get -Headers $headers -ContentType application/json -ErrorAction Stop
                            $response.group.name
                        } catch {
                            $errMessage = "`nERROR: $($Error[0].Exception.Message)"
                            Out-Log -Message $errMessage -Type Error
                            $null
                        }
                    }
                }
            }
            $updated = @{
                Name = 'Updated'
                Expression = {Get-Date $_.Updated_at -f g}
            }
            $created = @{
                Name = 'Created'
                Expression = {Get-Date $_.Created_at -f g}
            }
            $status = @{
                Name = 'Status'
                Expression = {$_.status.ToUpper()}
            }
            $results | Select-Object $ticket,$status,$created,$updated,$assignee,$subject,$message | Out-String -Width $textWidth
        }

        function Get-SearchTrelloResultsText {
            # get Boards list
            # get Labels list
            $card = @{
                Name = 'Card'
                Expression = {$_.shortUrl}
            }
            $name = @{
                Name = 'Name'
                Expression = {$_.name}
            }
            $desc = @{
                Name = 'Description'
                Expression = {$_.desc}
            }
            $updated = @{
                Name = 'Updated'
                Expression = {Get-Date $_.dateLastActivity -f g}
            }
            $due = @{
                Name = 'Due'
                Expression = {Get-Date $_.due -f g}
            }
            $list = @{
                Name = 'On List'
                Expression = {$Data.Trello.Lists | Where-Object {$_.Id -EQ $_.idList} | Select-Object -ExpandProperty Name}
            }
            $labels = @{
                Name = 'Labels'
                Expression = {($_.idLabels | ForEach-Object {$Data.Trello.Labels | Where-Object {$_.Id -EQ $_}} | `
                    Select-Object -ExpandProperty Name) -join ', '}
            }
            $results | Select-Object $card,$name,$labels,$desc,$updated,$due,$list | Out-String -Width $textWidth
        }

        # main Form
        $textWidth = 78
        $form = New-Object System.Windows.Forms.Form
        $Data.Form.AddOwnedForm($form)
        $form.Font = $Data.Form.Font
        $form.Text = switch ($this.Name) {
            SearchZenDesk {"ZenDesk Search Results"}
            SearchTrello  {"Trello Search Results"}
        }
        $form.Icon = $Data.Form.Icon
        $form.Size = New-Object System.Drawing.Size(600,500)
        $form.KeyPreview = $Data.Form.KeyPreview
        $form.FormBorderStyle = 'FixedDialog' # prevent resize
        $form.StartPosition = 'CenterScreen'
        $form.Location.Offset(50,50)

        # Label
        $control = New-Object System.Windows.Forms.Label
        $control.Text = switch ($this.Name) {
            SearchZenDesk {"Found $($results.count) ZenDesk ticket(s):"}
            SearchTrello  {"Found $($results.count) Trello card(s):"}
        }
        $control.Location = New-Object System.Drawing.Size(10,15)
        $control.Size = New-Object System.Drawing.Size(280,20)
        $form.Controls.Add($control) 

        # Richtextbox
        $control = New-Object System.Windows.Forms.RichTextBox 
        $control.Name = 'Body'
        $control.Font = New-Object System.Drawing.Font('Lucida Console',9)
        $control.Location = New-Object System.Drawing.Size(10,35) 
        $control.Size = New-Object System.Drawing.Size(570,420)
        $control.Text = switch ($this.Name) {
            SearchZenDesk {Get-SearchZenDeskResultsText}
            SearchTrello  {Get-SearchTrelloResultsText}
        }
        $control.ReadOnly = $true
        $control.BackColor = $form.BackColor
        $control.Multiline = $true
        $control.DetectUrls = $true
        $control.Add_LinkClicked({Start-Process $_.LinkText})
        $form.Controls.Add($control)

        #[void]$form.ShowDialog()
        [void]$form.Show()
   } #function



    function Set-PMDialogActions {

        Out-Log -Message "Setting dialog actions"

        #region Dialog shown action
        $Data.Form.Add_Shown({
            $Data.Form.Activate()
            $control = $Data.Form.Controls.Item('Subject')
            [void]$control.Focus()
            $control.SelectionStart = $control.Text.length
            $control.SelectionLength = 0
        })
        #endregion

        #region Subject, Body, Trello labels change actions
        $OnContentChange = {
            $subjtext = $Data.Form.Controls.Item('Subject').Text -replace "(^PM: )|(^\[Documentation\]: )"
            $bodytext = $Data.Form.Controls.Item('Body'   ).Text
            # if ALL below conditions are true, enable Publish button
            #  Subject text: => 5 char
            #  Body text   : => 10 char
            #  Trello label: checked at least one
            $Data.Form.Controls.Item('Publish').Enabled = if (
                $subjtext.Length -ge 5  -and `
                $bodytext.Length -ge 10 -and `
                $Data.Form.Controls.Find('TrelloLabel',$true).Checked -contains $true
            ) {$true} else {$false}
            # if ANY of below conditions are true, enable SearchZenDesk and SearchTrello buttons
            #  Subject text: => 5 char
            $Data.Form.Controls.Item('SearchZenDesk').Enabled = if (
                $subjtext.Length -ge 5
            ) {$true} else {$false}
            $Data.Form.Controls.Item('SearchTrello').Enabled = if (
                $subjtext.Length -ge 5
            ) {$true} else {$false}

            # add / remove '[Documentation]' in Subject
            if ($this.Name -eq 'TrelloLabel' -and $this.Text -eq 'Documentation') {
                $subject = $Data.Form.Controls.Item('Subject')
                $subject.Text = if ($this.Checked) {
                    $subject.Text -replace '^PM: ','[Documentation]: '
                } else {
                    $subject.Text -replace '^\[Documentation\]: ','PM: '
                }
            }

            # validate 'PM: ' or 'PM [Documentation]: ' in subject
            if ($this.Name -eq 'Subject') {
                if (($Data.Form.Controls.Find('TrelloLabel',$true) | Where-Object {$_.Text -eq 'Documentation'}).Checked) {
                    if ($this.Text -notmatch "^\[Documentation\]: .*") {
                        $this.Text = '[Documentation]: '
                        $this.SelectionStart = $this.Text.length
                        $this.SelectionLength = 0
                    }
                } else {
                    if ($this.Text -notmatch "^PM: .*") {
                        $this.Text = 'PM: '
                        $this.SelectionStart = $this.Text.length
                        $this.SelectionLength = 0
                    }
                }
            }
        }
        $Data.Form.Controls.Item('Subject').Add_TextChanged($OnContentChange)
        $Data.Form.Controls.Item('Body'   ).Add_TextChanged($OnContentChange)
        $Data.Form.Controls.Find('TrelloLabel',$true) | Foreach-Object {
            $_.Add_CheckStateChanged($OnContentChange)
        } #%
        #endregion

        #region search for tickets matching Subject
        $OnSearchClick = {
            # search data
            $subjecttext = $Data.Form.Controls.Item('Subject').Text -replace "(^PM: )|(^\[Documentation\]: )"
            $bodytext    = $Data.Form.Controls.Item('Body'   ).Text
            switch ($this.Name) {
                SearchZendesk {
                    # compile URL
                    $filter  = " subject:$subjecttext"
                    $filter += " description:$bodytext"
                    $url = 'https://t3n.zendesk.com/api/v2/search.json?query=type:ticket' + $filter
                    # headers
                    $headers = $data.ZenDesk.Headers
                    # invoke search
                    Out-Log -Message "Searching ZenDesk Tickets"
                    try {
                        $response = Invoke-RestMethod -Uri $url -Method Get -Headers $headers -ContentType application/json -ErrorAction Stop
                    } catch {
                        $errMessage  = "`nZenDesk search failed"
                        $errMessage += "`nURL: $url"
                        $errMessage += "`nERROR: " + $Error[0].Exception.Message
                        Out-Log -Message $errMessage -Type TerminatingError
                        break
                    }
                    Out-Log "Found $($response.count) tickets"
                    New-SearchResultsDialog -results $response.results
                }
                SearchTrello {
                    # compile URL
                    $url  = 'https://api.trello.com/1/search'
                    $url += '?query=' + $subjecttext
                    $url += '&modelTypes=cards'
                    $url += '&key='   + $Data.Trello.Key
                    $url += '&token=' + $Data.Trello.Token

                    # invoke search
                    Out-Log -Message "Searching Trello Cards"
                    try {
                        $response = Invoke-RestMethod -Method Get -Uri $url -ContentType application/json -ErrorAction Stop
                    } catch {
                        $errMessage  = "`nTrello search failed"
                        $errMessage += "`nURL: $url"
                        $errMessage += "`nERROR: " + $Error[0].Exception.Message
                        Out-Log -Message $errMessage -Type Error
                    }
                    Out-Log "Found $($response.cards.Count) cards"
                    New-SearchResultsDialog -results $response.cards
                }
            } 
        }
        $Data.Form.Controls.Item('SearchZenDesk').Add_Click($OnSearchClick)
        $Data.Form.Controls.Item('SearchTrello').Add_Click($OnSearchClick)
        #endregion

        #region Publish button click action
        $OnPublishClick = {

            $OnLinkMouseClick = {
                switch ($_.Button) {
                    Left {
                        $this.Select()
                        Start-Process $this.Text
                        $this.LinkVisited = $true
                    }
                    Right {
                        $this.SelectionStart = 0
                        $this.SelectionLength = $this.Text.length
                        [System.Windows.Forms.Clipboard]::Clear()
                        [System.Windows.Forms.Clipboard]::SetText($this.Text)
                        Start-Sleep -Milliseconds 200
                        $this.SelectionLength = 0
                    }
                }
            }

            # disable Publish button and text boxes and checkboxes
            Out-Log -Message "Disable edit"
            $this.Enabled = $false
            $Data.Form.Controls.Item('Subject').Enabled = $false
            $Data.Form.Controls.Item('Body'   ).Enabled = $false
            $Data.Form.Controls.Find('TrelloLabel',$true) | Foreach-Object {$_.Enabled = $false}

            # create [blank] Trello card
            New-TrelloCard
            # set and show Trello link label
            Out-Log -Message "Display Trello link"
            $Data.Form.Controls.Item('TrelloLinkLabel').Visible = $true
            $linkControl = $Data.Form.Controls.Item('TrelloLink')
            $linkControl.Text = $Data.Trello.Card.shortUrl
            $linkControl.Add_MouseClick({$OnLinkMouseClick})
            $linkControl.Visible = $true

            # create ZenDesk ticket
            New-ZenDeskTicket
            # set and show ZenDesk link label
            Out-Log -Message "Display ZenDesk link"
            $Data.Form.Controls.Item('ZenDeskLinkLabel').Visible = $true
            $linkControl = $Data.Form.Controls.Item('ZenDeskLink')
            $linkControl.Text = 'https://t3n.zendesk.com/agent/tickets/' + $Data.ZenDesk.Ticket.id
            $linkControl.Add_MouseClick({$OnLinkMouseClick})
            $linkControl.Visible = $true

            # update Trello card description and add comment
            Update-TrelloCard
        }
        $Data.Form.Controls.Item('Publish').Add_Click($OnPublishClick)
        #endregion

        Out-Log -Message "Completed"
    } #function



    function Invoke-PMDialog {
        # activate and display the form
        Out-Log -Message "Display dialog"
        [void]$Data.Form.ShowDialog()
        #[void]$Data.Form.Show()
        Out-Log -Message "Exit"
    } #function


#endregion



#region ACTIONS

    # start log
    Out-Log "Executing: $($MyInvocation.MyCommand.Path)" -New
    
    # import module
    Write-Progress -Activity 'Initializing' -Status "Importing modules" -PercentComplete 20
    Import-ScriptModule -Name Credential
    Import-ScriptModule -Name Logging -Optional

    # Create variable to hold all data
    $Data = @{}

    # Connect to ZenDesk
    Write-Progress -Activity 'Initializing' -Status 'Connecting to ZenDesk API' -PercentComplete 30
    Connect-ZenDeskApi

    # Connect to Trello
    Write-Progress -Activity 'Initializing' -Status 'Connecting to Trello API' -PercentComplete 60
    Connect-TrelloApi

    # Build Dialog
    Write-Progress -Activity 'Initializing' -Status 'Creating GUI Dialog' -PercentComplete 80
    New-PMDialog
    
    # Set Dialog actions
    Write-Progress -Activity 'Initializing' -Status 'Setting Dialog Actions' -PercentComplete 90
    Set-PMDialogActions

    # Display Dialog
    Write-Progress -Activity 'Initializing' -Completed
    Invoke-PMDialog

    # save log
    if ($Log) {Out-Log -Save}

#endregion

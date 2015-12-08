<#
    .DESCRIPTION
        Collection of functions to connect and work against MS Exchange Online (Office365) services:
        - MSO (Microsoft Office Online) via Implicit Remote PS Session,
        - EWS (Exchange Web Service) via .NET assembly methods,
        - API (Application Programming Interface) via REST calls.

    .REQUIRED MODULES
        Utility
        Credential

    .NESTED MODULES
        MsOnline

    .REQUIRED ASSEMBLIES
        Microsoft.Exchange.WebServices.dll

    .FUNCTIONS
        New-O365PSSession

        Unblock-SSL
        New-O365EwsService
        Get-O365EwsMailboxFolder
        Find-O365EwsMailboxFolders
        Find-O365EwsCalendarEvents
        Find-O365EwsPublicFolderCalendarEvents
        Get-O365EwsMailMessage
        Move-O365EwsMailMessage
        Get-O365EwsMailMessageHeader
        Remove-O365EwsMailMessage
        Send-O365EwsMailMessage

        Get-O365ApiBaseUri
        New-O365ApiWebSession
        Find-O365ApiCalendarEvents

        Set-O365PublicFolderAccessRightsForDistributionListMembers

    .NOTES
        Company : CenturyLink Cloud
        Author  : Dmitry Gancho, dmitry.gancho@ctl.io

    .LINK
        https://support.ctl.io/hc/en-us/articles/207030123

    .SERVICE
        # F8 to generate module manifest and copy contents of current folder to destination folder
        Publish-ThisModule -Destination "$env:USERPROFILE\Documents\GitHub\toolbox\PowerShell Modules"
#>


#region IMPORT ASSEMBLIES
    # required by EWS functions
    Add-Type -Path $PSScriptRoot\Microsoft.Exchange.WebServices.dll
#endregion    


#region COMMON


#region PS SESSION

function New-O365PSSession {
<#
.SYNOPSIS
    Connect to Exchange Online and import PS session configuration for implicit remoting.
    Imported module name : ExchangeOnline
.DESCRIPTION
    Author    : Dmitry Gancho
    Last edit : 12/4/2015
    Version   : 1.0
.EXAMPLE
    New-O365MSOSession
.INPUTS
    [PSCredential]
.OUTPUTS
    [PSSession]
.LINK
    https://support.ctl.io/hc/en-us/articles/207030123
.LINK
    https://technet.microsoft.com/en-us/magazine/hh750396.aspx
.LINK
    https://technet.microsoft.com/en-us/library/jj200677(v=exchg.160).aspx
#>
    [CmdletBinding()]
    param (
        [PSCredential]$Credential = (Import-Credential -FriendlyName Office365 -NewIfNotFound),
        [switch]$PassThru
    )

    Import-Module "$($MyInvocation.MyCommand.Module.ModuleBase)\MsOnline"
    Connect-MsolService -Credential $Credential
    $param = @{
        ConfigurationName = 'Microsoft.Exchange'
        ConnectionUri = 'https://outlook.office365.com/powershell-liveid/'
        Credential = $Credential
        Authentication = 'Basic'
        AllowRedirection = $true
    }
    $session = New-PSSession @param
    $tempdir = [System.IO.Path]::GetTempPath()
    Export-PSSession -Session $session -OutputModule $tempdir\ExchangeOnline -AllowClobber -Force | Out-Null
    Import-Module $tempdir\ExchangeOnline -DisableNameChecking -Global -Force
    if ($PassThru) {
        return $session
    }
}

#endregion


#region EXCHANGE WEB SERVICE

function Unblock-SSL {
<#
.SYNOPSIS
    Unblock untrusted SSL Certificates.
.DESCRIPTION
    Last edit : 11/26/2015
    Version   : 1.0
.EXAMPLE
    Unblock-SSL
.INPUTS
    none
.OUTPUTS
    none
.LINK
    https://support.ctl.io/hc/en-us/articles/207030123
.LINK
    http://poshcode.org/624
#>
    # create compilation environment
    $provider = New-Object Microsoft.CSharp.CSharpCodeProvider
    $param = New-Object System.CodeDom.Compiler.CompilerParameters
    $param.GenerateExecutable = $False
    $param.GenerateInMemory = $True
    $param.IncludeDebugInformation = $False
    [void]$param.ReferencedAssemblies.Add('system.dll')
    $source = @'
        namespace Local.ToolkitExtensions.Net.CertificatePolicy {
            public class TrustAll : System.Net.ICertificatePolicy {
                public TrustAll() {}
                public bool CheckValidationResult(System.Net.ServicePoint sp,
                System.Security.Cryptography.X509Certificates.X509Certificate cert, 
                System.Net.WebRequest req, int problem) {return true;}
            }
        }
'@ 
    $assembly = $provider.CompileAssemblyFromSource($param,$source).CompiledAssembly
    # create instance of TrustAll and attach to ServicePointManager
    $TrustAll = $assembly.CreateInstance('Local.ToolkitExtensions.Net.CertificatePolicy.TrustAll')
    [System.Net.ServicePointManager]::CertificatePolicy = $TrustAll
}


function New-O365EwsService {
<#
.SYNOPSIS
    Connect to Office365 Exchange serivce via .NET EWS.
.DESCRIPTION
    Author    : Dmitry Gancho
    Last edit : 11/27/2015
    Version   : 1.0
.PARAMETER Credential
.EXAMPLE
    New-O365EwsService
.EXAMPLE
    $Credential = Get-Credential -Message "Enter credential for 'Office365' account:"
    New-O365EwsService -Credential $Credential
.INPUTS
    [PSCredential]
.OUTPUTS
    [Microsoft.Exchange.WebServices.Data.ExchangeService]
.LINK
    https://support.ctl.io/hc/en-us/articles/207030123
.LINK
    https://msdn.microsoft.com/en-us/library/dd635285(v=exchg.80).aspx
#>
    [CmdletBinding()]
    param (
        [PSCredential]$Credential = (Import-Credential -FriendlyName Office365 -NewIfNotFound)
    )

    Unblock-SSL
    # convert [PSCredential] to [NetworkCredential]
    $user = $Credential.UserName
    $pass = $Credential.Password
    $cred = New-Object System.Net.NetworkCredential -ArgumentList $user,$pass

    $version = [Microsoft.Exchange.WebServices.Data.ExchangeVersion]::Exchange2013_SP1
    $service = New-Object Microsoft.Exchange.WebServices.Data.ExchangeService($version)
    #$exchService.UseDefaultCredentials = $true
    $service.Credentials = $cred
    #$service.AutodiscoverUrl($cred.UserName,{$true})
    $service.Url = 'https://outlook.office365.com/EWS/Exchange.asmx'
    return $service
}


function Get-O365EwsMailboxFolder {
<#
.SYNOPSIS
    Get mailbox folder.
.DESCRIPTION
    Author    : Dmitry Gancho
    Last edit : 12/4/2015
    Version   : 1.0
.EXAMPLE
    Get-O365EwsMailboxFolder Inbox -SmtpAddress first.last@ctl.io
.EXAMPLE
    $service = New-O365EwsService -Credential (Get-Credential -Message "Enter credential for 'Office365' account:")
    Get-O365EwsMailboxFolderId -WellKnownName Calendar -ExService $service
.INPUTS
    [string]
    [string]
    [Microsoft.Exchange.WebServices.Data.ExchangeService]
.OUTPUTS
    [Microsoft.Exchange.WebServices.Data.Folder]
.LINK
    https://support.ctl.io/hc/en-us/articles/207030123
#>
    [CmdletBinding(DefaultParameterSetName='unknown')]
    param (
        [Parameter(Position=0,ParameterSetName='unknown')]
        [string]$Name = 'root',

        [Parameter(Position=1)]
        [string]$SmtpAddress,

        [Parameter()]
        [Alias('service')]
        [Microsoft.Exchange.WebServices.Data.ExchangeService]$ExService = (New-O365EwsService)
    )

    DynamicParam {
        $dictionary = New-Object -TypeName System.Management.Automation.RuntimeDefinedParameterDictionary
        
        #region parameter WellKnownFolder
        $paramName = 'WellKnownName'
        $paramType = [string]
        $attributes = New-Object Management.Automation.ParameterAttribute
        $attributes.Position = 0
        $attributes.Mandatory = $true
        $attributes.ParameterSetName = 'known'
        $values = [enum]::GetNames([Microsoft.Exchange.WebServices.Data.WellKnownFolderName])
        $collection = New-Object Collections.ObjectModel.Collection[System.Attribute]
        $collection.Add($Attributes)
        $collection.Add((New-Object Management.Automation.ValidateSetAttribute($values)))
        $parameter = New-Object Management.Automation.RuntimeDefinedParameter($paramName,$paramType,$collection)
        $dictionary.Add($paramName,$parameter)
        #endregion

        $dictionary
    }

    process {
        $ErrorActionPreference = 'Stop'
        if ($PSCmdlet.ParameterSetName -eq 'known') {
            $Name = $dictionary.WellKnownName.Value
        }
        $folderName = [Microsoft.Exchange.WebServices.Data.WellKnownFolderName]::$Name
        $folderId = New-Object Microsoft.Exchange.WebServices.Data.FolderId($folderName,$SmtpAddress)
        [Microsoft.Exchange.WebServices.Data.Folder]::Bind($ExService,$folderId)
    }
}


function Find-O365EwsMailboxFolders {
<#
.SYNOPSIS
    Find mailbox folder.
.DESCRIPTION
    Author    : Dmitry Gancho
    Last edit : 12/4/2015
    Version   : 1.0
.EXAMPLE
    Find-O365EwsMailboxFolders -DisplayName TEST -SmtpAddress first.last@ctl.io
.EXAMPLE
    $service = New-O365EwsService -Credential (Get-Credential -Message "Enter credential for 'Office365' account:")
    Find-O365EwsMailboxFolders -Class IPF.Appointment -ExService $service
.INPUTS
    [Microsoft.Exchange.WebServices.Data.ExchangeService]
.OUTPUTS
    [Microsoft.Exchange.WebServices.Data.Folder[]]
.LINK
    https://support.ctl.io/hc/en-us/articles/207030123
#>
    [CmdletBinding(DefaultParameterSetName='DisplayName')]
    # all schemas: [Microsoft.Exchange.WebServices.Data.FolderSchema]::new().GetEnumerator()
    param (
        [Parameter(Mandatory,Position=0,ParameterSetName='DisplayName')]
        [Alias('name')]
        [string]$DisplayName,

        [Parameter(Mandatory,Position=0,ParameterSetName='FolderClass')]
        [Alias('class')]
        [ValidateSet(
            'IPF.Note',
            'IPF.Post',
            'IPF.Contact',
            'IPF.Activity',
            'IPF.Task',
            'IPF.Appointment'
        )]
        [string]$FolderClass,

        [Parameter(Position=1)]
        [string]$SmtpAddress = $null,

        [Parameter()]
        [Alias('service')]
        [Microsoft.Exchange.WebServices.Data.ExchangeService]$ExService = (New-O365EwsService)
    )

    process {
        $root = Get-O365EwsMailboxFolder -WellKnownName MsgFolderRoot -SmtpAddress $SmtpAddress -ExService $ExService 
        $folderSchema = [Microsoft.Exchange.WebServices.Data.FolderSchema]::($PSCmdlet.ParameterSetName)
        $value = Get-Variable -Name $PSCmdlet.ParameterSetName -ValueOnly    
        $searchFilter = New-Object Microsoft.Exchange.WebServices.Data.SearchFilter+IsEqualTo($folderSchema,$value)
        $folderView = New-Object Microsoft.Exchange.WebServices.Data.FolderView(5)
        $root.FindFolders($searchFilter,$folderView)
    }
}


function Find-O365EwsCalendarEvents {
<#
.SYNOPSIS
    Find appointments in a calendar.
.DESCRIPTION
    Author    : Dmitry Gancho
    Last edit : 12/4/2015
    Version   : 1.0
.EXAMPLE
    $credential = Import-Credential -FriendlyName Office365 -NewIfNotFound
    $service = New-O365EwsService -Credential $credential
    $calendar = Get-O365EwsMailboxFolder -Name Calendar -ExService $service
    $appointments = Find-O365EwsCalendarEvents -StartDate (Get-Date) -EndDate (Get-Date).AddDays(7) -Calendar $calendar
    $appointments | Format-Table Start,End,Subject,Categories,MyResponseType,IsCancelled -AutoSize
.INPUTS
    [DateTime]
    [DateTime]
    [Microsoft.Exchange.WebServices.Data.CalendarFolder]
.OUTPUTS
    [PSObject[]]
.LINK
    https://support.ctl.io/hc/en-us/articles/207030123
#>
    [CmdletBinding()]
    param (
        [Parameter()]
        [Alias('start','from','fr')]
        [DateTime]$StartDate=([datetime]::Now),

        [Parameter()]
        [Alias('end','to')]
        [DateTime]$EndDate,

        [Parameter(Mandatory)]
        [Microsoft.Exchange.WebServices.Data.CalendarFolder]$Calendar
    )

    process {
        # end date
        if (-not $EndDate) {
            $EndDate = $StartDate
        }
        $calendarView = New-Object Microsoft.Exchange.WebServices.Data.CalendarView($StartDate,$EndDate)
        $calendarView.MaxItemsReturned = 1000
        $Calendar.FindAppointments($calendarView)
    }
}


function Find-O365EwsPublicFolderCalendarEvents {
<#
.SYNOPSIS
    Find events in a Public Folder calendar.
.DESCRIPTION
    Author    : Dmitry Gancho
    Last edit : 12/4/2015
    Version   : 1.0
.EXAMPLE
    Find-O365EwsPublicFolderCalendarEvents -PubicFolderName 'Customer Care' -CalendarName 'Customer Care Staffing'
    ------------------------
    This example lists all events in '\Customer Care\Customer Care Staffing' Public Folder Calendar happening now
.EXAMPLE
    $service = New-O365EwsService -Credential (Get-Credential -Message "Enter credential for 'Office365' account:")
    Find-O365EwsPublicFolderCalendarEvents -PubicFolderName 'Customer Care' -CalendarName 'Customer Care Staffing' -StartDate ([datetime]::Today) -EndDate ([datetime]::Today.AddDays(1)) -ExService $service
    ------------------------
    This example lists all events in '\Customer Care\Customer Care Staffing' Public Folder Calendar happening during today
.INPUTS
    [string]
    [string]
    [datetime]
    [datetime]
    [int32]
    [Microsoft.Exchange.WebServices.Data.ExchangeService]
.OUTPUTS
    [PSObject]
.LINK
    https://support.ctl.io/hc/en-us/articles/207030123
#>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]$PubicFolderName, # = 'Customer Care Staffing',

        [Parameter(Mandatory)]
        [string]$CalendarName, # = 'Customer Care',

        [Parameter()]
        [datetime]$StartDate = ([datetime]::Now),

        [Parameter()]
        [datetime]$EndDate,

        [Parameter()]
        [int32]$MaxEvents = 1000,

        [Parameter()]
        [Alias('service')]
        [Microsoft.Exchange.WebServices.Data.ExchangeService]$ExService = (New-O365EwsService)
    )

    # end date
    if (-not $EndDate) {
        $EndDate = $StartDate
    }

    # get Public Folders Root
    $publicFoldersRoot = Get-O365EwsMailboxFolder -WellKnownName PublicFoldersRoot -ExService $ExService

    # find Public Folder
    $folderView   = New-Object Microsoft.Exchange.WebServices.Data.FolderView(1)
    $folderSchema = [Microsoft.Exchange.WebServices.Data.FolderSchema]::DisplayName,$PubicFolderName
    $searchFilter = New-Object Microsoft.Exchange.WebServices.Data.SearchFilter+IsEqualTo($folderSchema)
    $publicFolder = $publicFoldersRoot.FindFolders($searchFilter,$folderView)

    # find Calendar subfolder
    $folderSchema   = [Microsoft.Exchange.WebServices.Data.FolderSchema]::DisplayName,$CalendarName
    $searchFilter   = New-Object Microsoft.Exchange.WebServices.Data.SearchFilter+IsEqualTo($folderSchema)
    $calendarFolder = $publicFolder.FindFolders($searchFilter,$folderView)

    # load folder content
    #$calendarFolder.Load()

    # find events
    $calendarView = New-Object Microsoft.Exchange.WebServices.Data.CalendarView($StartDate,$EndDate,$MaxEvents)
    $events = $calendarFolder.FindAppointments($calendarView)

    $format = @(
        @{
            Label = 'Name'
            Expression = {$_.Subject}
        }
        @{
            Label = 'Location'
            Expression = {$_.Location}
        }
        @{
            Label = 'StartTime'
            Expression = {[datetime]::Parse($_.Start)}
        }
        @{
            Label = 'EndTime'
            Expression = {[datetime]::Parse($_.End)}
        }
    )
    $events | Sort-Object Start | Format-Table $format
}


function Get-O365EwsMailMessage {
<#
	.SYNOPSIS
		This function retrieves messages from an Exchange Mailbox using the EWS Managed API

	.DESCRIPTION

	.PARAMETER  Mailbox
		Specifies the email address of the mailbox to search. If no value is provided, 
		the mailbox of the user running the function will be targeted. When specifying an 
		alternate mailbox you'll need to be assigned the ApplicationImpersonation 
		RBAC role.

	.PARAMETER  SearchQuery
		This parameter allows you to specify a query string based on Advanced
		Query Syntax (AQS). You can use an AQS query to specific properties
		of a message using word phrase restriction, date range restriction,
		and message type restriction. See the following article for details:
		http://msdn.microsoft.com/en-us/library/ee693615.aspx

	.PARAMETER  ResultSize
		Specifies the number of messages that should be returned by your search.
		This values is set to 1000 by default.
		
	.PARAMETER  Folder
		Allows you to specify which well knwon mailbox folder should be searched 
		in your command. If you do not specify a value the Inbox folder will be 
		used.
		
		The following values are valid for this parameter:
		
			Calendar
			Contacts
			DeletedItems
			Drafts
			Inbox
			Journal
			Notes
			Outbox
			SentItems
			Tasks
			MsgFolderRoot
			PublicFoldersRoot
			Root
			JunkEmail
			SearchFolders
			VoiceMail
			RecoverableItemsRoot
			RecoverableItemsDeletions
			RecoverableItemsVersions
			RecoverableItemsPurges
			ArchiveRoot
			ArchiveMsgFolderRoot
			ArchiveDeletedItems
			ArchiveRecoverableItemsRoot
			ArchiveRecoverableItemsDeletions
			ArchiveRecoverableItemsVersions
			ArchiveRecoverableItemsPurges

	.EXAMPLE
		Get-O365EwsMailMessage -ResultSize 10
		
		Description
		-----------
		Retrieves the first 10 messages in the callers Inbox.	

	.EXAMPLE
		Get-O365EwsMailMessage -ResultSize 1 -Mailbox sysadmin@contoso.com
		
		Description
		-----------
		Returns the newest message in the sysadmin Inbox.		
		
	.NOTES

    .LINK
        https://support.ctl.io/hc/en-us/articles/207030123

	.LINK
		http://msdn.microsoft.com/en-us/library/dd633696%28v=EXCHG.80%29.aspx		

#>
	[CmdletBinding()]
    param(
        [Parameter(Position=0)]
		[String]$Mailbox,

        [Parameter(Position=1)]
		[String]$SearchQuery = "*",

        [Parameter(Position=2)]
		[int]$ResultSize = 1000,

        [Parameter(Position=3)]
		[ValidateSet(
			'Calendar',
			'Contacts',
			'DeletedItems',
			'Drafts',
			'Inbox',
			'Journal',
			'Notes',
			'Outbox',
			'SentItems',
			'Tasks',
			'MsgFolderRoot',
			'PublicFoldersRoot',
			'Root',
			'JunkEmail',
			'SearchFolders',
			'VoiceMail',
			'RecoverableItemsRoot',
			'RecoverableItemsDeletions',
			'RecoverableItemsVersions',
			'RecoverableItemsPurges',
			'ArchiveRoot',
			'ArchiveMsgFolderRoot',
			'ArchiveDeletedItems',
			'ArchiveRecoverableItemsRoot',
			'ArchiveRecoverableItemsDeletions',
			'ArchiveRecoverableItemsVersions',
			'ArchiveRecoverableItemsPurges'
		)]
        [string]$Folder = 'Inbox',

        [Parameter(Mandatory)]
        [Alias('service')]
        [Microsoft.Exchange.WebServices.Data.ExchangeService]$ExService
    )
	
    process {
 		# Create a view based on the $ResultSize parameter value
        $view = New-Object Microsoft.Exchange.WebServices.Data.ItemView -ArgumentList $ResultSize
		
		# Define which properties we want to retrieve from each message
        $propertyset = New-Object Microsoft.Exchange.WebServices.Data.PropertySet ([Microsoft.Exchange.WebServices.Data.BasePropertySet]::IdOnly)
        
        $view.PropertySet = $propertyset
		
		# Use FindItems method for the specified folder, AQS query and number of messages
        $items = $service.FindItems($Folder,$SearchQuery,$view)
		
		# Loop through each message returned by FindItems
        $items | %{
			# The FindItem method does not return the message body so we need to bind to 
			# the message using the Bind method of the EmailMessage class
			$emailProps = New-Object Microsoft.Exchange.WebServices.Data.PropertySet ([Microsoft.Exchange.WebServices.Data.BasePropertySet]::FirstClassProperties)
			$emailProps.RequestedBodyType = "Text"
			$email = [Microsoft.Exchange.WebServices.Data.EmailMessage]::Bind($ExService, $_.Id, $emailProps)
            
			# Create a custom object that returns the desired message properties
			New-Object PSObject -Property @{
                Id             = $email.Id.ToString()
                Subject        = $email.Subject
                From           = $email.Sender.Name
                To             = $email.DisplayTo
                Cc             = $email.DisplayCc
                HasAttachments = [bool]$email.HasAttachments
                Sent           = $email.DateTimeSent
                Received       = $email.DateTimeReceived
                Body           = $email.Body
                Mailbox        = $Mailbox
            }
        }
    }
}


function Move-O365EwsMailMessage {
<#
	.SYNOPSIS
		This function uses the EWS Managed API to move an email message 
		from a source folder to a target folder in the same mailbox.
	.DESCRIPTION

	.EXAMPLE
		Get-O365EwsMailMessage -SearchQuery "Subject:'Hello World'" | Move-O365EwsMailMessage -TargetFolder Drafts
		
		Description
		-----------
		Moves all messages with the subject "Hello World" to the drafts 
		folder.

	.EXAMPLE
		Get-O365EwsMailMessage -Folder DeletedItems | Move-O365EwsMailMessage -TargetFolder Inbox -Confirm:$false
		
		Description
		-----------
		Moves the first 1000 messages in the Deleted Items folder to the Inbox 
		without confirmation.
		
    .LINK
        https://support.ctl.io/hc/en-us/articles/207030123

	.LINK
		http://msdn.microsoft.com/en-us/library/dd633696%28v=EXCHG.80%29.aspx		

#>
	[CmdletBinding(SupportsShouldProcess,ConfirmImpact='High')]
    param(
        [Parameter(Position=0,Mandatory,ValueFromPipelineByPropertyName)]
		[string]$Id,

        [Parameter(Position=1,Mandatory,ValueFromPipelineByPropertyName)]
		[string]$Mailbox,

        [Parameter(Position=2,Mandatory)]
		[string]$TargetFolder,

        [Parameter(Mandatory)]
        [Alias('service')]
        [Microsoft.Exchange.WebServices.Data.ExchangeService]$ExService

    )
    
    process {
 		# Create a view for a single item
        $view = New-Object Microsoft.Exchange.WebServices.Data.ItemView -ArgumentList 1
		
		# Create a propertyset specifying only the message id
		$propertyset = New-Object Microsoft.Exchange.WebServices.Data.PropertySet ([Microsoft.Exchange.WebServices.Data.BasePropertySet]::IdOnly)
        $view.PropertySet = $propertyset
		
		# Use the Bind method to create an instance of the message based off the message id
        $item = [Microsoft.Exchange.WebServices.Data.Item]::Bind($ExService, $Id)
        
		# Use the Move method to move the message to the target folder
		# Return the message subject for confirmation and -whatif parameter
		if ($pscmdlet.ShouldProcess($item.Subject)) {
			$item.Move($TargetFolder)
		}
    }
}


function Get-O365EwsMailMessageHeader {
<#
	.SYNOPSIS
		This function retrieves the message headers for a single email message.

	.DESCRIPTION

	.PARAMETER  Id
		Specifies the message id of the message that should be moved.

	.PARAMETER  Mailbox
		Specifies the email address of the mailbox to search. If no value is provided, 
		the mailbox of the user running the function will be targeted. When specifying an 
		alternate mailbox you'll need to be assigned the ApplicationImpersonation 
		RBAC role.

	.EXAMPLE
		Get-EWSMailMessage -ResultSize 1 | Get-EWSMessageHeader
		
		Description
		-----------
		Retrieves the message headers for the first item in the callers Inbox.	

	.EXAMPLE
		Get-EWSMailMessage -SearchQuery "Subject:'Sales meeting on 4/12'" | Get-EWSMessageHeader
		
		Description
		-----------
		Retrieves the message headers for an item with a specific subject in the callers Inbox.		
		
	.NOTES

    .LINK
        https://support.ctl.io/hc/en-us/articles/207030123

	.LINK
		http://msdn.microsoft.com/en-us/library/dd633696%28v=EXCHG.80%29.aspx		

#>
	[CmdletBinding()]
    param(
        [Parameter(Position=0,Mandatory,ValueFromPipelineByPropertyName)]
		[string]$Id,

        [Parameter(Position=1,Mandatory,ValueFromPipelineByPropertyName)]
		[string]$Mailbox,

        [Parameter(Mandatory)]
        [Alias('service')]
        [Microsoft.Exchange.WebServices.Data.ExchangeService]$ExService

    )
    
    process {
		# Create a view for a single item
        $view = New-Object Microsoft.Exchange.WebServices.Data.ItemView -ArgumentList 1
		
		# Create a propertyset specifying only the message headers
        $propertyset = New-Object Microsoft.Exchange.WebServices.Data.PropertySet ([Microsoft.Exchange.WebServices.Data.ItemSchema]::InternetMessageHeaders)
        $view.PropertySet = $propertyset
		
		# Use the Bind method to create an instance of the message based off the message id
        $item = [Microsoft.Exchange.WebServices.Data.Item]::Bind($ExService, $Id, $view.PropertySet)
		
		# Return the message headers
        $item.InternetMessageHeaders
    }
}


function Remove-O365EwsMailMessage {
<#
	.SYNOPSIS
		This function uses the EWS Managed API to delete messages from an Exchange mailbox.

	.DESCRIPTION

	.PARAMETER  Id
		Specifies the message id of the message that should be moved.

	.PARAMETER  Mailbox
		Specifies the email address of the mailbox to search. If no value is provided, 
		the mailbox of the user running the function will be targeted. When specifying an 
		alternate mailbox you'll need to be assigned the ApplicationImpersonation 
		RBAC role.
		
	.PARAMETER  DeleteMode
		Specifies the delete operation that should be performed. The following 
		values are valid for this parameter:
		
			HardDelete
			SoftDelete
			MoveToDeletedItems

	.EXAMPLE
		Get-O365EwsMailMessage -SearchQuery "Subject:'Your Mailbox is Full'" | Remove-O365EwsMailMessage -DeleteMode HardDelete
		
		Description
		-----------
		Removes messages with the specified message subject permanently.		

	.EXAMPLE
		Get-O365EwsMailMessage -SearchQuery "Subject:'Your Mailbox is Full'" | Remove-O365EwsMailMessage -DeleteMode SoftDelete
		
		Description
		-----------
		Removes messages with the specified message subject from the mailbox, but the mailbox 
		owner can restore the message from Recoverable Items.
		
	.EXAMPLE
		Get-O365EwsMailMessage -SearchQuery "Subject:'Your Mailbox is Full'" | Remove-O365EwsMailMessage -DeleteMode MoveToDeletedItems
		
		Description
		-----------
		Moves messages with the specified message subject to the Deleted Items folder.
		
	.NOTES

    .LINK
        https://support.ctl.io/hc/en-us/articles/207030123

	.LINK
		http://msdn.microsoft.com/en-us/library/dd633696%28v=EXCHG.80%29.aspx		

#>
	[CmdletBinding(SupportsShouldProcess,ConfirmImpact='High')]
    param(
        [Parameter(Position=0,Mandatory,ValueFromPipelineByPropertyName)]
		[string]$Id,

        [Parameter(Position=1,Mandatory,ValueFromPipelineByPropertyName)]
		[string]$Mailbox,

        [Parameter(Position=2,Mandatory)]
		[ValidateSet(
			'HardDelete',
			'SoftDelete',
			'MoveToDeletedItems'
		)]
        [string]$DeleteMode='MoveToDeletedItems',

        [Parameter(Mandatory)]
        [Alias('service')]
        [Microsoft.Exchange.WebServices.Data.ExchangeService]$ExService

    )
    
    process {
		# Create a view for a single item
        $view = New-Object Microsoft.Exchange.WebServices.Data.ItemView -ArgumentList 1
		
		# Create a propertyset specifying only the message id
        $propertyset = New-Object Microsoft.Exchange.WebServices.Data.PropertySet ([Microsoft.Exchange.WebServices.Data.BasePropertySet]::IdOnly)
        $view.PropertySet = $propertyset
		
		# Use the Bind method to create an instance of the message based off the message id
        $item = [Microsoft.Exchange.WebServices.Data.Item]::Bind($ExService, $Id)
		
		# Use the Move method to move the message to the target folder
		# Return the message subject for confirmation and -whatif parameter		
		if ($pscmdlet.ShouldProcess($item.Subject)) {
        	$item.Delete($DeleteMode)
		}
    }
}


function Send-O365EwsMailMessage {
<#
	.SYNOPSIS
		This function uses the EWS Managed API to send an email message from an Exchange mailbox.

	.DESCRIPTION
		
	.PARAMETER  To
		Specifies one or more recipient email address.
		
	.PARAMETER  CcRecipients
		Specifies one or more carbon copy recipient email address.

	.PARAMETER  BccRecipients
		Specifies one or more blind copy recipient email address.
		
	.PARAMETER  From
		Specifies the sender email address. If no value is provided, 
		the message will be sent from the callers mailbox. When specifying an 
		alternate email address you'll need to be assigned the 
		ApplicationImpersonation RBAC role.
		
	.PARAMETER  Subject
		Specifies the subject of the email message.
		
	.PARAMETER  Body
		Specifies the body of the email message.	

	.EXAMPLE
		Send-O365EwsMailMessage -To sysadmin@contoso.com -Subject 'Hello World' -Body 'This is a test'
		
		Description
		-----------
		Sends an email message to a single recipient.	

	.EXAMPLE
		$subject = 'Hello World'
		$body = 'This is a test'
		Send-O365EwsMailMessage -To sysadmin@contoso.com,support@contoso.com -Subject $subject -Body $body
		
		Description
		-----------
		Sends an email message to multiple recipients.
		
	.NOTES

    .LINK
        https://support.ctl.io/hc/en-us/articles/207030123

	.LINK
		http://msdn.microsoft.com/en-us/library/dd633696%28v=EXCHG.80%29.aspx		
#>
    [CmdletBinding()]
    param(
        [Parameter(Position=0,Mandatory)]
		[String[]]$To,

        [Parameter(Position=1)]
		[String[]]$CcRecipients,

        [Parameter(Position=2)]
		[String[]]$BccRecipients,

        [Parameter(Position=3)]
		[String]$From,

        [Parameter(Position=4,Mandatory)]
        [String]$Subject,

        [Parameter(Position=5,Mandatory,ValueFromPipeline)]
        [String]$Body,

        [Parameter(Mandatory)]
        [Alias('service')]
        [Microsoft.Exchange.WebServices.Data.ExchangeService]$ExService
        )
	
    process {
		# Create a new email message object
		$mail = New-Object Microsoft.Exchange.WebServices.Data.EmailMessage($ExService)
		
		# Set the subject and body based on function parameters
		$mail.Subject = $Subject
		$mail.Body = $Body
		
		# Loop through each recipient based on function parameters
		$To | ForEach-Object {
            [Void]$mail.ToRecipients.Add($_)
        }
		if ($CcRecipients) {
            $CcRecipients | ForEach-Object {
                [Void]$mail.CcRecipients.Add($_)
            }
        } 
		if ($BccRecipients) {
            $BccRecipients | ForEach-Object {
                [Void]$mail.BccRecipients.Add($_)
            }
        }
		
		# Send the message and save a copy in the sent items folder
		$mail.SendAndSaveCopy()
	}
}


#endregion


#region API

function Get-O365ApiBaseUri {
<#
.SYNOPSIS
    Return base URI to connect to Office365 API v1.0
.DESCRIPTION
    Author    : Dmitry Gancho
    Last edit : 11/26/2015
    Version   : 1.0
.EXAMPLE
    Get-O365ApiBaseUri
.INPUTS
    none
.OUTPUTS
    [string]
.LINK
    https://support.ctl.io/hc/en-us/articles/207030123
#>
    return 'https://outlook.office365.com/api/v1.0'
}


function New-O365ApiWebSession {
<#
.SYNOPSIS
    Return Office365 API authenticated Web Session
.DESCRIPTION
    Author    : Dmitry Gancho
    Last edit : 11/26/2015
    Version   : 1.0
.PARAMETER Credential
.EXAMPLE
    Get-O365ApiWebSession
.INPUTS
    none
.OUTPUTS
    [WebSession]
.LINK
    https://support.ctl.io/hc/en-us/articles/207030123
#>
    [CmdletBinding()]
    param (
        [PSCredential]$Credential = (Import-Credential -FriendlyName Office365 -NewIfNotFound)
    )
    $base = Get-O365ApiBaseUri
    $param = @{
        Uri = "$base/me"
        Credential = $Credential
    }
    $response = Invoke-RestMethod @param -SessionVariable session
    Write-Verbose $response
    return $session
}


function Find-O365ApiCalendarEvents {
<#
.SYNOPSIS
    Get events from own mailbox calendar.
.DESCRIPTION
    Author    : Dmitry Gancho, dmitry@ganco.com
    Last edit : 11/30/2015
    Version   : 1.0
.PARAMETER CalendarName
.PARAMETER StartDate
.PARAMETER EndDate
.PARAMETER WebSession
.INPUTS
    [WebSession]
.OUTPUTS
.LINK
    https://support.ctl.io/hc/en-us/articles/207030123
.LINK
    https://msdn.microsoft.com/office/office365/APi/calendar-rest-operations
#>
    [CmdletBinding()]
    param (
        [Parameter()]
        [string]$CalendarName = 'Calendar',

        [Parameter()]
        [datetime]$StartDate = ([datetime]::Now),

        [Parameter()]
        [datetime]$EndDate,

        [Parameter()]
        [Alias('session')]
        [Microsoft.PowerShell.Commands.WebRequestSession]$WebSession = (New-O365ApiWebSession)
    )

    # end date
    if (-not $EndDate) {
        $EndDate = $StartDate
    }

    # base uri
    $baseUri = Get-O365ApiBaseUri

    # get calendar id
    $param = @{
        Uri = "$baseUri/me/calendars"
        WebSession = $WebSession
    }
    $response = Invoke-RestMethod @param
    $calendar = $response.value | Where-Object Name -EQ $CalendarName
    $Id = $calendar.Id

    # get events
    if (-not $EndDate) {
        $EndDate = $StartDate
    }
    $headers = @{
        Prefer = "outlook.timezone=""Pacific Standard Time"""
    }
    $param = @{
        Headers = $headers
        Uri = "$baseUri/me/calendars/$Id/calendarview?startDateTime=$StartDate&endDateTime=$EndDate"
        WebSession = $WebSession
    }
    # GET https://outlook.office.com/api/v2.0/users/customer.care/calendars/{calendar_id}/calendarview?startDateTime={start_datetime}&endDateTime={end_datetime}
    $response = Invoke-RestMethod @param
    $format = @(
        @{
            Label = 'Name'
            Expression = {$_.Subject}
        }
        @{
            Label = 'Location'
            Expression = {$_.Location.DisplayName}
        }
        @{
            Label = 'Start'
            Expression = {[datetime]::Parse($_.Start)}
        }
        @{
            Label = 'End'
            Expression = {[datetime]::Parse($_.End)}
        }
    )
    $response.Value | Sort-Object Start | Format-Table $format
}

#endregion


#endregion


#region TASKS


function Set-O365PublicFolderAccessRightsForDistributionListMembers {
<#
.SYNOPSIS
    Get list of a Distribution Group members and add them with specified AccessRight to a Public Folder.
    This is a workaround temporary function to be removed when 'Cloud Customer Care' and 'Cloud Customer Care Leads'
    MailEnabledDistributionGroups will be converted to MailEnabledSecurityGroups
.DESCRIPTION
    Author    : Dmitry Gancho
    Last edit : 12/4/2015
    Version   : 1.0
.EXAMPLE
    Set-PublicFolderAccessRightsForDistributionListMembers -DistributionListIdentity 'Cloud Customer Care' -PublicFolderIdentity '\Customer Care\Customer Care Staffing' -AccessRights Reviewer
.EXAMPLE
    Set-PublicFolderAccessRightsForDistributionListMembers -DistributionListIdentity 'Cloud Customer Care Leads' -PublicFolderIdentity '\Customer Care\Customer Care Staffing' -AccessRights PublishingEditor
.INPUTS
    [string]
    [string]
    [string]
.OUTPUTS
    [PSObject[]]
.LINK
    https://support.ctl.io/hc/en-us/articles/207030123
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$DistributionListIdentity,

        [Parameter(Mandatory)]
        [string]$PublicFolderIdentity,

        [Parameter(Mandatory)]
        [ValidateSet('Reviewer','PublishingEditor')]
        [string]$AccessRights
    )

    if (-not (Test-Module ExchangeOnline)) {
        New-O365PSSession
    }

    $users = Get-PublicFolderClientPermission -Identity $PublicFolderIdentity
    $members = Get-DistributionGroupMember -Identity $DistributionListIdentity

    foreach ($member in $members) {
        if ($member.DisplayName -notin $users.User.DisplayName) {
            Add-PublicFolderClientPermission -Identity $PublicFolderIdentity -User $member.DisplayName -AccessRights $AccessRights | Out-Null
        } elseif ($AccessRights -notin (Get-PublicFolderClientPermission -Identity $PublicFolderIdentity -User $member.DisplayName | select -exp AccessRights)) {
            Remove-PublicFolderClientPermission -Identity $PublicFolderIdentity -User $member.DisplayName
            Add-PublicFolderClientPermission -Identity $PublicFolderIdentity -User $member.DisplayName -AccessRights $AccessRights | Out-Null
        }
    }
    Get-PublicFolderClientPermission -Identity $PublicFolderIdentity | Format-Table User,AccessRights -AutoSize
}


#endregion


### Aliases and Export ###
Export-ModuleMember -Function *

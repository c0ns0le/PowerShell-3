<#
    .DESCRIPTION
        Collection of functions for interaction with CenturyLink Cloud Control API.

    .REQUIRED MODULES
        Utility
        Credential
        Infrastructure

    .FUNCTIONS
        New-ControlApi1Session
        New-ControlApi2Session
        Invoke-ControlApi1
        Invoke-ControlApi2

    .NOTES
        Company : CenturyLink Cloud
        Author  : Dmitry Gancho, dmitry.gancho@ctl.io

    .LINK
        https://support.ctl.io/hc/en-us/articles/206757223

    .SERVICE
        # run to generate module manifest and copy contents of current folder to destination forlder
        Publish-ThisModule #-Destination "$env:USERPROFILE\Documents\GitHub\toolbox\Team Scripts\Dmitry Gancho"
#>



function New-ControlApi1Session {
    [CmdLetBinding()]
    param (
        [string]$Api1Key      = $null,
        [string]$Api1Password = $null
    )

    # get creds if not provided
    $regpath = 'HKCU:\Environment\Credentials\Control'
    if ((Test-Path -Path $regpath) -and (&{
        $Script:key  = Get-ItemProperty -Path $regpath | select -exp Api1Key
        $Script:pass = Get-ItemProperty -Path $regpath | select -exp Api1Password
        $Script:key -and $Script:pass
    })) {
        $Api1Key      = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR((ConvertTo-SecureString $Script:key)))
        $Api1Password = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR((ConvertTo-SecureString $Script:pass)))
    } else {
        #region Enter Key/Password form
        [void][System.Reflection.Assembly]::LoadWithPartialName('System.Drawing')
        [void][System.Reflection.Assembly]::LoadWithPartialName('System.Windows.Forms')
        [System.Windows.Forms.Application]::EnableVisualStyles()

        $form = New-Object System.Windows.Forms.Form 
        $form.Text = 'Enter Credentials'
        $form.Size = New-Object System.Drawing.Size(310,190)
        $form.StartPosition = 'CenterScreen'

        $label0 = New-Object System.Windows.Forms.Label
        $label0.Location = New-Object System.Drawing.Size(10,10)
        $label0.Size = New-Object System.Drawing.Size(280,20) 
        $label0.Text = 'Please enter Control APIv1 Key and Password:'
        $form.Controls.Add($label0) 

        $linklabel = New-Object System.Windows.Forms.LinkLabel
        $linklabel.Location = New-Object System.Drawing.Size(40,30)
        $linklabel.Size = New-Object System.Drawing.Size(280,20) 
        $linklabel.Text = 'where do I get these'
        $linklabel.Add_MouseClick({
            $this.Select()
            Start-Process 'https://www.ctl.io/knowledge-base/accounts-&-users/creating-users/'
            $this.LinkVisited = $true
        })
        $form.Controls.Add($linklabel) 

        $label1 = New-Object System.Windows.Forms.Label
        $label1.Location = New-Object System.Drawing.Size(15,60)
        $label1.Size = New-Object System.Drawing.Size(60,20) 
        $label1.Text = 'Key'
        $form.Controls.Add($label1) 

        $label2 = New-Object System.Windows.Forms.Label
        $label2.Location = New-Object System.Drawing.Size(15,90)
        $label2.Size = New-Object System.Drawing.Size(60,20) 
        $label2.Text = 'Password'
        $form.Controls.Add($label2) 

        $textBox1 = New-Object System.Windows.Forms.TextBox
        $textBox1.Location = New-Object System.Drawing.Size(80,60)
        $textBox1.Size = New-Object System.Drawing.Size(200,20)
        $form.Controls.Add($textBox1)

        $textBox2 = New-Object System.Windows.Forms.TextBox
        $textBox2.Location = New-Object System.Drawing.Size(80,90)
        $textBox2.Size = New-Object System.Drawing.Size(200,20)
        $form.Controls.Add($textBox2)

        $OK1Btn = New-Object System.Windows.Forms.Button
        $OK1Btn.Location = New-Object System.Drawing.Size(20,120)
        $OK1Btn.Size = New-Object System.Drawing.Size(80,20)
        $OK1Btn.Text = "OK and Save"
        $OK1Btn.DialogResult = [System.Windows.Forms.DialogResult]::Yes
        $OK1Btn.Add_Click({
            $Api1Key      = $textBox1.Text
            $Api1Password = $textBox2.Text
            $form.Close()
        })
        $form.Controls.Add($OK1Btn)

        $OK2Btn = New-Object System.Windows.Forms.Button
        $OK2Btn.Location = New-Object System.Drawing.Size(110,120)
        $OK2Btn.Size = New-Object System.Drawing.Size(80,20)
        $OK2Btn.Text = "OK"
        $OK2Btn.DialogResult = [System.Windows.Forms.DialogResult]::OK
        $OK2Btn.Add_Click({
            $Api1Key      = $textBox1.Text
            $Api1Password = $textBox2.Text
            $form.Close()
        })
        $form.Controls.Add($OK2Btn)

        $ClBtn = New-Object System.Windows.Forms.Button
        $ClBtn.Location = New-Object System.Drawing.Size(200,120)
        $ClBtn.Size = New-Object System.Drawing.Size(80,20)
        $ClBtn.Text = "Cancel"
        $ClBtn.DialogResult = [System.Windows.Forms.DialogResult]::Cancel
        $ClBtn.Add_Click({$form.Close()})
        $form.Controls.Add($ClBtn)

        $form.KeyPreview = $True
        $form.Add_KeyDown({
            if ($_.KeyCode -eq 'Enter') {
                $Api1Key      = $textBox1.Text
                $Api1Password = $textBox2.Text
                $form.Close()
            }
        })
        $form.Add_KeyDown({
            if ($_.KeyCode -eq 'Escape') {$form.Close()}
        })

        $form.Topmost = $True
        $form.Add_Shown({$form.Activate()})
        #endregion

        switch ($form.ShowDialog()) {
            Yes {
                if (-not (Test-Path -Path $regpath)) {New-Item -Path $regpath -Force | Out-Null}
                $enkey  = $Api1Key      | ConvertTo-SecureString -AsPlainText -Force | ConvertFrom-SecureString
                $enpass = $Api1Password | ConvertTo-SecureString -AsPlainText -Force | ConvertFrom-SecureString
                New-ItemProperty -Path $regpath -Name Api1Key      -Value $enkey  -PropertyType String -Force | Out-Null
                New-ItemProperty -Path $regpath -Name Api1Password -Value $enpass -PropertyType String -Force | Out-Null
            }
            Cancel {
                return $null
            }
        }
    }

    $params = @{
        Uri = 'https://api.ctl.io/REST/Auth/Logon/'
        Method = 'POST'
        ContentType = 'application/json'
        Body = @{
            APIKey   = $Api1Key
            Password = $Api1Password
        }
        SessionVariable = 'webSession'
        ErrorAction = 'Stop'
    }
    Write-Verbose "Invoke-RestMethod params:`n$(ConvertTo-Json $params)"
    $params.Body = ConvertTo-Json $params.Body -Compress
    $response = Invoke-RestMethod @params
    Write-Verbose "Invoke-RestMethod response:`n$(ConvertTo-Json $response)"
    Write-Verbose "WebSession:`n$(ConvertTo-Json $webSession)"
    $successprop = $response | Get-Member -MemberType NoteProperty | Where-Object Name -EQ Success
    if ($successprop -and $successprop.Definition -like '*Success=True*') {
        return $webSession
    } else {
        return $response
    }
}



function New-ControlApi2Session {
    [CmdletBinding()]
    param (
        [Alias('cred')]
        [PSCredential]$Credential
    )
    #region get creds
    if ($Credential) {
        $user = $Credential.Username
        $pass = $Credential.GetNetworkCredential().Password
    } else {
        $regpath = 'HKCU:\Environment\Credentials\Control'
        if ((Test-Path -Path $regpath) -and (&{
            $Script:u = Get-ItemProperty -Path $regpath | select -exp UserName
            $Script:p = Get-ItemProperty -Path $regpath | select -exp Password
            $Script:u -and $Script:p
        })) {
            $user = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR((ConvertTo-SecureString $Script:u)))
            $pass = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR((ConvertTo-SecureString $Script:p)))
        } else {
            $Credential = Get-Credential -Message 'Enter credential for Control:'
            if (-not $Credential) {return $null}
            $user = $Credential.Username
            $pass = $Credential.GetNetworkCredential().Password
            # offer User to save credential
            [void][Reflection.Assembly]::LoadWithPartialName('System.Windows.Forms')
            [System.Windows.Forms.Application]::EnableVisualStyles()
            if ([Windows.Forms.MessageBox]::Show('Save Control credential for future use?','Question',1,'Question') -eq 'OK') {
                if (-not (Test-Path -Path $regpath)) {New-Item -Path $regpath -Force | Out-Null}
                $enuser = $user | ConvertTo-SecureString -AsPlainText -Force | ConvertFrom-SecureString
                $enpass = $pass | ConvertTo-SecureString -AsPlainText -Force | ConvertFrom-SecureString
                New-ItemProperty -Path $regpath -Name UserName -Value $enuser -PropertyType String -Force | Out-Null
                New-ItemProperty -Path $regpath -Name Password -Value $enpass -PropertyType String -Force | Out-Null
            }
        }
    }
    #endregion
    #region login and get websession
    $params = @{
        Method          = 'POST'
        Uri             = 'https://api.ctl.io/v2/authentication/login'
        Body            = @{
            username = $user
            password = $pass
        }
        SessionVariable = 'webSession'
        ErrorAction     = 'Stop'
    } #@
    Write-Verbose "Params: $([pscustomobject]$params)"
    try {
        Write-Verbose "Invoke-RestMethod params:`n$(ConvertTo-Json $params)"
        $response = Invoke-RestMethod @params
        Write-Verbose "Invoke-RestMethod response:`n$(ConvertTo-Json $response)"
        $webSession.Headers.Add('Accept','application/json')
        $webSession.Headers.Add('Authorization',"Bearer $($response.bearerToken)")
        Write-Verbose "WebSession:`n$(ConvertTo-Json $webSession)"
        return $webSession
    } catch {
        throw $_
    }
    #endregion
}



function Invoke-ControlApi1 {

<#
    .SYNOPSIS
        Interaction with api.clt.io via APIv1
    .DESCRIPTION
        Use switch -Help for detailed description
    .EXAMPLE
        Invoke-ControlApi1 -Account GetAccountDetails -AccountAlias T3N
    .EXAMPLE
        Invoke-ControlApi1 -Account GetAccountDetails -Help
    .NOTES
        Author    : Dmitry Gancho, dmitry.gancho@ctl.io
        Last edit : 11/14/2015
        Version   : 1.2
    .LINK
        https://www.ctl.io/api-docs/v1/
#>

    [CmdletBinding(
        SupportsShouldProcess,
        DefaultParameterSetName='__AllParameterSets',
        ConfirmImpact='High'
    )]

    param (

        [Parameter(Mandatory,ParameterSetName='Account')]
        [ValidateSet(
            'CreateAccount',
            'EnableAccount',
            'GetAccountDetails',
            'GetAccounts',
            'GetCustomFields',
            'GetLocations',
            'SuspendAccount',
            'UpdateAccountDetails'
        )]
        [string]$Account,

        [Parameter(Mandatory,ParameterSetName='Billing')]
        [ValidateSet(
            'GetAccountSummary',
            'GetBillingHistory',
            'GetGroupEstimate',
            'GetGroupSummaries',
            'GetInvoiceDetails',
            'GetServerEstimate',
            'GetServerHourlyCharges'
        )]
        [string]$Billing,

        [Parameter(Mandatory,ParameterSetName='Blueprint')]
        [ValidateSet(
            'DeployBlueprint',
            'GetBlueprintDetails',
            'GetBlueprintParameters',
            'GetBlueprints',
            'GetDeploymentStatus',
            'GetPackages',
            'GetPendingPackages',
            'PublishPackage'
        )]
        [string]$Blueprint,

        [Parameter(Mandatory,ParameterSetName='Group')]
        [ValidateSet(
            'ArchiveHardwareGroup',
            'CreateHardwareGroup',
            'DeleteHardwareGroup',
            'GetGroups',
            'HardwareGroupMaintenance',
            'PauseHardwareGroup',
            'PowerOffHardwareGroup',
            'PowerOnHardwareGroup',
            'RebootHardwareGroup',
            'ResetHardwareGroup',
            'RestoreHardwareGroup',
            'ShutdownHardwareGroup'
        )]
        [string]$Group,

        [Parameter(Mandatory,ParameterSetName='Network')]
        [ValidateSet(
            'AddPublicIPAddress',
            'GetAccountNetworks',
            'GetDeployableNetworks',
            'GetNetworkDetails',
            'GetNetworks',
            'UpdatePublicIPAddress'
        )]
        [string]$Network,

        [Parameter(Mandatory,ParameterSetName='Queue')]
        [ValidateSet(
            'GetRequestStatus',
            'ListQueueRequests'
        )]
        [string]$Queue,

        [Parameter(Mandatory,ParameterSetName='Server')]
        [ValidateSet(
            'ArchiveServer',
            'ChangePassword',
            'ConfigureServer',
            'ConvertServerToTemplate',
            'ConvertTemplateToServer',
            'CreateServer',
            'DeleteDisk',
            'DeleteServer',
            'DeleteSnapshot',
            'DeleteTemplate',
            'GetAllServersForAccountHierarchyByModifiedDates',
            'GetAllServers',
            'GetAllServersByModifiedDates',
            'GetAllServersForAccountHierarchy',
            'GetArchiveServers',
            'GetServer',
            'GetServerCredentials',
            'GetServers',
            'GetServersByModifiedDates',
            'GetServerTemplates',
            'GetSnapshots',
            'ListArchivedServers',
            'ListAvailableServerTemplates',
            'ListDisks',
            'PauseServer',
            'PowerOffServer',
            'PowerOnServer',
            'RebootServer',
            'ResetServer',
            'ResizeDisk',
            'RestoreServer',
            'RevertToSnapshot',
            'ServerMaintenance',
            'ShutdownServer',
            'SnapshotServer'
        )]
        [string]$Server,

        [Parameter(Mandatory,ParameterSetName='SMTPRelay')]
        [ValidateSet(
            'CreateAlias',
            'DisableAlias',
            'GetInvalidAddresses',
            'ListAliases',
            'RemoveAlias'
        )]
        [string]$SMTPRelay,

        [Parameter(Mandatory,ParameterSetName='User')]
        [ValidateSet(
            'CreateUser',
            'DeleteUser',
            'GetUserDetails',
            'GetUsers',
            'SuspendUser',
            'UnsuspendUser',
            'UpdateUser'
        )]
        [string]$User,

        [Parameter()][Alias('ws')]
        [Microsoft.PowerShell.Commands.WebRequestSession]$WebSession = (New-ControlApi1Session),

        [Parameter()]
        [switch]$Force,

        [Parameter()]
        [switch]$Json,

        [Parameter()]
        [switch]$Help
    )

    DynamicParam {

        function add-parameter {
            param (
                [string]$name,
                [type]$type=[string],
                [string[]]$values,
                [switch]$mandatory
            )
            $attributes = New-Object -TypeName System.Management.Automation.ParameterAttribute
            $attributes.Mandatory = if ($Help) {$false} else {$mandatory}
            $attributes.ParameterSetName = $PSCmdlet.ParameterSetName
            $attributes.HelpMessage = if ($mandatory) {'mandatory'} else {'optional'}
            $collection = New-Object -TypeName System.Collections.ObjectModel.Collection[System.Attribute]
            $collection.Add($Attributes)
            if ($values) {$collection.Add((New-Object -TypeName System.Management.Automation.ValidateSetAttribute($values)))}
            $parameter = New-Object -TypeName System.Management.Automation.RuntimeDefinedParameter($name,$type,$collection)
            $dictionary.Add($name,$parameter)
        }

        # define dictionary
        $dictionary = New-Object -TypeName System.Management.Automation.RuntimeDefinedParameterDictionary
        # define enumerator
        $enum = @{
            DataCenters = 'CA1','CA2','CA3','DE1','GB1','GB3','IL1','NE1','NY1','SG1','UC1','UT1','VA1','WA1'
            HelpUri = 'https://www.ctl.io/api-docs/v1/'
        }
        # define value for switch $Help (used in add-parameter)
        if (-not (Test-Path Variable:Help)) {$Help = $false}
        # define action 
        $action = Get-Variable -Name $PSCmdlet.ParameterSetName -ValueOnly -ErrorAction Ignore
        # define other parameters
        switch -Exact ($PSCmdlet.ParameterSetName) {
            Account {
                switch -Exact ($action) {
                    CreateAccount {
                        $enum.HelpUri += '#account-create-account'
                        $enum.Status = @{
                            1 = 'Active'
                            0 = 'Inactive'
                        }
                        $enum.TimeZone = @(
                            'Dateline Standard Time'
                            'UTC-11'
                            'Hawaiian Standard Time'
                            'Alaskan Standard Time'
                            'Pacific Standard Time (Mexico)'
                            'Pacific Standard Time'
                            'US Mountain Standard Time'
                            'Mountain Standard Time (Mexico)'
                            'Mountain Standard Time'
                            'Central America Standard Time'
                            'Central Standard Time'
                            'Central Standard Time(Mexico)'
                            'Canada Central Standard Time'
                            'SA Pacific Standard Time'
                            'Eastern Standard Time'
                            'US Eastern Standard Time'
                            'Venezuela Standard Time'
                            'Paraguay Standard Time'
                            'Atlantic Standard Time'
                            'Central Brazilian Standard Time'
                            'SA Western Standard Time'
                            'Pacific SA Standard Time'
                            'Newfoundland Standard Time'
                            'E. South America Standard Time'
                            'Argentina Standard Time'
                            'SA Eastern Standard Time'
                            'Greenland Standard Time'
                            'Montevideo Standard Time'
                            'Bahia Standard Time'
                            'UTC-02'
                            'Mid-Atlantic Standard Time'
                            'Azores Standard Time'
                            'Cape Verde Standard Time'
                            'Morocco Standard Time'
                            'UTC'
                            'GMT Standard Time'
                            'Greenwich Standard Time'
                            'W. Europe Standard Time'
                            'Central Europe Standard Time'
                            'Romance Standard Time'
                            'Central European Standard Time'
                            'W. Central Africa Standard Time'
                            'Namibia Standard Time'
                            'Jordan Standard Time'
                            'GTB Standard Time'
                            'Middle East Standard Time'
                            'Egypt Standard Time'
                            'Syria Standard Time'
                            'South Africa Standard Time'
                            'FLE Standard Time'
                            'Turkey Standard Time'
                            'Israel Standard Time'
                            'E. Europe Standard Time'
                            'Arabic Standard Time'
                            'Kaliningrad Standard Time'
                            'Arab Standard Time'
                            'E. Africa Standard Time'
                            'Iran Standard Time'
                            'Arabian Standard Time'
                            'Azerbaijan Standard Time'
                            'Russian Standard Time'
                            'Mauritius Standard Time'
                            'Georgian Standard Time'
                            'Caucasus Standard Time'
                            'Afghanistan Standard Time'
                            'Pakistan Standard Time'
                            'West Asia Standard Time'
                            'India Standard Time'
                            'Sri Lanka Standard Time'
                            'Nepal Standard Time'
                            'Central Asia Standard Time'
                            'Bangladesh Standard Time'
                            'Ekaterinburg Standard Time'
                            'Myanmar Standard Time'
                            'SE Asia Standard Time'
                            'N. Central Asia Standard Time'
                            'China Standard Time'
                            'North Asia Standard Time'
                            'Singapore Standard Time'
                            'W. Australia Standard Time'
                            'Taipei Standard Time'
                            'Ulaanbaatar Standard Time'
                            'North Asia East Standard Time'
                            'Tokyo Standard Time'
                            'Korea Standard Time'
                            'Cen. Australia Standard Time'
                            'AUS Central Standard Time'
                            'E. Australia Standard Time'
                            'AUS Eastern Standard Time'
                            'West Pacific Standard Time'
                            'Tasmania Standard Time'
                            'Yakutsk Standard Time'
                            'Central Pacific Standard Time'
                            'Vladivostok Standard Time'
                            'New Zealand Standard Time'
                            'UTC+12'
                            'Fiji Standard Time'
                            'Magadan Standard Time'
                            'Kamchatka Standard Time'
                            'Tonga Standard Time'
                            'Samoa Standard Time'
                        )
                        add-parameter -name ParentAlias -mandatory
                        add-parameter -name AccountAlias
                        add-parameter -name Location -mandatory -values $enum.DataCenters
                        add-parameter -name BusinessName -mandatory
                        add-parameter -name Address1 -mandatory
                        add-parameter -name Address2
                        add-parameter -name City -mandatory
                        add-parameter -name StateProvince -mandatory
                        add-parameter -name PostalCode -mandatory
                        add-parameter -name Country -mandatory
                        add-parameter -name Telephone -mandatory
                        add-parameter -name Fax
                        add-parameter -name TimeZone -values $enum.TimeZone
                        add-parameter -name ShareParentNetworks -mandatory -type ([bool])
                        add-parameter -name BillingResponsibilityID -mandatory -values 1,2
                    }
                    EnableAccount {
                        $enum.HelpUri += '#account-enable-account'
                        add-parameter -name AccountAlias -mandatory
                    }
                    GetAccountDetails {
                        $enum.HelpUri += '#account-getaccountdetails'
                        $enum.Status = @{
                            1 = 'Active'
                            2 = 'Disabled'
                            3 = 'Deleted'
                            4 = 'Demo'
                        }
                        add-parameter -name AccountAlias -mandatory
                    }
                    GetAccounts {
                        $enum.HelpUri += '#account-getaccounts'
                    }
                    GetCustomFields {
                        $enum.HelpUri += '#account-getcustomfields'
                        add-parameter -name AccountAlias -mandatory
                    }
                    GetLocations {
                        $enum.HelpUri += '#account-getlocations'
                    }
                    SuspendAccount {
                        $enum.HelpUri += '#account-suspendaccount'
                        add-parameter -name AccountAlias -mandatory
                    }
                    UpdateAccountDetails {
                        $enum.HelpUri += '#account-updateaccountdetails'
                        $enum.Status = @{
                            1 = 'Active'
                            0 = 'Inactive'
                        }
                        add-parameter -name AccountAlias -mandatory
                        add-parameter -name BusinessName -mandatory
                        add-parameter -name Address1 -mandatory
                        add-parameter -name Address2
                        add-parameter -name City -mandatory
                        add-parameter -name StateProvince -mandatory
                        add-parameter -name PostalCode -mandatory
                        add-parameter -name Country -mandatory
                        add-parameter -name Telephone -mandatory
                        add-parameter -name Fax
                        add-parameter -name TimeZone -mandatory -values $enum.TimeZone
                        add-parameter -name ShareParentNetworks -mandatory -type ([bool])
                        add-parameter -name BillingResponsibilityID -mandatory -values 1,2
                    }
                }
            }
            Billing {
                switch -Exact ($action) {
                    GetAccountSummary {
                        $enum.HelpUri += '#billing-getaccountsummary'
                        add-parameter -name AccountAlias -mandatory
                    }
                    GetBillingHistory {
                        $enum.HelpUri += '#billing-getbillinghistory'
                        add-parameter -name AccountAlias -mandatory
                    }
                    GetGroupEstimate {
                        $enum.HelpUri += '#billing-getgroupestimate'
                        add-parameter -name AccountAlias
                        add-parameter -name HardwareGroupUUID -mandatory
                    }
                    GetGroupSummaries {
                        $enum.HelpUri += '#billing-getgroupsummaries'
                        add-parameter -name AccountAlias
                        add-parameter -name StartDate
                        add-parameter -name EndDate
                    }
                    GetInvoiceDetails {
                        $enum.HelpUri += '#billing-getinvoicedetails'
                        add-parameter -name AccountAlias -mandatory
                        add-parameter -name InvoiceID -mandatory
                    }
                    GetServerEstimate {
                        $enum.HelpUri += '#billing-getserverestimate'
                        add-parameter -name AccountAlias
                        add-parameter -name ServerName -mandatory
                    }
                    GetServerHourlyCharges {
                        $enum.HelpUri += '#billing-getserverhourlycharges'
                        add-parameter -name AccountAlias
                        add-parameter -name ServerName -mandatory
                        add-parameter -name StartDate
                        add-parameter -name EndDate
                    }
                }
            }
            Blueprint {
                switch -Exact ($action) {
                    DeployBlueprint {
                        $enum.HelpUri += '#blueprint-deploy-blueprint'
                        add-parameter -name ID -mandatory
                        add-parameter -name LocationAlias -values $enum.DataCenters
                        add-parameter -name Parameters
                        add-parameter -name CustomFields
                    }
                    GetBlueprintDetails {
                        $enum.HelpUri += '#blueprint-get-blueprint-details'
                        $enum.Status = @{
                            1 = 'Active'
                            3 = 'Deleted'
                            4 = 'Under Construction'
                        }
                        $enum.Visibility = @{
                            1 = 'Public'
                            2 = 'Private'
                        }
                        add-parameter -name ID -mandatory
                    }
                    GetBlueprintParameters {
                        $enum.HelpUri += '#blueprint-get-blueprint-parameters'
                        $enum.Type = @{
                            1 = 'Network'
                            2 = 'Numeric'
                            3 = 'Option'
                            4 = 'Password'
                            5 = 'Server'
                            6 = 'ServerIP'
                            7 = 'String'
                            8 = 'MultiSelect'
                        }
                        add-parameter -name ID -mandatory
                    }
                    GetBlueprints {
                        $enum.HelpUri += '#blueprint-get-blueprints'
                        add-parameter -name CompanySize -values 1,2,3,4
                        add-parameter -name OperatingSystems -values 6,7,21,13,14,19,20,15,16,2,3,4,5,17,18
                        add-parameter -name Search
                        add-parameter -name Visibility -values 1,2,3
                    }
                    GetDeploymentStatus {
                        $enum.HelpUri += '#blueprint-get-deployment-status'
                        add-parameter -name RequestID -mandatory
                        add-parameter -name LocationAlias -values $enum.DataCenters
                        add-parameter -name AccountAlias -mandatory
                    }
                    GetPackages {
                        $enum.HelpUri += '#blueprint-get-packages'
                        $enum.Classification = @{
                            1 = 'System'
                            2 = 'Script'
                            3 = 'Software'
                        }
                        add-parameter -name Classification -mandatory -values 1,2,3
                        add-parameter -name Visibility -mandatory -values 1,2,3
                    }
                    GetPendingPackages {
                        $enum.HelpUri += '#blueprint-get-pending-packages'
                        $enum.Classification = @{
                            0 = 'Pending'
                        }
                    }
                    PublishPackage {
                        $enum.HelpUri += '#blueprint-publish-package'
                        add-parameter -name Classification -mandatory -values 1,2,3
                        add-parameter -name Name -mandatory
                        add-parameter -name OperatingSystems -mandatory -values 2,3,5,15,16,18,20,25,26,27,28,29,30,31,32,33,34,35,36,37,38,40,41
                        add-parameter -name Visibility -mandatory -values 1,2,3
                    }
                }
            }
            Group {
                switch -Exact ($action) {
                    ArchiveHardwareGroup {
                        $enum.HelpUri += '#group-archivehardwaregroup'
                        add-parameter -name AccountAlias
                        add-parameter -name UUID -mandatory
                    }
                    CreateHardwareGroup {
                        $enum.HelpUri += '#group-createhardwaregroup'
                        add-parameter -name AccountAlias -mandatory
                        add-parameter -name ParentUUID -mandatory
                        add-parameter -name Name
                        add-parameter -name Description
                    }
                    DeleteHardwareGroup {
                        $enum.HelpUri += '#group-deletehardwaregroup'
                        add-parameter -name AccountAlias
                        add-parameter -name UUID -mandatory
                    }
                    GetGroups {
                        $enum.HelpUri += '#group-getgroups'
                        add-parameter -name AccountAlias
                        add-parameter -name Location -mandatory -values $enum.DataCenters
                    }
                    HardwareGroupMaintenance {
                        $enum.HelpUri += '#group-hardwaregroupmaintenance'
                        add-parameter -name AccountAlias
                        add-parameter -name UUID -mandatory
                        add-parameter -name Enable -type ([bool])
                    }
                    PauseHardwareGroup {
                        $enum.HelpUri += '#group-pausehardwaregroup'
                        add-parameter -name AccountAlias
                        add-parameter -name UUID -mandatory
                    }
                    PowerOffHardwareGroup {
                        $enum.HelpUri += '#group-poweroffhardwaregroup'
                        add-parameter -name AccountAlias
                        add-parameter -name UUID -mandatory
                    }
                    PowerOnHardwareGroup {
                        $enum.HelpUri += '#group-poweronhardwaregroup'
                        add-parameter -name AccountAlias
                        add-parameter -name UUID -mandatory
                    }
                    RebootHardwareGroup {
                        $enum.HelpUri += '#group-reboothardwaregroup'
                        add-parameter -name AccountAlias
                        add-parameter -name UUID -mandatory
                    }
                    ResetHardwareGroup {
                        $enum.HelpUri += '#group-resethardwaregroup'
                        add-parameter -name AccountAlias
                        add-parameter -name UUID -mandatory
                    }
                    RestoreHardwareGroup {
                        $enum.HelpUri += '#group-restorehardwaregroup'
                        add-parameter -name AccountAlias
                        add-parameter -name UUID -mandatory
                        add-parameter -name ParentUUID -mandatory
                    }
                    ShutdownHardwareGroup {
                        $enum.HelpUri += '#group-shutdownhardwaregroup'
                        add-parameter -name AccountAlias
                        add-parameter -name UUID -mandatory
                    }
                }
            }
            Network {
                switch -Exact ($action) {
                    AddPublicIPAddress {
                        $enum.HelpUri += '#network-addpublicipaddress'
                        add-parameter -name AccountAlias
                        add-parameter -name ServerName -mandatory
                        add-parameter -name IPAddress -mandatory
                        add-parameter -name AllowHTTP -type ([switch])
                        add-parameter -name AllowHTTPonPort8080 -type ([switch])
                        add-parameter -name AllowHTTPS -type ([switch])
                        add-parameter -name AllowFTPS -type ([switch])
                        add-parameter -name AllowSFTP -type ([switch])
                        add-parameter -name AllowSSH -type ([switch])
                        add-parameter -name AllowRDP -type ([switch])
                    }
                    GetAccountNetworks {
                        $enum.HelpUri += '#network-getaccountnetworks'
                        add-parameter -name AccountAlias
                        add-parameter -name Location -values $enum.DataCenters
                    }
                    GetDeployableNetworks {
                        $enum.HelpUri += '#network-getdeployablenetworks'
                        add-parameter -name AccountAlias
                        add-parameter -name Location -values $enum.DataCenters
                    }
                    GetNetworkDetails {
                        $enum.HelpUri += '#network-getnetworkdetails'
                        add-parameter -name AccountAlias
                        add-parameter -name Location -values $enum.DataCenters
                        add-parameter -name Name -mandatory
                    }
                    GetNetworks {
                        $enum.HelpUri += '#network-getnetworks'
                        add-parameter -name AccountAlias
                        add-parameter -name Location -values $enum.DataCenters
                    }
                    UpdatePublicIPAddress {
                        $enum.HelpUri += '#network-updatepublicipaddress'
                        add-parameter -name AccountAlias
                        add-parameter -name ServerName -mandatory
                        add-parameter -name PublicIPAddress -mandatory
                        add-parameter -name AllowHTTP -type ([switch])
                        add-parameter -name AllowHTTPonPort8080 -type ([switch])
                        add-parameter -name AllowHTTPS -type ([switch])
                        add-parameter -name AllowFTPS -type ([switch])
                        add-parameter -name AllowSFTP -type ([switch])
                        add-parameter -name AllowSSH -type ([switch])
                        add-parameter -name AllowRDP -type ([switch])
                    }
                }
            }
            Queue {
                switch -Exact ($action) {
                    GetRequestStatus {
                        $enum.HelpUri += '#queue-getrequeststatus'
                        add-parameter -name RequestID -mandatory
                    }
                    ListQueueRequests {
                        $enum.HelpUri += '#queue-listqueuerequests'
                        add-parameter -name ItemStatusType -mandatory -values 1,2,3,4
                    }
                }
            }
            Server {
                $enum.Status = @{
                    1 = 'Standard'
                    2 = 'Premium'
                }
                $enum.ServerType = @{
                    1 = 'Standard'
                    2 = 'Premium'
                }
                $enum.ServiceLevel = @{
                    1 = 'Standard'
                    2 = 'Premium'
                }
                $enum.OperatingSystem = @{
                    2  = 'Windows 2003 32-bit'
                    3  = 'Windows 2003 64-bit'
                    4  = 'Windows 2008 32-bit'
                    5  = 'Windows 2008 64-bit'
                    6  = 'CentOS 32-bit'
                    7  = 'CentOS 64-bit'
                    8  = 'Windows XP 32-bit'
                    9  = 'Windows Vista 32-bit'
                    10 = 'Windows Vista 64-bit'
                    11 = 'Windows 7 32-bit'
                    12 = 'Windows 7 64-bit'
                    13 = 'FreeBSD 32-bit'
                    14 = 'FreeBSD 64-bit'
                    15 = 'Windows 2003 Enterprise 32-bit'
                    16 = 'Windows 2003 Enterprise 64-bit'
                    17 = 'Windows 2008 Enterprise 32-bit'
                    18 = 'Windows 2008 Enterprise 64-bit'
                    19 = 'Ubuntu 32-bit'
                    20 = 'Ubuntu 64-bit'
                    21 = 'Debian 64-bit'
                    22 = 'RedHat Enterprise Linux 64-bit'
                    25 = 'RedHat Enterprise Linux 5 64-bit'
                    27 = 'Windows 2012 Datacenter 64-bit'
                    28 = 'Windows 2012 R2 Datacenter 64-Bit'
                    31 = 'Ubuntu 12 64-Bit'
                    33 = 'CentOS 5 64-Bit'
                    35 = 'CentOS 6 64-Bit'
                    36 = 'Debian 6 64-Bit'
                    37 = 'Debian 7 64-Bit'
                    38 = 'RedHat 6 64-Bit'
                    39 = 'CoreOS'
                    40 = 'PXE Boot'
                    41 = 'Ubuntu 14 64-Bit'
                    42 = 'RedHat 7 64-Bit'
                    43 = 'Windows 2008 R2 Standard 64-Bit'
                    44 = 'Windows 2008 R2 Enterprise 64-Bit'
                    45 = 'Windows 2008 R2 Datacenter 64-Bit'
                }
                $enum.PowerState = @{
                    0 = 'Stopped'
                    1 = 'Started'
                    2 = 'Paused'
                }
                switch ($action) {
                    ArchiveServer {
                        $enum.HelpUri += '#server-archive-server'
                        add-parameter -name AccountAlias
                        add-parameter -name Name -mandatory
                    }
                    ChangePassword {
                        $enum.HelpUri += '#server-change-password'
                        add-parameter -name AccountAlias
                        add-parameter -name Name -mandatory
                        add-parameter -name CurrentPassword -mandatory
                        add-parameter -name NewPassword -mandatory
                    }
                    ConfigureServer {
                        $enum.HelpUri += '#server-configure-server'
                        add-parameter -name AccountAlias
                        add-parameter -name Name -mandatory
                        add-parameter -name HardwareGroupUUID -mandatory
                        add-parameter -name Cpu -mandatory -values 1,2,4
                        add-parameter -name MemoryGB -mandatory -values 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16
                        add-parameter -name AdditionalStorageGB
                        add-parameter -name CustomFields -type ([object])
                    }
                    ConvertServerToTemplate {
                        $enum.HelpUri += '#server-convert-server-to-template'
                        add-parameter -name AccountAlias
                        add-parameter -name Name -mandatory
                        add-parameter -name Password -mandatory
                        add-parameter -name TemplateAlias -mandatory
                    }
                    ConvertTemplateToServer {
                        $enum.HelpUri += '#server-converttemplatetoserver'
                        add-parameter -name AccountAlias
                        add-parameter -name Name -mandatory
                        add-parameter -name Password -mandatory
                        add-parameter -name HardwareGroupUUID -mandatory
                        add-parameter -name Network -mandatory
                    }
                    CreateServer {
                        $enum.HelpUri += '#server-create-server'
                        add-parameter -name AccountAlias
                        add-parameter -name LocationAlias -values $enum.DataCenters
                        add-parameter -name Template -mandatory
                        add-parameter -name Alias -mandatory
                        add-parameter -name Description
                        add-parameter -name HardwareGroupUUID -mandatory
                        add-parameter -name ServerType -mandatory -values 1,2
                        add-parameter -name ServiceLevel -mandatory -values 1,2
                        add-parameter -name Cpu -mandatory
                        add-parameter -name MemoryGB -mandatory
                        add-parameter -name ExtraDriveGB -mandatory
                        add-parameter -name PrimaryDns
                        add-parameter -name SecondaryDns
                        add-parameter -name Network
                        add-parameter -name Password
                        add-parameter -name CustomFields -type ([object])
                    }
                    DeleteDisk {
                        $enum.HelpUri += '#server-delete-disk'
                        add-parameter -name AccountAlias
                        add-parameter -name Name -mandatory
                        add-parameter -name ScsiBusID -mandatory
                        add-parameter -name ScsiDeviceID -mandatory
                        add-parameter -name OverrideFailsafes -type ([switch])
                    }
                    DeleteServer {
                        $enum.HelpUri += '#server-delete-server'
                        add-parameter -name AccountAlias
                        add-parameter -name Name -mandatory
                    }
                    DeleteSnapshot {
                        $enum.HelpUri += '#server-delete-snapshot'
                        add-parameter -name AccountAlias
                        add-parameter -name Name -mandatory
                        add-parameter -name SnapshotName -mandatory
                    }
                    DeleteTemplate {
                        $enum.HelpUri += '#server-deletetemplate'
                        add-parameter -name AccountAlias
                        add-parameter -name Name -mandatory
                    }
                    GetAllServersForAccountHierarchyByModifiedDates {
                        $enum.HelpUri += '#server-get-all-servers-for-account-hierarchy-by-modified-date'
                        add-parameter -name AccountAlias
                        add-parameter -name Location -values $enum.DataCenters
                        add-parameter -name BeginDate
                        add-parameter -name EndDate
                    }
                    GetAllServers {
                        $enum.HelpUri += '#server-getallservers'
                        add-parameter -name AccountAlias
                        add-parameter -name HardwareGroupUUID
                        add-parameter -name Location -values $enum.DataCenters
                    }
                    GetAllServersByModifiedDates {
                        $enum.HelpUri += '#server-getallserversbymodifieddates'
                        add-parameter -name AccountAlias
                        add-parameter -name HardwareGroupUUID
                        add-parameter -name Location -values $enum.DataCenters
                        add-parameter -name BeginDate
                        add-parameter -name EndDate
                    }
                    GetAllServersForAccountHierarchy {
                        $enum.HelpUri += '#server-getallserversforaccounthierarchy'
                        add-parameter -name AccountAlias
                        add-parameter -name Location -values $enum.DataCenters
                    }
                    GetArchiveServers {
                        $enum.HelpUri += '#server-getarchiveservers'
                    }
                    GetServer {
                        $enum.HelpUri += '#server-getserver'
                        add-parameter -name AccountAlias
                        add-parameter -name Name -mandatory
                    }
                    GetServerCredentials {
                        $enum.HelpUri += '#server-getservercredentials'
                        add-parameter -name AccountAlias
                        add-parameter -name Name -mandatory
                    }
                    GetServers {
                        $enum.HelpUri += '#server-getservers'
                        add-parameter -name AccountAlias
                        add-parameter -name HardwareGroupUUID -mandatory
                    }
                    GetServersByModifiedDates {
                        $enum.HelpUri += '#server-getserversbymodifieddates'
                        add-parameter -name AccountAlias
                        add-parameter -name HardwareGroupUUID -mandatory
                        add-parameter -name BeginDate
                        add-parameter -name EndDate
                    }
                    GetServerTemplates {
                        $enum.HelpUri += '#server-getservertemplates'
                        add-parameter -name Success -type ([switch])
                        add-parameter -name Message
                        add-parameter -name StatusCode
                        add-parameter -name Templates
                    }
                    GetSnapshots {
                        $enum.HelpUri += '#server-getsnapshots'
                        add-parameter -name AccountAlias
                        add-parameter -name Name -mandatory
                    }
                    ListArchivedServers {
                        $enum.HelpUri += '#server-listarchiveservers'
                        add-parameter -name AccountAlias
                        add-parameter -name Location -values $enum.DataCenters
                    }
                    ListAvailableServerTemplates {
                        $enum.HelpUri += '#server-listavailableservertemplates'
                        add-parameter -name AccountAlias
                        add-parameter -name Location -values $enum.DataCenters
                    }
                    ListDisks {
                        $enum.HelpUri += '#server-listdisks'
                        add-parameter -name AccountAlias
                        add-parameter -name Name -mandatory
                        add-parameter -name QueryGuestDiskNames
                    }
                    PauseServer {
                        $enum.HelpUri += '#server-pauseserver'
                        add-parameter -name AccountAlias
                        add-parameter -name Name -mandatory
                    }
                    PowerOffServer {
                        $enum.HelpUri += '#server-poweroffserver'
                        add-parameter -name AccountAlias
                        add-parameter -name Name -mandatory
                    }
                    PowerOnServer {
                        $enum.HelpUri += '#server-poweronserver'
                        add-parameter -name AccountAlias
                        add-parameter -name Name -mandatory
                    }
                    RebootServer {
                        $enum.HelpUri += '#server-rebootserver'
                        add-parameter -name AccountAlias
                        add-parameter -name Name -mandatory
                    }
                    ResetServer {
                        $enum.HelpUri += '#server-resetserver'
                        add-parameter -name AccountAlias
                        add-parameter -name Name -mandatory
                    }
                    ResizeDisk {
                        $enum.HelpUri += '#server-resizedisk'
                        add-parameter -name AccountAlias
                        add-parameter -name Name -mandatory
                        add-parameter -name ScsiBusID -mandatory
                        add-parameter -name ScsiDeviceID -mandatory
                        add-parameter -name ResizeGuestDisk -type ([switch])
                        add-parameter -name NewSizeGB -mandatory
                    }
                    RestoreServer {
                        $enum.HelpUri += '#server-restoreserver'
                        add-parameter -name AccountAlias
                        add-parameter -name Name -mandatory
                        add-parameter -name HardwareGroupUUID -mandatory
                    }
                    RevertToSnapshot {
                        $enum.HelpUri += '#server-reverttosnapshot'
                        add-parameter -name AccountAlias
                        add-parameter -name Name -mandatory
                        add-parameter -name SnapshotName -mandatory
                    }
                    ServerMaintenance {
                        $enum.HelpUri += '#server-servermaintenance'
                        add-parameter -name AccountAlias
                        add-parameter -name Name -mandatory
                        add-parameter -name Enable -mandatory -type ([bool])
                    }
                    ShutdownServer {
                        $enum.HelpUri += '#server-shutdownserver'
                        add-parameter -name AccountAlias
                        add-parameter -name Name -mandatory
                    }
                    SnapshotServer {
                        $enum.HelpUri += '#server-snapshotserver'
                        add-parameter -name AccountAlias
                        add-parameter -name Name -mandatory
                    }
                }
            }
            SMTPRelay {
                switch -Exact ($action) {
                    CreateAlias {
                        $enum.HelpUri += '#smtp-relay-createalias'
                    }
                    DisableAlias {
                        $enum.HelpUri += '#smtp-relay-disablealias'
                        add-parameter -name RelayAlias -mandatory
                    }
                    GetInvalidAddresses {
                        $enum.HelpUri += '#smtp-relay-get-invalid-addresses'
                        add-parameter -name DomainAlias -mandatory
                        add-parameter -name StartDate -mandatory
                        add-parameter -name EndDate -mandatory
                    }
                    ListAliases {
                        $enum.HelpUri += '#smtp-relay-listaliases'
                    }
                    RemoveAlias {
                        $enum.HelpUri += '#smtp-relay-removealias'
                        add-parameter -name RelayAlias -mandatory
                    }
                }
            }
            User {
                $enum.Roles = @{
                    2  = 'Server Administrator'
                    3  = 'Billing Manager'
                    8  = 'DNS Manager'
                    9  = 'Account Administrator'
                    10 = 'Account Viewer'
                    12 = 'Network Manager'
                    13 = 'Security Manager'
                    14 = 'Server Operator'
                    15 = 'Server Scheduler'
                }
                switch -Exact ($action) {
                    CreateUser {
                        $enum.HelpUri += '#users-createuser'
                        add-parameter -name UserName -mandatory
                        add-parameter -name AccountAlias -mandatory
                        add-parameter -name EmailAddress -mandatory
                        add-parameter -name FirstName -mandatory
                        add-parameter -name LastName -mandatory
                        add-parameter -name AlternateEmailAddress
                        add-parameter -name Title
                        add-parameter -name OfficeNumber
                        add-parameter -name MobileNumber
                        add-parameter -name AllowSMSAlerts
                        add-parameter -name FaxNumber
                        add-parameter -name SAMLUserName
                        add-parameter -name Roles -type ([int16[]])
                        add-parameter -name TimeZoneID
                    }
                    DeleteUser {
                        $enum.HelpUri += '#users-deleteuser'
                        add-parameter -name UserName -mandatory
                    }
                    GetUserDetails {
                        $enum.HelpUri += '#users-getuserdetails'
                        add-parameter -name AccountAlias -mandatory
                        add-parameter -name UserName -mandatory
                    }
                    GetUsers {
                        $enum.HelpUri += '#users-getusers'
                        add-parameter -name AccountAlias -mandatory
                    }
                    SuspendUser {
                        $enum.HelpUri += '#users-suspenduser'
                        add-parameter -name UserName -mandatory
                    }
                    UnsuspendUser {
                        $enum.HelpUri += '#users-unsuspenduser'
                        add-parameter -name UserName -mandatory
                    }
                    UpdateUser {
                        $enum.HelpUri += '#users-updateuser'
                        add-parameter -name UserName -mandatory
                        add-parameter -name EmailAddress -mandatory
                        add-parameter -name FirstName -mandatory
                        add-parameter -name LastName -mandatory
                        add-parameter -name AlternateEmailAddress
                        add-parameter -name Title
                        add-parameter -name OfficeNumber
                        add-parameter -name MobileNumber
                        add-parameter -name AllowSMSAlerts
                        add-parameter -name FaxNumber
                        add-parameter -name SAMLUserName
                        add-parameter -name Roles -type ([int16[]])
                        add-parameter -name TimeZoneID
                    }
                }
            }
        }

        # return dictionary
        $dictionary
    }

    process {
        # if help is called, open help uri and exit
        if ($Help) {
            Start-Process $enum.HelpUri
            break
        }
        # construct URI
        $object = $PSCmdlet.ParameterSetName
        $uri  = "https://api.ctl.io/REST/$object/$action/JSON"
        # convert dictionary to json and create body
        $body = @{}
        $dictionary.Keys | % {$body.$_ = $dictionary.$_.Value}
        $params = @{
            Uri         = $uri
            Method      = 'POST'
            Body        = $body
            ContentType = 'application/json'
            WebSession  = $WebSession
            ErrorAction = 'Stop'
        }
        # verify if we should invoke anything but Get or List
        $accountAlias = if ($body.ContainsKey('AccountAlias')) {
            $body.AccountAlias
        } else {
            '<unknown>'
        }
        if (($action -match "^Get.+|^List.+") -or $Force -or $PSCmdlet.ShouldProcess("Account $accountAlias","$object/$action")) {
            # invoke and return
            Write-Verbose "Invoke-RestMethod params:`n$(ConvertTo-Json $params)"
            $params.Body = ConvertTo-Json $params.Body -Compress
            $response = Invoke-RestMethod @params
            Write-Verbose "Invoke-RestMethod response:`n$(ConvertTo-Json $response)"
            if ($Json) {
                ConvertTo-Json $response -Depth 10
            } else {
                $response
            }
        }
    }

}



function Invoke-ControlApi2 {

<#
    .SYNOPSIS
        Interaction with api.clt.io via APIv2
    .DESCRIPTION
        Parameter Content type [object] accepts values in any of the following formats:
        [string] (json) i.e.:
            '{
              "userName":"root",
              "password":"P@ssw0rd1"
            }'
        [string], i.e.:
            'NAME1'
        [string[]], i.e.:
            'NAME1','NAME2'
        [hashtable], i.e.:
            @{
              userName = 'root'
              password = 'P@ssw0rd1'
            }
        [PSCustomObject], i.e.:
            [pscustomobject]@{
              userName = 'root'
              password = 'P@ssw0rd1'
            }
        All types will be converted to json format by function
        Use switch -Help for detailed description
    .PARAMETER content
        Use switch -Help for properties
    .EXAMPLE
        Invoke-ControlApi2 -Billing GetInvoiceDataForAnAccountAlias -accountAlias XXXX -year 2015 -month 9
    .EXAMPLE
        Invoke-ControlApi2 -PowerOperations PowerOnServer -accountAlias XXXX -content WA1XXXX201,WA1XXXX801
    .EXAMPLE
        Invoke-ControlApi2 -Servers GetServer -Help
    .NOTES
        Author    : Dmitry Gancho, dmitry.gancho@ctl.io
        Last edit : 11/14/2015
        Version   : 1.2
    .LINK
        https://www.ctl.io/api-docs/v2/
#>

    [CmdletBinding(
        SupportsShouldProcess,
        DefaultParameterSetName='__AllParameterSets',
        ConfirmImpact='High'
    )]

    param (
        [Parameter(Mandatory,ParameterSetName='AlertPolicies')]
        [ValidateSet(
            'CreateAlertPolicy',
            'DeleteAlertPolicy',
            'GetAlertPolicies',
            'GetAlertPolicy',
            'UpdateAlertPolicy'
        )]
        [string]$AlertPolicies,

        [Parameter(Mandatory,ParameterSetName='AntiAffinityPolicies')]
        [ValidateSet(
            'CreateAntiAffinityPolicy',
            'DeleteAntiAffinityPolicy',
            'GetAntiAffinityPolicies',
            'GetAntiAffinityPolicy',
            'UpdateAntyAffinityPolicy'
        )]
        [string]$AntiAffinityPolicies,

        [Parameter(Mandatory,ParameterSetName='AutoscalePolicies')]
        [ValidateSet(
            'GetVerticalAutoscalePolicies',
            'GetVerticalAutoscalePolicy',
            'RemoveVerticalAutoscalePolicyFromServer',
            'SetVerticalAutoscalePolicyOnServer',
            'ViewVerticalAutoscalePolicyOnServer'
        )]
        [string]$AutoscalePolicies,

        [Parameter(Mandatory,ParameterSetName='Billing')]
        [ValidateSet(
            'GetInvoiceDataForAnAccountAlias'
        )]
        [string]$Billing,

        [Parameter(Mandatory,ParameterSetName='CustomFields')]
        [ValidateSet(
            'GetCustomFields'
        )]
        [string]$CustomFields,

        [Parameter(Mandatory,ParameterSetName='DataCenters')]
        [ValidateSet(
            'GetDataCenter',
            'GetDataCenterBareMetalCapabilities',
            'GetDataCenterDeploymentCapabilities',
            'GetDataCenterList'
        )]
        [string]$DataCenters,

        [Parameter(Mandatory,ParameterSetName='FirewallPolicies')]
        [ValidateSet(
            'CreateanIntraDataCenterFirewallPolicy',
            'DeleteanIntraDataCenterFirewallPolicy',
            'GetIntraDataCenterFirewallPolicy',
            'GetIntraDataCenterFirewallPolicyList',
            'UpdateIntraDataCenterFirewallPolicy'
        )]
        [string]$FirewallPolicies,

        [Parameter(Mandatory,ParameterSetName='Groups')]
        [ValidateSet(
            'CreateGroup',
            'DeleteGroup',
            'GetGroup',
            'GetGroupBillingDetails',
            'GetGroupHorizontalAutoscalePolicy',
            'GetGroupMonitoringStatistics',
            'GetGroupScheduledActivities',
            'SetGroupCustomFields',
            'SetGroupDefaults',
            'SetGroupHorizontalAutoscalePolicy',
            'SetGroupName/Description',
            'SetGroupParent'
        )]
        [string]$Groups,

        [Parameter(Mandatory,ParameterSetName='GroupActions')]
        [ValidateSet(
            'ArchiveGroup',
            'RestoreGroup'
        )]
        [string]$GroupActions,

        [Parameter(Mandatory,ParameterSetName='Networks')]
        [ValidateSet(
            'ClaimNetwork',
            'GetIPAddressList',
            'GetNetwork',
            'GetNetworkList',
            'ReleaseNetwork',
            'UpdateNetwork'
        )]
        [string]$Networks,

        [Parameter(Mandatory,ParameterSetName='PowerOperations')]
        [ValidateSet(
            'PauseServer',
            'PowerOffServer',
            'PowerOnServer',
            'RebootServer',
            'ResetServer',
            'SetMaintenanceMode',
            'ShutDownServer',
            'StartMaintenanceMode',
            'StopMaintenanceMode'
        )]
        [string]$PowerOperations,

        [Parameter(Mandatory,ParameterSetName='PublicIP')]
        [ValidateSet(
            'AddPublicIPAddress',
            'GetPublicIPAddress',
            'RemovePublicIPAddress',
            'UpdatePublicIPAddress'
        )]
        [string]$PublicIP,

        [Parameter(Mandatory,ParameterSetName='Queue')]
        [ValidateSet(
            'GetStatus'
        )]
        [string]$Queue,

        [Parameter(Mandatory,ParameterSetName='Servers')]
        [ValidateSet(
            'GetServer',
            'AddSecondaryNetwork',
            'CloneServer',
            'CreateServer',
            'DeleteServer',
            'GetAvailableServerImports',
            'GetServerCredentials',
            'ImportServer',
            'RemoveSecondaryNetwork',
            'SetServerCPU/Memory',
            'SetServerCredentials',
            'SetServerCustomFields',
            'SetServerDescription/Group',
            'SetServerDisks'
        )]
        [string]$Servers,

        [Parameter(Mandatory,ParameterSetName='ServerActions')]
        [ValidateSet(
            'ArchiveServer',
            'CreateSnapshot',
            'DeleteSnapshot',
            'ExecutePackage',
            'RestoreServer',
            'ReverttoSnapshot'
        )]
        [string]$ServerActions,

        [Parameter(Mandatory,ParameterSetName='SharedLoadBalancers')]
        [ValidateSet(
            'CreateLoadBalancerPool',
            'CreateSharedLoadBalancer',
            'DeleteLoadBalancerPool',
            'DeleteSharedLoadBalancer',
            'GetLoadBalancerNodes',
            'GetLoadBalancerPool',
            'GetLoadBalancerPools',
            'GetSharedLoadBalancer',
            'GetSharedLoadBalancers',
            'UpdateLoadBalancerNodes',
            'UpdateLoadBalancerPool',
            'UpdateSharedLoadBalancer'
        )]
        [string]$SharedLoadBalancers,

        [Parameter()][Alias('ws')]
        [Microsoft.PowerShell.Commands.WebRequestSession]$WebSession = (New-ControlApi2Session),

        [Parameter()]
        [switch]$Force,

        [Parameter()]
        [switch]$Json,

        [Parameter()]
        [switch]$Help
    )

    DynamicParam {

        function add-parameter {
            param (
                [string]$name,
                [type]$type=[string],
                [string[]]$values,
                [switch]$mandatory
            )
            $attributes = New-Object -TypeName System.Management.Automation.ParameterAttribute
            $attributes.Mandatory = if ($Help) {$false} else {$mandatory}
            $attributes.ParameterSetName = $PSCmdlet.ParameterSetName
            $attributes.HelpMessage = if ($mandatory) {'mandatory'} else {'optional'}
            $collection = New-Object -TypeName System.Collections.ObjectModel.Collection[System.Attribute]
            $collection.Add($Attributes)
            if ($values) {$collection.Add((New-Object -TypeName System.Management.Automation.ValidateSetAttribute($values)))}
            $parameter = New-Object -TypeName System.Management.Automation.RuntimeDefinedParameter($name,$type,$collection)
            $dictionary.Add($name,$parameter)
        }

        # define dictionary
        $dictionary = New-Object -TypeName System.Management.Automation.RuntimeDefinedParameterDictionary
        # define enumerator
        $enum = @{
            DataCenters = 'CA1','CA2','CA3','DE1','GB1','GB3','IL1','NE1','NY1','SG1','UC1','UT1','VA1','WA1'
            HelpUri = 'https://www.ctl.io/api-docs/v2/'
        }
        # define value for switch $Help (used in add-parameter)
        if (-not (Test-Path Variable:Help)) {$Help = $false}
        # define action
        $action = Get-Variable -Name $PSCmdlet.ParameterSetName -ValueOnly -ErrorAction Ignore
        # define other parameters
        switch -Exact ($PSCmdlet.ParameterSetName) {
            AlertPolicies {
                switch -Exact ($action) {
                    CreateAlertPolicy {
                        $enum.HelpUri += '#alert-policies-create-alert-policy'
                        $enum.Structure = 'POST https://api.ctl.io/v2/alertPolicies/{accountAlias}'
                        add-parameter -name accountAlias -mandatory
                        add-parameter -name content -mandatory -type ([object])
                    }
                    DeleteAlertPolicy {
                        $enum.HelpUri += '#alert-policies-delete-alert-policy'
                        $enum.Structure = 'DELETE https://api.ctl.io/v2/alertPolicies/{accountAlias}/{policyId}'
                        add-parameter -name accountAlias -mandatory
                        add-parameter -name policyId -mandatory
                    }
                    GetAlertPolicies {
                        $enum.HelpUri += '#alert-policies-get-alert-policies'
                        $enum.Structure = 'GET https://api.ctl.io/v2/alertPolicies/{accountAlias}'
                        add-parameter -name accountAlias -mandatory
                    }
                    GetAlertPolicy {
                        $enum.HelpUri += '#alert-policies-get-alert-policy'
                        $enum.Structure = 'GET https://api.ctl.io/v2/alertPolicies/{accountAlias}/{policyId}'
                        add-parameter -name accountAlias -mandatory
                        add-parameter -name policyId -mandatory
                    }
                    UpdateAlertPolicy {
                        $enum.HelpUri += '#alert-policies-update-alert-policy'
                        $enum.Structure = 'PUT https://api.ctl.io/v2/alertPolicies/{accountAlias}/{policyId}'
                        add-parameter -name accountAlias -mandatory
                        add-parameter -name policyId -mandatory
                        add-parameter -name content -mandatory -type ([object])
                    }
                }
            }
            AntiAffinityPolicies {
                switch -Exact ($action) {
                    CreateAntiAffinityPolicy {
                        $enum.HelpUri += '#anti-affinity-policies-create-anti-affinity-policy'
                        $enum.Structure = 'POST https://api.ctl.io/v2/antiAffinityPolicies/{accountAlias}'
                        add-parameter -name accountAlias -mandatory
                        add-parameter -name content -mandatory -type ([object])
                    }
                    DeleteAntiAffinityPolicy {
                        $enum.HelpUri += '#anti-affinity-policies-delete-anti-affinity-policy'
                        $enum.Structure = 'DELETE https://api.ctl.io/v2/antiAffinityPolicies/{accountAlias}/{policyId}'
                        add-parameter -name accountAlias -mandatory
                        add-parameter -name policyId -mandatory
                    }
                    GetAntiAffinityPolicies {
                        $enum.HelpUri += '#anti-affinity-policies-get-anti-affinity-policies'
                        $enum.Structure = 'GET https://api.ctl.io/v2/antiAffinityPolicies/{accountAlias}'
                        add-parameter -name accountAlias -mandatory
                    }
                    GetAntiAffinityPolicy {
                        $enum.HelpUri += '#anti-affinity-policies-get-anti-affinity-policy'
                        $enum.Structure = 'GET https://api.ctl.io/v2/antiAffinityPolicies/{accountAlias}/{policyId}'
                        add-parameter -name accountAlias -mandatory
                        add-parameter -name policyId -mandatory
                    }
                    UpdateAntyAffinityPolicy {
                        $enum.HelpUri += '#anti-affinity-policies-update-anti-affinity-policy'
                        $enum.Structure = 'PUT https://api.ctl.io/v2/antiAffinityPolicies/{accountAlias}/{policyId}'
                        add-parameter -name accountAlias -mandatory
                        add-parameter -name policyId -mandatory
                        add-parameter -name content -mandatory -type ([object])
                    }
                }
            }
            AutoscalePolicies {
                switch -Exact ($action) {
                    GetVerticalAutoscalePolicies {
                        $enum.HelpUri += '#autoscale-policies'
                        $enum.Structure = 'GET https://api.ctl.io/v2/autoscalePolicies/{accountAlias}'
                        add-parameter -name accountAlias -mandatory
                    }
                    GetVerticalAutoscalePolicy {
                        $enum.HelpUri += '#autoscale-policies-get-vertical-autoscale-policy'
                        $enum.Structure = 'GET https://api.ctl.io/v2/autoscalePolicies/{accountAlias}/{policyId}'
                        add-parameter -name accountAlias -mandatory
                        add-parameter -name policyId -mandatory
                    }
                    RemoveVerticalAutoscalePolicyFromServer {
                        $enum.HelpUri += '#autoscale-policies-remove-vertical-autoscale-policy-from-server'
                        $enum.Structure = 'DELETE https://api.ctl.io/v2/servers/{accountAlias}/{serverId}/cpuAutoscalePolicy'
                        add-parameter -name accountAlias -mandatory
                        add-parameter -name serverId -mandatory
                    }
                    SetVerticalAutoscalePolicyOnServer {
                        $enum.HelpUri += '#autoscale-policies-set-vertical-autoscale-policy-on-server'
                        $enum.Structure = 'PUT https://api.ctl.io/v2/servers/{accountAlias}/{serverId}/cpuAutoscalePolicy'
                        add-parameter -name accountAlias -mandatory
                        add-parameter -name serverId -mandatory
                        add-parameter -name content -mandatory -type ([object])
                    }
                    ViewVerticalAutoscalePolicyOnServer {
                        $enum.HelpUri += '#autoscale-policies-view-vertical-autoscale-policy-on-server'
                        $enum.Structure = 'GET https://api.ctl.io/v2/servers/{accountAlias}/{serverId}/cpuAutoscalePolicy'
                        add-parameter -name accountAlias -mandatory
                        add-parameter -name serverId -mandatory
                    }
                }
            }
            Billing {
                switch -Exact ($action) {
                    GetInvoiceDataForAnAccountAlias {
                        $enum.HelpUri += '#billing-get-invoice-data-for-an-account-alias'
                        $enum.Structure = 'GET https://api.ctl.io/v2/invoice/{accountAlias}/{year}/{month}?{pricingAccountAlias}'
                        add-parameter -name accountAlias -mandatory
                        add-parameter -name year -mandatory
                        add-parameter -name month -mandatory
                        add-parameter -name pricingAccountAlias
                    }
                }
            }
            CustomFields {
                switch -Exact ($action) {
                    GetCustomFields {
                        $enum.HelpUri += '#custom-fields-get-custom-fields'
                        $enum.Structure = 'GET https://api.ctl.io/v2/accounts/{accountAlias}/customFields'
                        add-parameter -name accountAlias -mandatory
                    }
                }
            }
            DataCenters {
                switch -Exact ($action) {
                    GetDataCenter {
                        $enum.HelpUri += '#data-centers-get-data-center'
                        $enum.Structure = 'GET https://api.ctl.io/v2/datacenters/{accountAlias}/{dataCenter}?groupLinks={groupLinks}'
                        add-parameter -name accountAlias -mandatory
                        add-parameter -name dataCenter -mandatory -values $enum.DataCenters
                        add-parameter -name groupLinks -values 'true','false'
                    }
                    GetDataCenterBareMetalCapabilities {
                        $enum.HelpUri += '#data-centers-get-data-center-bare-metal-capabilities'
                        $enum.Structure = 'GET https://api.ctl.io/v2/datacenters/{accountAlias}/{dataCenter}/bareMetalCapabilities'
                        add-parameter -name accountAlias -mandatory
                        add-parameter -name dataCenter -mandatory -values $enum.DataCenters
                    }
                    GetDataCenterDeploymentCapabilities {
                        $enum.HelpUri += '#data-centers-get-data-center-deployment-capabilities'
                        $enum.Structure = 'GET https://api.ctl.io/v2/datacenters/{accountAlias}/{dataCenter}/deploymentCapabilities'
                        add-parameter -name accountAlias -mandatory
                        add-parameter -name dataCenter -mandatory -values $enum.DataCenters
                    }
                    GetDataCenterList {
                        $enum.HelpUri += '#data-centers-get-data-center-list'
                        $enum.Structure = 'GET https://api.ctl.io/v2/datacenters/{accountAlias}'
                        add-parameter -name accountAlias -mandatory
                    }
                }
            }
            FirewallPolicies {
                switch -Exact ($action) {
                    CreateanIntraDataCenterFirewallPolicy {
                        $enum.HelpUri += '#firewall-policies-create-an-intra-data-center-firewall-policy'
                        $enum.Structure = 'POST https://api.ctl.io/v2-experimental/firewallPolicies/{sourceAccountAlias}/{dataCenter}'
                        add-parameter -name sourceAccountAlias -mandatory
                        add-parameter -name dataCenter -mandatory -values $enum.DataCenters
                        add-parameter -name content -mandatory -type ([object])
                    }
                    DeleteanIntraDataCenterFirewallPolicy {
                        $enum.HelpUri += '#firewall-policies-delete-an-intra-data-center-firewall-policy'
                        $enum.Structure = 'DELETE https://api.ctl.io/v2-experimental/firewallPolicies/{sourceAccountAlias}/{dataCenter}/{firewallPolicy}'
                        add-parameter -name sourceAccountAlias -mandatory
                        add-parameter -name dataCenter -mandatory -values $enum.DataCenters
                        add-parameter -name firewallPolicy -mandatory
                    }
                    GetIntraDataCenterFirewallPolicy {
                        $enum.HelpUri += '#firewall-policies-get-intra-data-center-firewall-policy'
                        $enum.Structure = 'GET https://api.ctl.io/v2-experimental/firewallPolicies/{sourceAccountAlias}/{dataCenter}/{firewallPolicy}'
                        add-parameter -name sourceAccountAlias -mandatory
                        add-parameter -name dataCenter -mandatory -values $enum.DataCenters
                        add-parameter -name firewallPolicy -mandatory
                    }
                    GetIntraDataCenterFirewallPolicyList {
                        $enum.HelpUri += '#firewall-policies-get-intra-data-center-firewall-policy-list'
                        $enum.Structure = 'GET https://api.ctl.io/v2-experimental/firewallPolicies/{sourceAccountAlias}/{dataCenter}?destinationAccount={destinationAccountAlias}'
                        add-parameter -name sourceAccountAlias -mandatory
                        add-parameter -name dataCenter -mandatory -values $enum.DataCenters
                        add-parameter -name destinationAccountAlias -mandatory
                    }
                    UpdateIntraDataCenterFirewallPolicy {
                        $enum.HelpUri += '#firewall-policies-update-intra-data-center-firewall-policy'
                        $enum.Structure = 'PUT https://api.ctl.io/v2-experimental/firewallPolicies/{sourceAccountAlias}/{dataCenter}/{firewallPolicy}'
                        add-parameter -name sourceAccountAlias -mandatory
                        add-parameter -name dataCenter -mandatory -values $enum.DataCenters
                        add-parameter -name destinationAccountAlias -mandatory
                        add-parameter -name content -mandatory -type ([object])
                    }
                }
            }
            Groups {
                switch -Exact ($action) {
                    CreateGroup {
                        $enum.HelpUri += '#groups-create-group'
                        $enum.Structure = 'POST https://api.ctl.io/v2/groups/{accountAlias}'
                        add-parameter -name accountAlias -mandatory
                        add-parameter -name content -mandatory -type ([object])
                    }
                    DeleteGroup {
                        $enum.HelpUri += '#groups-delete-group'
                        $enum.Structure = 'DELETE https://api.ctl.io/v2/groups/{accountAlias}/{groupId}'
                        add-parameter -name accountAlias -mandatory
                        add-parameter -name groupId -mandatory
                    }
                    GetGroup {
                        $enum.HelpUri += '#groups-get-group'
                        $enum.Structure = 'GET https://api.ctl.io/v2/groups/{accountAlias}/{groupId}'
                        add-parameter -name accountAlias -mandatory
                        add-parameter -name groupId -mandatory
                    }
                    GetGroupBillingDetails {
                        $enum.HelpUri += '#groups-get-group-billing-details'
                        $enum.Structure = 'GET https://api.ctl.io/v2/groups/{accountAlias}/{groupId}/billing'
                        add-parameter -name accountAlias -mandatory
                        add-parameter -name groupId -mandatory
                    }
                    GetGroupHorizontalAutoscalePolicy {
                        $enum.HelpUri += '#groups-get-group-horizontal-autoscale-policy'
                        $enum.Structure = 'GET https://api.ctl.io/v2/groups/{accountAlias}/{groupId}/horizontalAutoscalePolicy/'
                        add-parameter -name accountAlias -mandatory
                        add-parameter -name groupId -mandatory
                    }
                    GetGroupMonitoringStatistics {
                        $enum.HelpUri += '#groups-get-group-monitoring-statistics'
                        $enum.Structure = 'GET https://api.ctl.io/v2/groups/{accountAlias}/{groupId}/statistics?type=hourly&start={datetime}&end={datetime}&sampleInterval={sampleInterval}'
                        add-parameter -name accountAlias -mandatory
                        add-parameter -name groupId -mandatory
                        add-parameter -name type -mandatory -values 'latest','hourly','realtime'
                        add-parameter -name start -mandatory
                        add-parameter -name end
                        add-parameter -name sampleInterval -mandatory
                    }
                    GetGroupScheduledActivities {
                        $enum.HelpUri += '#groups-get-group-scheduled-activities'
                        $enum.Structure = 'GET https://api.ctl.io/v2/groups/{accountAlias}/{groupId}/ScheduledActivities/'
                        add-parameter -name accountAlias -mandatory
                        add-parameter -name groupId -mandatory
                    }
                    SetGroupCustomFields {
                        $enum.HelpUri += '#groups-set-group-custom-fields'
                        $enum.Structure = 'PATCH https://api.ctl.io/v2/groups/{accountAlias}/{groupId}'
                        add-parameter -name accountAlias -mandatory
                        add-parameter -name groupId -mandatory
                        add-parameter -name content -mandatory -type ([object])
                    }
                    SetGroupDefaults {
                        $enum.HelpUri += '#groups-set-group-defaults'
                        $enum.Structure = 'POST https://api.ctl.io/v2/groups/{accountAlias}/{groupId}/defaults'
                        add-parameter -name accountAlias -mandatory
                        add-parameter -name groupId -mandatory
                        add-parameter -name content -mandatory -type ([object])
                    }
                    SetGroupHorizontalAutoscalePolicy {
                        $enum.HelpUri += '#groups-set-group-horizontal-autoscale-policy'
                        $enum.Structure = 'PUT https://api.ctl.io/v2/groups/{accountAlias}/{groupId}/horizontalAutoscalePolicy/'
                        add-parameter -name accountAlias -mandatory
                        add-parameter -name groupId -mandatory
                        add-parameter -name content -mandatory -type ([object])
                    }
                    SetGroupName/Description {
                        $enum.HelpUri += '#groups-set-group-namedescription'
                        $enum.Structure = 'PATCH https://api.ctl.io/v2/groups/{accountAlias}/{groupId}'
                        add-parameter -name accountAlias -mandatory
                        add-parameter -name groupId -mandatory
                        add-parameter -name content -mandatory -type ([object])
                    }
                    SetGroupParent {
                        $enum.HelpUri += '#groups-set-group-parent'
                        $enum.Structure = 'PATCH https://api.ctl.io/v2/groups/{accountAlias}/{groupId}'
                        add-parameter -name accountAlias -mandatory
                        add-parameter -name groupId -mandatory
                        add-parameter -name content -mandatory -type ([object])
                    }
                }
            }
            GroupActions {
                switch -Exact ($action) {
                    ArchiveGroup {
                        $enum.HelpUri += '#group-actions-archive-group'
                        $enum.Structure = 'POST https://api.ctl.io/v2/groups/{accountAlias}/{groupId}/archive'
                        add-parameter -name accountAlias -mandatory
                        add-parameter -name groupId -mandatory
                    }
                    RestoreGroup {
                        $enum.HelpUri += '#group-actions-restore-group'
                        $enum.Structure = 'POST https://api.ctl.io/v2/groups/{accountAlias}/{groupId}/restore'
                        add-parameter -name accountAlias -mandatory
                        add-parameter -name groupId -mandatory
                        add-parameter -name content -mandatory -type ([object])
                    }
                }
            }
            Networks {
                switch -Exact ($action) {
                    ClaimNetwork {
                        $enum.HelpUri += '#networks-claim-network'
                        $enum.Structure = 'POST https://api.ctl.io/v2-experimental/networks/{accountAlias}/{dataCenter}/claim'
                        add-parameter -name accountAlias -mandatory
                        add-parameter -name dataCenter -mandatory -values $enum.DataCenters
                    }
                    GetIPAddressList {
                        $enum.HelpUri += '#networks-get-ip-address-list'
                        $enum.Structure = 'GET https://api.ctl.io/v2-experimental/networks/{accountAlias}/{dataCenter}/{Network}/ipAddresses?type={type}'
                        add-parameter -name accountAlias -mandatory
                        add-parameter -name dataCenter -mandatory -values $enum.DataCenters
                        add-parameter -name network -mandatory
                        add-parameter -name type -values 'claimed','free','all'
                    }
                    GetNetwork {
                        $enum.HelpUri += '#networks-get-network'
                        $enum.Structure = 'GET https://api.ctl.io/v2-experimental/networks/{accountAlias}/{dataCenter}/{Network}?ipAddresses={ipAddresses}'
                        add-parameter -name accountAlias -mandatory
                        add-parameter -name dataCenter -mandatory -values $enum.DataCenters
                        add-parameter -name network -mandatory
                        add-parameter -name ipAddresses -values 'none','claimed','free','all'
                    }
                    GetNetworkList {
                        $enum.HelpUri += '#networks-get-network-list'
                        $enum.Structure = 'GET https://api.ctl.io/v2-experimental/networks/{accountAlias}/{dataCenter}'
                        add-parameter -name accountAlias -mandatory
                        add-parameter -name dataCenter -mandatory -values $enum.DataCenters
                    }
                    ReleaseNetwork {
                        $enum.HelpUri += '#networks-release-network'
                        $enum.Structure = 'POST https://api.ctl.io/v2-experimental/networks/{accountAlias}/{dataCenter}/{Network}/release'
                        add-parameter -name accountAlias -mandatory
                        add-parameter -name dataCenter -mandatory -values $enum.DataCenters
                        add-parameter -name network -mandatory
                    }
                    UpdateNetwork {
                        $enum.HelpUri += '#networks-update-network'
                        $enum.Structure = 'PUT https://api.ctl.io/v2-experimental/networks/{accountAlias}/{dataCenter}/{Network}'
                        add-parameter -name accountAlias -mandatory
                        add-parameter -name dataCenter -mandatory -values $enum.DataCenters
                        add-parameter -name network -mandatory
                        add-parameter -name content -mandatory -type ([object])
                    }
                }
            }
            PowerOperations {
                switch -Exact ($action) {
                    PauseServer {
                        $enum.HelpUri += '#power-operations-pause-server'
                        $enum.Structure = 'POST https://api.ctl.io/v2/operations/{accountAlias}/servers/pause'
                        add-parameter -name accountAlias -mandatory
                        add-parameter -name content -mandatory -type ([object])
                    }
                    PowerOffServer {
                        $enum.HelpUri += '#power-operations-power-off-server'
                        $enum.Structure = 'POST https://api.ctl.io/v2/operations/{accountAlias}/servers/powerOff'
                        add-parameter -name accountAlias -mandatory
                        add-parameter -name content -mandatory -type ([object])
                    }
                    PowerOnServer {
                        $enum.HelpUri += '#power-operations-power-on-server'
                        $enum.Structure = 'POST https://api.ctl.io/v2/operations/{accountAlias}/servers/powerOn'
                        add-parameter -name accountAlias -mandatory
                        add-parameter -name content -mandatory -type ([object])
                    }
                    RebootServer {
                        $enum.HelpUri += '#power-operations-reboot-server'
                        $enum.Structure = 'POST https://api.ctl.io/v2/operations/{accountAlias}/servers/reboot'
                        add-parameter -name accountAlias -mandatory
                        add-parameter -name content -mandatory -type ([object])
                    }
                    ResetServer {
                        $enum.HelpUri += '#power-operations-reset-server'
                        $enum.Structure = 'POST https://api.ctl.io/v2/operations/{accountAlias}/servers/reset'
                        add-parameter -name accountAlias -mandatory
                        add-parameter -name content -mandatory -type ([object])
                    }
                    SetMaintenanceMode {
                        $enum.HelpUri += '#power-operations-set-maintenance-mode'
                        $enum.Structure = 'POST https://api.ctl.io/v2/operations/{accountAlias}/servers/setMaintenance'
                        add-parameter -name accountAlias -mandatory
                        add-parameter -name content -mandatory -type ([object])
                    }
                    ShutDownServer {
                        $enum.HelpUri += '#power-operations-shut-down-serve'
                        $enum.Structure = 'POST https://api.ctl.io/v2/operations/{accountAlias}/servers/shutDown'
                        add-parameter -name accountAlias -mandatory
                        add-parameter -name content -mandatory -type ([object])
                    }
                    StartMaintenanceMode {
                        $enum.HelpUri += '#power-operations-start-maintenance-mode'
                        $enum.Structure = 'POST https://api.ctl.io/v2/operations/{accountAlias}/servers/startMaintenance'
                        add-parameter -name accountAlias -mandatory
                        add-parameter -name content -mandatory -type ([object])
                    }
                    StopMaintenanceMode {
                        $enum.HelpUri += '#power-operations-stop-maintenance-mode'
                        $enum.Structure = 'POST https://api.ctl.io/v2/operations/{accountAlias}/servers/stopMaintenance'
                        add-parameter -name accountAlias -mandatory
                        add-parameter -name content -mandatory -type ([object])
                    }
                }
            }
            PublicIP {
                switch -Exact ($action) {
                    AddPublicIPAddress {
                        $enum.HelpUri += '#public-ip-add-public-ip-address'
                        $enum.Structure = 'POST https://api.ctl.io/v2/servers/{accountAlias}/{serverId}/publicIPAddresses'
                        add-parameter -name accountAlias -mandatory
                        add-parameter -name serverId -mandatory
                        add-parameter -name content -mandatory -type ([object])
                    }
                    GetPublicIPAddress {
                        $enum.HelpUri += '#public-ip-get-public-ip-address'
                        $enum.Structure = 'GET https://api.ctl.io/v2/servers/{accountAlias}/{serverId}/publicIPAddresses/{publicIP}'
                        add-parameter -name accountAlias -mandatory
                        add-parameter -name serverId -mandatory
                        add-parameter -name publicIP -mandatory
                    }
                    RemovePublicIPAddress {
                        $enum.HelpUri += '#public-ip-remove-public-ip-address'
                        $enum.Structure = 'DELETE https://api.ctl.io/v2/servers/{accountAlias}/{serverId}/publicIPAddresses/{publicIP}'
                        add-parameter -name accountAlias -mandatory
                        add-parameter -name serverId -mandatory
                        add-parameter -name publicIP -mandatory
                    }
                    UpdatePublicIPAddress {
                        $enum.HelpUri += '#public-ip-update-public-ip-address'
                        $enum.Structure = 'PUT https://api.ctl.io/v2/servers/{accountAlias}/{serverId}/publicIPAddresses/{publicIP}'
                        add-parameter -name accountAlias -mandatory
                        add-parameter -name serverId -mandatory
                        add-parameter -name publicIP -mandatory
                        add-parameter -name content -mandatory -type ([object])
                    }
                }
            }
            Queue {
                switch -Exact ($action) {
                    GetStatus {
                        $enum.HelpUri += '#queue-get-status'
                        $enum.Structure = 'GET https://api.ctl.io/v2/operations/{accountAlias}/status/{statusId}'
                        add-parameter -name accountAlias -mandatory
                        add-parameter -name statusID -mandatory
                    }
                }
            }
            Servers {
                switch -Exact ($action) {
                    GetServer {
                        $enum.HelpUri += '#servers-get-server'
                        $enum.Structure = 'GET https://api.ctl.io/v2/servers/{accountAlias}/{serverId}'
                        add-parameter -name accountAlias -mandatory
                        add-parameter -name serverId -mandatory
                    }
                    AddSecondaryNetwork {
                        $enum.HelpUri += '#servers-add-secondary-network'
                        $enum.Structure = 'POST https://api.ctl.io/v2/servers/{accountAlias}/{serverId}/networks'
                        add-parameter -name accountAlias -mandatory
                        add-parameter -name serverId -mandatory
                        add-parameter -name content -mandatory -type ([object])
                    }
                    CloneServer {
                        $enum.HelpUri += '#servers-clone-server'
                        $enum.Structure = 'POST https://api.ctl.io/v2/servers/{accountAlias}'
                        add-parameter -name accountAlias -mandatory
                        add-parameter -name content -mandatory -type ([object])
                    }
                    CreateServer {
                        $enum.HelpUri += '#servers-create-server'
                        $enum.Structure = 'POST https://api.ctl.io/v2/servers/{accountAlias}'
                        add-parameter -name accountAlias -mandatory
                        add-parameter -name content -mandatory -type ([object])
                    }
                    DeleteServer {
                        $enum.HelpUri += '#servers-delete-server'
                        $enum.Structure = 'DELETE https://api.ctl.io/v2/servers/{accountAlias}/{serverId}'
                        add-parameter -name accountAlias -mandatory
                        add-parameter -name serverId -mandatory
                    }
                    GetAvailableServerImports {
                        $enum.HelpUri += '#servers-get-available-server-imports'
                        $enum.Structure = 'GET https://api.ctl.io/v2/vmImport/{accountAlias}/{locationId}/available'
                        add-parameter -name accountAlias -mandatory
                        add-parameter -name locationId -mandatory -values $enum.DataCenters
                    }
                    GetServerCredentials {
                        $enum.HelpUri += '#servers-get-server-credentials'
                        $enum.Structure = 'GET https://api.ctl.io/v2/servers/{accountAlias}/{serverId}/credentials'
                        add-parameter -name accountAlias -mandatory
                        add-parameter -name serverId -mandatory
                    }
                    ImportServer {
                        $enum.HelpUri += '#servers-import-server'
                        $enum.Structure = 'POST https://api.ctl.io/v2/vmImport/{accountAlias}'
                        add-parameter -name accountAlias -mandatory
                        add-parameter -name content -mandatory -type ([object])
                    }
                    RemoveSecondaryNetwork {
                        $enum.HelpUri += '#servers-remove-secondary-network'
                        $enum.Structure = 'DELETE https://api.ctl.io/v2/servers/{accountAlias}/{serverId}/networks/{networkId}'
                        add-parameter -name accountAlias -mandatory
                        add-parameter -name serverId -mandatory
                        add-parameter -name networkId -mandatory
                    }
                    SetServerCPU/Memory {
                        $enum.HelpUri += '#servers-set-server-cpumemory'
                        $enum.Structure = 'PATCH https://api.ctl.io/v2/servers/{accountAlias}/{serverId}'
                        add-parameter -name accountAlias -mandatory
                        add-parameter -name serverId -mandatory
                        add-parameter -name content -mandatory -type ([object])
                    }
                    SetServerCredentials {
                        $enum.HelpUri += '#servers-set-server-credentials'
                        $enum.Structure = 'PATCH https://api.ctl.io/v2/servers/{accountAlias}/{serverId}'
                        add-parameter -name accountAlias -mandatory
                        add-parameter -name serverId -mandatory
                        add-parameter -name content -mandatory -type ([object])
                    }
                    SetServerCustomFields {
                        $enum.HelpUri += '#servers-set-server-custom-fields'
                        $enum.Structure = 'PATCH https://api.ctl.io/v2/servers/{accountAlias}/{serverId}'
                        add-parameter -name accountAlias -mandatory
                        add-parameter -name serverId -mandatory
                        add-parameter -name content -mandatory -type ([object])
                    }
                    SetServerDescription/Group {
                        $enum.HelpUri += '#servers-set-server-descriptiongroup'
                        $enum.Structure = 'PATCH https://api.ctl.io/v2/servers/{accountAlias}/{serverId}'
                        add-parameter -name accountAlias -mandatory
                        add-parameter -name serverId -mandatory
                        add-parameter -name content -mandatory -type ([object])
                    }
                    SetServerDisks {
                        $enum.HelpUri += '#servers-set-server-disks'
                        $enum.Structure = 'PATCH https://api.ctl.io/v2/servers/{accountAlias}/{serverId}'
                        add-parameter -name accountAlias -mandatory
                        add-parameter -name serverId -mandatory
                        add-parameter -name content -mandatory -type ([object])
                    }
                }
            }
            ServerActions {
                switch -Exact ($action) {
                    ArchiveServer {
                        $enum.HelpUri += '#server-actions-archive-server'
                        $enum.Structure = 'POST https://api.ctl.io/v2/operations/{accountAlias}/servers/archive'
                        add-parameter -name accountAlias -mandatory
                        add-parameter -name content -mandatory -type ([object])
                    }
                    CreateSnapshot {
                        $enum.HelpUri += '#server-actions-create-snapshot'
                        $enum.Structure = 'POST https://api.ctl.io/v2/operations/{accountAlias}/servers/createSnapshot'
                        add-parameter -name accountAlias -mandatory
                        add-parameter -name content -mandatory -type ([object])
                    }
                    DeleteSnapshot {
                        $enum.HelpUri += '#server-actions-delete-snapshot'
                        $enum.Structure = 'DELETE https://api.ctl.io/v2/servers/{accountAlias}/{serverId}/snapshots/{snapshotId}'
                        add-parameter -name accountAlias -mandatory
                        add-parameter -name serverId -mandatory
                        add-parameter -name snapshotId -mandatory
                    }
                    ExecutePackage {
                        $enum.HelpUri += '#server-actions-execute-package'
                        $enum.Structure = 'POST https://api.ctl.io/v2/operations/{accountAlias}/servers/executePackage'
                        add-parameter -name accountAlias -mandatory
                        add-parameter -name content -mandatory -type ([object])
                    }
                    RestoreServer {
                        $enum.HelpUri += '#server-actions-restore-server'
                        $enum.Structure = 'POST https://api.ctl.io/v2/servers/{accountAlias}/{serverId}/restore'
                        add-parameter -name accountAlias -mandatory
                        add-parameter -name serverId -mandatory
                        add-parameter -name content -mandatory -type ([object])
                    }
                    ReverttoSnapshot {
                        $enum.HelpUri += '#server-actions-revert-to-snapshot'
                        $enum.Structure = 'POST https://api.ctl.io/v2/servers/{accountAlias}/{serverId}/snapshots/{snapshotId}/restore'
                        add-parameter -name accountAlias -mandatory
                        add-parameter -name serverId -mandatory
                        add-parameter -name snapshotId -mandatory
                    }
                }
            }
            SharedLoadBalancers {
                switch -Exact ($action) {
                    CreateLoadBalancerPool {
                        $enum.HelpUri += '#shared-load-balancers-create-load-balancer-pool'
                        $enum.Structure = 'POST https://api.ctl.io/v2/sharedLoadBalancers/{accountAlias}/{dataCenter}/{loadBalancerId}/pools'
                        add-parameter -name accountAlias -mandatory
                        add-parameter -name dataCenter -mandatory -values $enum.DataCenters
                        add-parameter -name loadBalancerId -mandatory
                        add-parameter -name content -mandatory -type ([object])
                    }
                    CreateSharedLoadBalancer {
                        $enum.HelpUri += '#shared-load-balancers-create-shared-load-balancer'
                        $enum.Structure = 'POST https://api.ctl.io/v2/sharedLoadBalancers/{accountAlias}/{dataCenter}'
                        add-parameter -name accountAlias -mandatory
                        add-parameter -name dataCenter -mandatory -values $enum.DataCenters
                        add-parameter -name content -mandatory -type ([object])
                    }
                    DeleteLoadBalancerPool {
                        $enum.HelpUri += '#shared-load-balancers-delete-load-balancer-pool'
                        $enum.Structure = 'DELETE https://api.ctl.io/v2/sharedLoadBalancers/{accountAlias}/{dataCenter}/{loadBalancerId}/pools/{poolId}'
                        add-parameter -name accountAlias -mandatory
                        add-parameter -name dataCenter -mandatory -values $enum.DataCenters
                        add-parameter -name loadBalancerId -mandatory
                        add-parameter -name poolId -mandatory
                    }
                    DeleteSharedLoadBalancer {
                        $enum.HelpUri += '#shared-load-balancers-delete-shared-load-balancer'
                        $enum.Structure = 'DELETE https://api.ctl.io/v2/sharedLoadBalancers/{accountAlias}/{dataCenter}/{loadBalancerId}'
                        add-parameter -name accountAlias -mandatory
                        add-parameter -name dataCenter -mandatory -values $enum.DataCenters
                        add-parameter -name loadBalancerId -mandatory
                    }
                    GetLoadBalancerNodes {
                        $enum.HelpUri += '#shared-load-balancers-get-load-balancer-nodes'
                        $enum.Structure = 'https://api.ctl.io/v2/sharedLoadBalancers/{accountAlias}/{dataCenter}/{loadBalancerId}/pools/{poolId}/nodes'
                        add-parameter -name accountAlias -mandatory
                        add-parameter -name dataCenter -mandatory -values $enum.DataCenters
                        add-parameter -name loadBalancerId -mandatory
                        add-parameter -name poolId -mandatory
                    }
                    GetLoadBalancerPool {
                        $enum.HelpUri += '#shared-load-balancers-get-load-balancer-pool'
                        $enum.Structure = 'GET https://api.ctl.io/v2/sharedLoadBalancers/{accountAlias}/{dataCenter}/{loadBalancerId}/pools/{poolId}'
                        add-parameter -name accountAlias -mandatory
                        add-parameter -name dataCenter -mandatory -values $enum.DataCenters
                        add-parameter -name loadBalancerId -mandatory
                        add-parameter -name poolId -mandatory
                    }
                    GetLoadBalancerPools {
                        $enum.HelpUri += '#shared-load-balancers-get-load-balancer-pools'
                        $enum.Structure = 'GET https://api.ctl.io/v2/sharedLoadBalancers/{accountAlias}/{dataCenter}/{loadBalancerId}/pools'
                        add-parameter -name accountAlias -mandatory
                        add-parameter -name dataCenter -mandatory -values $enum.DataCenters
                        add-parameter -name loadBalancerId -mandatory
                    }
                    GetSharedLoadBalancer {
                        $enum.HelpUri += '#shared-load-balancers-get-shared-load-balancer'
                        $enum.Structure = 'GET https://api.ctl.io/v2/sharedLoadBalancers/{accountAlias}/{dataCenter}/{loadBalancerId}'
                        add-parameter -name accountAlias -mandatory
                        add-parameter -name dataCenter -mandatory -values $enum.DataCenters
                        add-parameter -name loadBalancerId -mandatory
                    }
                    GetSharedLoadBalancers {
                        $enum.HelpUri += '#shared-load-balancers-get-shared-load-balancers'
                        $enum.Structure = 'GET https://api.ctl.io/v2/sharedLoadBalancers/{accountAlias}/{dataCenter}'
                        add-parameter -name accountAlias -mandatory
                        add-parameter -name dataCenter -mandatory -values $enum.DataCenters
                    }
                    UpdateLoadBalancerNodes {
                        $enum.HelpUri += '#shared-load-balancers-update-load-balancer-nodes'
                        $enum.Structure = 'PUT https://api.ctl.io/v2/sharedLoadBalancers/{accountAlias}/{dataCenter}/{loadBalancerId}/pools/{poolId}/nodes'
                        add-parameter -name accountAlias -mandatory
                        add-parameter -name dataCenter -mandatory -values $enum.DataCenters
                        add-parameter -name loadBalancerId -mandatory
                        add-parameter -name poolId -mandatory
                        add-parameter -name content -mandatory -type ([object])
                    }
                    UpdateLoadBalancerPool {
                        $enum.HelpUri += '#shared-load-balancers-update-load-balancer-pool'
                        $enum.Structure = 'PUT https://api.ctl.io/v2/sharedLoadBalancers/{accountAlias}/{dataCenter}/{loadBalancerId}/pools/{poolId}'
                        add-parameter -name accountAlias -mandatory
                        add-parameter -name dataCenter -mandatory -values $enum.DataCenters
                        add-parameter -name loadBalancerId -mandatory
                        add-parameter -name poolId -mandatory
                        add-parameter -name content -mandatory -type ([object])
                    }
                    UpdateSharedLoadBalancer {
                        $enum.HelpUri += '#shared-load-balancers-update-shared-load-balancer'
                        $enum.Structure = 'PUT https://api.ctl.io/v2/sharedLoadBalancers/{accountAlias}/{dataCenter}/{loadBalancerId}'
                        add-parameter -name accountAlias -mandatory
                        add-parameter -name dataCenter -mandatory -values $enum.DataCenters
                        add-parameter -name loadBalancerId -mandatory
                        add-parameter -name content -mandatory -type ([object])
                    }
                }
            }
        }
        # return dictionary
        $dictionary
    }

    begin {
        function convertToJson {
            param ([object]$object)
            $jsonpattern = '(^\[.*|\n\]$)|(^{.*|\n}$)'
            $object = if ($object -is [string] -and $object -match $jsonpattern) {
                # presume JSON
                $object
            } else {
                # everything else try to convert
                $object | ConvertTo-Json -Depth 10 -Compress
            }
            if ($object -notmatch $jsonpattern) {
                # ConvertTo-Json doesn't add [] for single values
                $object = "[$object]"
            }
            return $object
        }
    }

    process {
        # if help is called, open help uri and exit
        if ($Help) {
            Start-Process $enum.HelpUri
            break
        }
        Write-Verbose "ParameterSetName $($PSCmdlet.ParameterSetName)"
        # split $structure
        $method,$uri = $enum.Structure -split ' '
        # replace {variableName} with actual values
        $res = Select-String -InputObject $uri -Pattern '{[a-z|A-Z|0-9]+}' -AllMatches
        $res.Matches.Value | ForEach-Object {
            $value = $dictionary.($_ -replace '{|}').Value
            $uri = $uri -replace $_,$value
        }
        # construct splat
        $params = @{
            Uri         = $uri
            Method      = $method
            WebSession  = $WebSession
            ErrorAction = 'Stop'
        }
        # add body if exist
        if ($dictionary.ContainsKey('content')) {
            $params += @{
                Body = $dictionary.Content.Value
                ContentType = 'application/json'
            }
        }
        # verify
        if ($method -eq 'GET' -or $Force -or $PSCmdlet.ShouldProcess($uri,$method)) {
            # invoke and return
            try {
                Write-Verbose "Invoke-RestMethod params:`n$(ConvertTo-Json $params)"
                $params.Body = convertToJson $params.Body
                $response = Invoke-RestMethod @params
                Write-Verbose "Invoke-RestMethod response:`n$(ConvertTo-Json $response)"
                if ($Json) {
                    ConvertTo-Json $response -Depth 10
                } else {
                    $response
                }
            } catch {
                $err = "`n$method $uri"
                if ($params.ContainsKey('Body')) {
                    $err  += "`ncontent : $($params.Body)"
                }
                $err += "`n$($_.Exception.Message)"
                $err += "`n$_"
                Write-Host $err -ForegroundColor Red
                throw $_
            }
        }
    }
}



# *** Aliases ***
#<#
    New-Alias -Name i1 -Value  Invoke-ControlApi1 -Scope Global -Force
    New-Alias -Name i2 -Value  Invoke-ControlApi2 -Scope Global -Force
    Export-ModuleMember -Function *
#>

<#
    .DESCRIPTION
        Collection of functions to store, retrieve, remove credentials in/from Windows Registry.
        Credentials are grouped by user-defined 'FriendlyName' in a hive
        HKCU:\Environment\Credentials\<FriendlyName>.
        Each credential item has a name (i.e. 'Username', 'ApiToken') and a value (i.e. 'dom.com\MyUserName').
        Values are encrypted and may be decrypted and retrieved only on the same computer
        under the same user account.

    .REQUIRED MODULES

    .FUNCTIONS
        Export-Credential
        Import-Credential
        Remove-Credential

    .NOTES
        Company : CenturyLink Cloud
        Author  : Dmitry Gancho

    .SERVICE
        # F8 line below to generate module manifest and copy contents of this module folder to destination folder.
        Publish-ThisModule #-Destination "$env:USERPROFILE\Documents\GitHub\toolbox\PowerShell Modules"
#>



function Export-Credential {
<#
    .SYNOPSIS
        Export encrypted credential to path HKCU:\Environment\Credentials\<FriendlyName>
    .DESCRIPTION
        If path does not exist, it is created`n
        Credential can be imported and decrypted only on the same computer under the same User account
        Ruturns NULL or [PSCustomObject]
        WARNING: Existing values overwritten with no warning
        Author   : Dmitry Gancho
        Last edit: 10/22/2015
    .PARAMETER FriendlyName
        Friendly name for credentials entry
    .PARAMETER UserName
        User name
    .PARAMETER Password
        Plaing text password
    .PARAMETER EntryName
        Name for encrypted value, i.e. MySecretKey  
    .PARAMETER EntryValue
        Value, i.e. qwef4q1w4
    .PARAMETER HashTable
        Hastable of Name/Value pairs to save, i.e. @{UserName='me@live.com';PIN='1234';Key='qwef4q1w4'}
    .PARAMETER PassThru
        Returns exported credential if True
    .EXAMPLE
        Export-Credential -FriendlyName Microsoft -Credential (Get-Credential)
        ParameterSetName : PSCredential
    .EXAMPLE
        Export-Credential -FriendlyName Microsoft -UserName me@live.com -Password P@ssw0rd!
        ParameterSetName : UserPass
    .EXAMPLE
        Export-Credential -FriendlyName Microsoft -EntryName MySecret -EntryValue P@ssw0rd!
        ParameterSetName = Single
    .EXAMPLE
        Export-Credential -FriendlyName mycredandkey -HashTable @{UserName='me@live.com';PIN='1234';Key='qwef4q1w4'}
        ParameterSetName : HashTable
    .LINK
        https://msdn.microsoft.com/en-us/library/windows/desktop/ms724946(v=vs.85).aspx
    .LINK
        http://www.mssqlnotes.es/powershell-two-methods-to-encrypt-and-decrypt-passwords/
#>



    [CmdletBinding(DefaultParametersetName='PSCredential')]
    param (
        [Parameter(Mandatory,Position=0)]
        [ValidateScript({$_ -notmatch "\\|\/"})]
        [Alias('name','n')]
        [string]$FriendlyName,

        [Parameter(Position=1,ParameterSetName='PSCredential')]
        [Alias('cred','cr')]
        [PSCredential]$Credential,

        [Parameter(Mandatory,ParameterSetName='UserPass')]
        [Alias('user','u')]
        [string]$UserName,

        [Parameter(Mandatory,ParameterSetName='UserPass')]
        [Alias('pass','p')]
        [string]$Password,

        [Parameter(Mandatory,ParameterSetName='Single')]
        [string]$EntryName,

        [Parameter(Mandatory,ParameterSetName='Single')]
        [string]$EntryValue,

        [Parameter(Mandatory,ParameterSetName='HashTable')]
        [Alias('hash','h')]
        [HashTable]$HashTable,

        [switch]$PassThru=$false
    ) #param

    #region FUNCTIONS
        
        function export-regentry {
            param (
                [string]$name,
                [string]$value
            )
            # encrypt
            $encrvalue = $value | ConvertTo-SecureString -AsPlainText -Force | ConvertFrom-SecureString
            Write-Verbose -Message "Registry Entry '$name' encrypted"
            # save
            try {
                New-ItemProperty `
                    -Path $fullpath `
                    -Name $name `
                    -Value $encrvalue `
                    -PropertyType String `
                    -Force:$true `
                    -ErrorAction Stop `
                    | Out-Null
                Write-Verbose -Message "Registry Entry '$name' saved"
            } catch {
                Write-Verbose -Message "Registry Entry '$name' not saved"
                Write-Verbose -Message 'ERROR: '+ $Error[0].Exception.Message
            }
        } #function

        function get-credfromuser {
            param (
                [string]$name,
                [string]$user=$null
            )
            $i=0; do {
                $cred = Get-Credential -Message "Enter credential for '$name'" -UserName $user
                $i++
            } until ($cred -is [PSCredential] -or $i -eq 2)
            if ($cred -is [PSCredential]) {
                Write-Verbose -Message "Credential aquired interactively on $i attempt"
            } else {
                Write-Verbose -Message "Credential not aquired interactively on $i attempts"
            }
            return $cred
        }

    #endregion

    #region TEST PATH
        # verify root path
        $rootpath = 'HKCU:\Environment\Credentials'
        if (-not (test-regkey -path $rootpath -create)) {
            Write-Verbose "Unable to access path '$rootpass'"
            return $null
        } #if
        # verify root\$FriendlyName path
        $fullpath = "HKCU:\Environment\Credentials\$FriendlyName"
        if (-not (test-regkey -path $fullpath -create)) {
            Write-Verbose "Unable to access path '$fullpass'"
            return $null
        } #if
    #endregion

    #region CONVERT PARAMETERS TO HASH
        $hash = @{}
        Write-Verbose -Message "ParameterSetName: $($PsCmdlet.ParameterSetName)"
        switch ($PsCmdlet.ParameterSetName) {
            PSCredential {
                if (-not $Credential) {
                    $Credential = get-credfromuser -name $FriendlyName
                }
                if ($Credential -is [PSCredential]) {
                    $hash.UserName = $Credential.UserName
                    # Password can be empty
                    $pass = try   {$Credential.GetNetworkCredential().Password}
                            catch {$null}
                    if ($pass) {$hash.Password = $pass}
                } else {
                    return $null
                }
            }
            UserPass {
                $hash.UserName = $UserName
                $hash.Password = $Password
            }
            Single {
                $hash.$EntryName = $EntryValue
            }
            HashTable {
                $hash += $HashTable
            }
            default {
                # unknown ParameterSetName
                return $null
            }
        } #switch
    #endregion

    #region BUSINESS
        # export hash entries
        $hash.Keys | Foreach-Object {
            export-regentry -name $_ -value $hash.$_
        } #%
        # output
        if ($PassThru) {
            $hash.FriendlyName = $FriendlyName
            return [PSCustomObject]$hash
        } #if
    #endregion

} #function



function Import-Credential {
<#
    .SYNOPSIS
        Import and decrypt credential from HKCU:\Environment\Credentials\<FriendlyName>
    .DESCRIPTION
        Import and decrypt credential from HKCU:\Environment\Credentials\<FriendlyName>
        Credential can be imported and decrypted only on the same computer under the same User account
        where they have been exported (saved)
        Can return [PSCredential] object, all entries, single (named) entry
        If switch -NewIfNotFound specified AND no such credential found, will inquire from User 
        interactively and export for reuse next time (only [PSCredential]
        Author   : Dmitry Gancho
        Last edit: 10/9/2015
    .EXAMPLE
        Import-Credential -FriendlyName Microsoft -NewIfNotFound
    .EXAMPLE
        Import-Credential -FriendlyName Microsoft -As HashTable
    .EXAMPLE
        Import-Credential -FriendlyName Microsoft -EntryName Password
    .PARAMETER FriendlyName
        Friendly Name used to identify credentials
    .PARAMETER EntryName
        Name of credential entry to return
    .PARAMETER NewIfNotFound
        If set of credential is not found, inquire User interactively and export for reuse
    .PARAMETER As
        Type of object to return. Can be either 'PSCredential','HashTable','PSCustomObject'
    .NOTES
    .LINK
#>
    [CmdletBinding(DefaultParameterSetName='MultiplyEntries')]
    param (
        #[Parameter(ParameterSetName='MultiplyEntries')]
        [ValidateSet('PSCredential','HashTable','PSCustomObject','NetworkCredential')]
        [string]$As='PSCredential',

        [Parameter(ParameterSetName='NewIfNotFound')]
        [switch]$NewIfNotFound
    ) #param

    DynamicParam {

        function New-DynamicParameter {
            param ([System.String]$ParamName,
                   [System.String[]]$ParamAliases,
                   [System.String[]]$ParamValues,
                   [System.Management.Automation.ParameterAttribute]$Attributes)
            # create attributecollection
            $attributeCollection = New-Object -TypeName System.Collections.ObjectModel.Collection[System.Attribute]
            # add attributes
            $attributeCollection.Add($attributes)
            # set aliase attribute
            if ($ParamAliases) {
                $attributeCollection.Add((New-Object -TypeName System.Management.Automation.AliasAttribute($ParamAliases)))
            }
            # set validateset attribute
            if ($ParamValues) {
                $attributeCollection.Add((New-Object -TypeName System.Management.Automation.ValidateSetAttribute($ParamValues)))
            }
            # create parameter specifying the attribute collection
            $dynParam = New-Object -TypeName System.Management.Automation.RuntimeDefinedParameter($ParamName,[string],$attributeCollection)
            # add to dictionary
            $paramDictionary.Add($ParamName,$dynParam)
        } #function

        # define dictionary
        $paramDictionary = New-Object -TypeName System.Management.Automation.RuntimeDefinedParameterDictionary

        #region PARAMETERs name,values,attributes

            # dynamic parater FriendlyName
            [string]$paramName = 'FriendlyName'
            [string[]]$paramAliases = 'name','n'
            if ($PsCmdlet.ParameterSetName -eq 'NewIfNotFound') {
                [string[]]$paramValues = $null
            } else {
                [string[]]$paramValues = & {
                    $path = 'HKCU:\Environment\Credentials'
                    if (Test-Path -Path $path) {
                        Get-ChildItem -Path $path | Select-Object -ExpandProperty Name | Split-Path -Leaf
                    }
                }
            }
            # set attributes
            $attributes = New-Object -TypeName System.Management.Automation.ParameterAttribute
            $attributes.Mandatory = $true
            $attributes.Position = 0
            $attributes.ParameterSetName = '__AllParameterSets'
            New-DynamicParameter -ParamName $paramName -ParamAliases $paramAliases -ParamValues $paramValues -Attributes $attributes

            # dynamic parater EntryName
            [string]$paramName = 'EntryName'
            $attributes = New-Object -TypeName System.Management.Automation.ParameterAttribute
            $attributes.Mandatory = $true
            $attributes.ParameterSetName = 'SingleEntry'
            New-DynamicParameter -ParamName $paramName -Attributes $attributes

        #endregion

        # return dictionary
        return $paramDictionary

    } #DynamicParam

    begin {

        function decrypt-string {
            # http://www.mssqlnotes.es/powershell-two-methods-to-encrypt-and-decrypt-passwords/
            param (
                [Parameter(Mandatory)]
                [string]$string
            )
            $ErrorActionPreference = 'Stop'
            try {
                $secstring = ConvertTo-SecureString $string
                [Runtime.InteropServices.Marshal]::PtrToStringAuto(
                    [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secstring)
                )
                Write-Verbose -Message "Decrypted successfully"
            } catch {
                Write-Verbose -Message "Failed to decrypt"
                Write-Verbose -Message "ERROR: " + $Error[0].Exception.Message
                return $null
            } #try-catch
        } #fucntion


        function read-regentries {
            param (
                [Parameter(Mandatory)]
                [string]$subkey
            )

            $output = @{}

            $fullpath = "HKCU:\Environment\Credentials\$subkey"
            if (test-regkey -path $fullpath) {
                # read entries at $path
                $allentries = Get-ItemProperty -Path $fullpath -Name * -ErrorAction SilentlyContinue
                if ($allentries) {
                    $output = @{}
                    # these are to be excluded
                    $exclentries = 'PSPath','PSProvider','PSParentPath','PSChildName','PSDrive'
                    $entriesnames = $allentries | Get-Member -MemberType NoteProperty | `
                        Where-Object -FilterScript {$_.Name -notin $exclentries} | `
                        Select-Object -ExpandProperty Name
                    $entriesnames | Foreach-Object {
                        if ($allentries.$_) {
                            $output.$_ = decrypt-string $allentries.$_
                        }
                    } #%
                } #if
            } #if

            return $output

        } #function


        function compile-credential {
            param (
                [hashtable]$entries,
                [ValidateSet('PSCredential','NetworkCredential')]
                [string]$as='PSCredential'
            )
                if ($entries.ContainsKey('UserName')) {
                    $user = $entries.UserName
                    if ($entries.ContainsKey('Password')) {
                        $pass = $entries.Password | ConvertTo-SecureString -AsPlainText -Force
                    } else {
                        $pass = New-Object -TypeName System.Security.SecureString
                    }
                    switch ($as) {
                        PSCredential {   
                            return New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $user,$pass
                        }
                        NetworkCredential {
                            return New-Object -TypeName System.Net.NetworkCredential -ArgumentList $user,$pass
                        }
                    }
                } else {
                    return $null
                }
        } #function


        # bind dynamic parameters to named variables
        $paramDictionary.Keys | Foreach-Object {New-Variable -Name $_ -Value $paramDictionary.$_.Value -Force}

    } #begin

    process {

        # read enrties from Registry
        $entries = read-regentries -subkey $FriendlyName

        switch ($PsCmdlet.ParameterSetName) {
            SingleEntry {
                if ($entries.ContainsKey($EntryName)) {
                    return $entries.$EntryName
                } else {
                    return $null
                }
            }
            MultiplyEntries {
                switch ($As) {
                    HashTable      {
                        return [hashtable]$entries
                    }
                    PSCUstomObject {
                        return [PSCustomObject]$entries
                    }
                    PSCredential {
                        return compile-credential $entries $As
                    }
                    NetworkCredential {
                        return compile-credential $entries $As
                    }
                    default {
                        return $null
                    }
                }
            }
            NewIfNotFound {
                # this is only to inquire [PSCredential] interactively from user
                # Syntax: Import-Credential -FriendlyName Microsoft -NewIfNotFound
                $cred = compile-credential -entries $entries
                if (-not $cred) {
                    Export-Credential -FriendlyName $FriendlyName
                }
                $cred = Import-Credential -FriendlyName $FriendlyName -As $As
                return $cred
            }
            default {
                return $null
            }
        } #switch
    
    } #process

} #function



function Remove-Credential {
<#
    .SYNOPSIS
        Remove set of credential stored in HKCU:\Environment\Credentials\<FriendlyName>
    .DESCRIPTION
        Remove set of credential stored in HKCU:\Environment\Credentials\<FriendlyName>
        Author   : Dmitry Gancho
        Last edit: 10/2/2015
    .EXAMPLE
        Remove-Credential -FriendlyName Microsoft
    .EXAMPLE
        Remove-Credential -FriendlyName Microsoft -Force
    .PARAMETER FriendlyName
        Friendly Name for credentials (strict match)
    .PARAMETER Force
        If False, User is asked before remove
        If True, User is not asked before remove
    .NOTES
    .LINK
#>
    [CmdletBinding(SupportsShouldProcess,ConfirmImpact='High')]
    param (
        [switch]$Force=$false
    ) #param

    DynamicParam {
        function New-DynamicParameter {
            param ([System.String]$ParamName,
                   [System.String[]]$ParamAliases,
                   [System.String[]]$ParamValues,
                   [System.Management.Automation.ParameterAttribute]$Attributes)
            $attributeCollection = New-Object -TypeName System.Collections.ObjectModel.Collection[System.Attribute]
            $attributeCollection.Add($attributes)
            $attributeCollection.Add((New-Object -TypeName System.Management.Automation.AliasAttribute($ParamAliases)))
            $attributeCollection.Add((New-Object -TypeName System.Management.Automation.ValidateSetAttribute($ParamValues)))
            $dynParam = New-Object -TypeName System.Management.Automation.RuntimeDefinedParameter($ParamName,[string],$attributeCollection)
            $paramDictionary.Add($ParamName,$dynParam)
        }

        $paramDictionary = New-Object -TypeName System.Management.Automation.RuntimeDefinedParameterDictionary

        [string]$paramName = 'FriendlyName'
        [string[]]$paramAliases = 'name','n'
        [string[]]$paramValues = Get-ChildItem -Path HKCU:\Environment\Credentials | Select-Object -ExpandProperty Name | Split-Path -Leaf
        $attributes = New-Object -TypeName System.Management.Automation.ParameterAttribute
        $attributes.Mandatory = $true
        $attributes.Position = 0
        New-DynamicParameter -ParamName $paramName -ParamAliases $paramAliases -ParamValues $paramValues -Attributes $attributes

        return $paramDictionary

    } #DynamicParam

    begin {
        # Bind the parameter to a friendly variable
        $FriendlyName = $PsBoundParameters[$paramName]
    } #begin

    process {
        # test path
        $fullpath = "HKCU:\Environment\Credentials\$FriendlyName"
        if (-not (Test-Path -Path $fullpath)) {
            Write-Host "ERROR: Path '$fullpath' does not exist or not accessible" -ForegroundColor Red
            return
        } #if

        # remove
        if ($Force -or $PSCmdlet.ShouldProcess($fullpath)) {
            Remove-Item -Path $fullpath -Force
        } #if
    } #process

} #function



function test-regkey {
    # helper function, not for export
    # test (and create if -create switch is specified) Regsitry Key
    # return [bool]
    param (
        [Parameter(Mandatory)]
        [ValidateScript({$_ -match 'HKCU:\\Environment\\Credentials.*'})]
        [string]$path,
        [switch]$create=$false
    ) #param
    if (Test-Path -Path $path) {
        Write-Verbose -Message "Registry Key '$path' found"
        return $true
    } else {
        Write-Verbose -Message "Registry Key '$path' not found"
        if ($create) {
            try {
                New-Item -Path $path -Force -ErrorAction Stop
                Write-Verbose -Message "Registry Key '$path' created"
                return $true
            } catch {
                Write-Verbose -Message "Registry Key '$path' not created"
                Write-Verbose -Message "ERROR: " + $Error[0].Exception.Message
                return $false
            }
        } else {
            return $false
        }
    }
} #function




# *** Aliases and Export ***
New-Alias -Name ecr -Value Export-Credential -Scope Global -Force
New-Alias -Name icr -Value Import-Credential -Scope Global -Force
New-Alias -Name rcr -Value Remove-Credential -Scope Global -Force

Export-ModuleMember -Function Export-Credential
Export-ModuleMember -Function Import-Credential
Export-ModuleMember -Function Remove-Credential

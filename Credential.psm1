
<#
    .DESCRIPTION
        Functions in the module:
        Export-Credential
        Import-Credential
        Remove-Credential
        test-regkey (module scope)
    .VERSION
        Version 1.1
#>



function test-regkey {
    # helper function, not for export
    # test (and create if $Create switch is specified) Regsitry Key
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




function Export-Credential {
<#
    .SYNOPSIS
        Export encrypted credential to path HKCU:\Environment\Credentials\<FriendlyName>
    .DESCRIPTION
        Export encrypted credential to path HKCU:\Environment\Credentials\<FriendlyName>
        If path does not exist, it is created
        Credential can be imported and decrypted only on the same computer under the same User account
        Ruturns NULL or [PSCustomObject]
        WARNING: Existing values overwritten with no warning
    .EXAMPLE (ParameterSetName = PSCredential)
        Export-Credential -FriendlyName Microsoft -Credential (Get-Credential)
    .EXAMPLE (ParameterSetName = UserPass)
        Export-Credential -FriendlyName Microsoft -UserName me@live.com -Password P@ssw0rd!
    .EXAMPLE (ParameterSetName = Single)
        Export-Credential -FriendlyName Microsoft -EntryName MySecret -EntryValue P@ssw0rd!
    .EXAMPLE (ParameterSetName = HashTable)
        Export-Credential -FriendlyName mycredandkey -HashTable @{UserName='me@live.com';PIN='1234';Key='qwef4q1w4'}
    .PARAMETER [string]FriendlyName
        Friendly name for credentials entry
    .PARAMETER [PSCredential]Credential
        Credential
    .PARAMETER [string]UserName
        User name
    .PARAMETER [string]Password
        Plaing text password
    .PARAMETER [string]EntryName
        Name for encrypted value, e.i. MySecretKey  
    .PARAMETER [string]EntryValue
        Value, e.i. qwef4q1w4
    .PARAMETER HashTable
        Hastable of Name/Value pairs to save, i.e. @{UserName='me@live.com';PIN='1234';Key='qwef4q1w4'}
    .PARAMETER PassThru, default:False
        Returns exported credential if True
    .NOTES
        Author: Dmitry Gancho
        Last edit: 10/2/2015
        Registry Terminology: https://msdn.microsoft.com/en-us/library/windows/desktop/ms724946(v=vs.85).aspx
    .LINK
#>
    [CmdletBinding(DefaultParametersetName='PSCredential')]
    param (
        [Parameter(Mandatory,Position=0)]
        [ValidateScript({$_ -notmatch "\W"})]
        [Alias('name','n')]
        [string]$FriendlyName,

        [Parameter(Position=1,ParameterSetName='PSCredential')]
        [Alias('cred','cr')]
        [PSCredential]$Credential,

        [Parameter(Mandatory,ParameterSetName='UserPass')]
        [ValidateNotNullOrEmpty()]
        [Alias('user','u')]
        [string]$UserName,

        [Parameter(Mandatory,ParameterSetName='UserPass')]
        [ValidateNotNullOrEmpty()]
        [Alias('pass','p')]
        [string]$Password,

        [Parameter(Mandatory,ParameterSetName='Single')]
        [ValidateNotNullOrEmpty()]
        [string]$EntryName,

        [Parameter(Mandatory,ParameterSetName='Single')]
        [ValidateNotNullOrEmpty()]
        [string]$EntryValue,

        [Parameter(Mandatory,ParameterSetName='HashTable')]
        [ValidateNotNullOrEmpty()]
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
            # http://www.mssqlnotes.es/powershell-two-methods-to-encrypt-and-decrypt-passwords/
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
                [ValidateNotNullOrEmpty()]
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
        $hash.Keys | % {
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
        If switch NewIfNotFound specified AND no such credential found, will inquire from User 
        interactively and export for reuse next time (only [PSCredential]
    .EXAMPLE
        Import-Credential -FriendlyName Microsoft -NewIfNotFound
    .EXAMPLE
        Import-Credential -FriendlyName Microsoft -As HashTable
    .EXAMPLE
        Import-Credential -FriendlyName Microsoft -EntryName Password
    .PARAMETER FriendlyName (alias 'name',n')
        Friendly Name used to identify credentials
    .PARAMETER EntryName
        Name of credential entry to return
    .PARAMETER NewIfNotFound
        If set and credential not found, inquire User interactively and export for reuse
    .PARAMETER As
        Type of object to return. Can be either 'PSCredential','HashTable','PSCustomObject'
    .NOTES
        Author: Dmitry Gancho
        Last edit: 10/9/2015
#>
    [CmdletBinding(DefaultParameterSetName='MultiplyEntries')]
    param (
        #[Parameter(ParameterSetName='MultiplyEntries')]
        [ValidateSet('PSCredential','HashTable','PSCustomObject')]
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

        #region PARAMETERs name,values,attributes - repeat for each dynamic parameter

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
            #$attributes.HelpMessage = [string]$null
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

<#      NOTE: in begin section assign parameter(s) to named variables:
        begin {
            $paramDictionary.Keys | % {New-Variable -Name $_ -Value $paramDictionary.$_.Value -Force}
        }
#>

    } #DynamicParam

    begin {

        function decrypt-string {
            # http://www.mssqlnotes.es/powershell-two-methods-to-encrypt-and-decrypt-passwords/
            param (
                [Parameter(Mandatory)]
                [ValidateNotNullOrEmpty()]
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
                [ValidateNotNullOrEmpty()]
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
                    $entriesnames | % {
                        if ($allentries.$_) {
                            $output.$_ = decrypt-string $allentries.$_
                        }
                    } #%
                } #if
            } #if

            return $output

        } #function


        function compile-credential {
            param ([HashTable]$entries)
                if ($entries.ContainsKey('UserName')) {
                    $user = $entries.UserName
                    if ($entries.ContainsKey('Password')) {
                        $pass = $entries.Password | ConvertTo-SecureString -AsPlainText -Force
                    } else {
                        $pass = New-Object -TypeName System.Security.SecureString
                    }
                    return New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $user,$pass
                } else {
                    return $null
                }
        } #function


        # bind dynamic parameters to named variables
        $paramDictionary.Keys | % {New-Variable -Name $_ -Value $paramDictionary.$_.Value -Force}

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
                        return [HashTable]$entries
                    }
                    PSCUstomObject {
                        return [PSCustomObject]$entries
                    }
                    PSCredential {
                        return compile-credential $entries
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
    .EXAMPLE
        Remove-Credential -FriendlyName Microsoft
    .EXAMPLE
        Remove-Credential -FriendlyName Microsoft -Force
    .PARAMETER FriendlyName (alias name)
        Friendly Name for credentials (strict match)
    .PARAMETER Force, default:False
        If False, User is asked before remove
        If True, User is not asked before remove
    .NOTES
        Author: Dmitry Gancho
        Last edit: 10/2/2015
#>
    [CmdletBinding(SupportsShouldProcess,ConfirmImpact='High')]
    param (
        [switch]$Force=$false
    ) #param

    DynamicParam {
        # NOTE: see more detailed example in function 'Import-Credential'
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




# *** Aliases and Export ***
Export-ModuleMember -Function Export-Credential -Alias ecred
Export-ModuleMember -Function Import-Credential -Alias icred
Export-ModuleMember -Function Remove-Credential -Alias rcred


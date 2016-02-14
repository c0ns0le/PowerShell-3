<#
.DESCRIPTION
    Operations with Windows registry on local or remote computer.

.REQUIRED MODULES

.FUNCTIONS
    Get-ComputerRegistry

.NOTES
    Company   : CenturyLink Cloud
    Author    : Dmitry Gancho

.LINK

.SERVICE
    # F8 line below in PowerShell_ISE to generate module manifest and copy contents of current folder to destination folder.
    Publish-ThisModule -Destination "$env:USERPROFILE\Documents\GitHub\CC-Preproduction\Dmitry Gancho\"
    Publish-ThisModule -Destination "$env:USERPROFILE\Documents\GitHub\PowerShell\"
#>


function Get-ComputerRegistry {
<#
.SYNOPSIS
        Get/Set registry values on local or remote computer via .NET, WMI or PSRemoting.

        .NET Object
        -------------
        $reg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine,ComputerName)

        Properties
        -------------
        Name
        SubKeyCount
        ValueCount

        Methods (some)
        -------------
        CreateSubKey
        DeleteSubKey
        DeleteSubKeyTree
        DeleteValue
        GetAccessControl
        GetLifetimeService
        GetSubKeyNames
        GetType
        GetValue
        GetValueKind
        GetValueNames
        OpenSubKey
        SetAccessControl
        SetValue

        Example
        -------------
        $hklmType           = [Microsoft.Win32.RegistryHive]::LocalMachine
        $hklmBase           = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey($hklmType,$ComputerName)
        $hklmSubKey         = $hklmBase.OpenSubKey('SOFTWARE\MICROSOFT')
        $accessControl      = $hklmSubKey.GetAccessControl()
        $accessControlRules = $accessControl.GetAccessRules($true,$true,[System.Security.Principal.NTAccount])

        
        WMI Object
        -------------
        $reg = [wmiclass]'\\ComputerName\root\default:StdRegProv'
        
        Methods
        -------------
        $reg.Methods | ft name
        Name                                                  
        ----                                             
        CheckAccess                                                  
        EnumKey                                                   
        EnumValues                                                 
        GetDWORDValue                                                 
        GetQWORDValue                                                   
        GetStringValue                                                  
        GetMultiStringValue                                                  
        GetExpandedStringValue                                                  
        GetBinaryValue                                                 
        CreateKey                                                 
        DeleteKey                                                 
        DeleteValue                                                 
        SetDWORDValue                                                 
        SetQWORDValue                                                 
        SetStringValue                                                  
        SetMultiStringValue                                                 
        SetExpandedStringValue                                                 
        SetBinaryValue                                                 
        SetSecurityDescriptor            

        Example
        -------------
        $HKEY_LOCAL_MACHINE = 2147483650 
        $Reg                = [WMIClass]'\\CO1PRODSIM\ROOT\DEFAULT:StdRegProv'
        $Key                = 'SOFTWARE\Microsoft\Virtual Machine\Guest\Parameters'
        $Results            = $Reg.EnumValues($HKEY_LOCAL_MACHINE, $Key)
        $Result             = $Reg.GetStringValue($HKEY_LOCAL_MACHINE,$Key,'PhysicalHostName')

        Example (1 line)
        -------------
        (([WMIClass]'\\CO1PRODSIM\ROOT\DEFAULT:StdRegProv').GetStringValue(2147483650,'SOFTWARE\Microsoft\Virtual Machine\Guest\Parameters','PhysicalHostName')).sValue

.DESCRIPTION
    Author   : Dmitry Gancho
    Last edit: 1/25/2015

.EXAMPLE
    if ((gp HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System).ConsentPromptBehaviorAdmin -ne 0) {
        start "$PSHome\powershell.exe" -WindowStyle Hidden -Verb runas `
        -ArgumentList ('sp HKLM:\Software\Microsoft\Windows\CurrentVersion\policies\system -Name ConsentPromptBehaviorAdmin -Value 0')
    } #if

.LINK
#>
    [CmdletBinding(DefaultParameterSetName='Common',
                   SupportsShouldProcess,
                   ConfirmImpact='High')]
    param(

        [Parameter(Position=0)]
        [Alias('comp','cn')]
        [string]$ComputerName = $env:COMPUTERNAME,

        [Parameter(ParameterSetName='Common',Mandatory)]
        [ValidateSet(
            'ConsentPromptBehaviorAdmin'    ,
            'ConsentPromptBehaviorUser'     ,
            'SCForceOption'                 ,
            'EnableLinkedConnections'       ,
            'fDenyTSConnections'            ,
            'FileAndPrint'                  ,
            'PhysicalHostName'              ,
            'PhysicalHostNameFullyQualified',
            'ProductName'                   ,
            'AutorecoverMOFs'
        )]
        [string]$Common,

        [Parameter(ParameterSetName='Generic',Mandatory)]
        [ValidateSet(
            'HKEY_CLASSES_ROOT'    ,
            'HKEY_CURRENT_USER'    ,
            'HKEY_LOCAL_MACHINE'   ,
            'HKEY_USERS'           ,
            'HKEY_PERFORMANCE_DATA',
            'HKEY_CURRENT_CONFIG'  ,
            'HKEY_DYN_DATA'
        )]
        [string]$Hive = 'HKEY_LOCAL_MACHINE',
        
        [Parameter(ParameterSetName='Generic')]
        [string]$Key = 'SOFTWARE',
        
        [Parameter(ParameterSetName='Generic')]
        [string]$Value,

        [Parameter()]
        [ValidateSet(
            'NET',
            'WMI',
            'PSR',
            'Any',
            'Info'
        )]
        [string]$Method = 'Any',

        [Parameter()]
        [string]$Set,

        [Parameter()]
        [switch]$Force

    ) #param

    begin {
 
        #region INITIALIZATION
            
            # common values
            $wkvHt = [ordered]@{
                ConsentPromptBehaviorAdmin     = @('HKEY_LOCAL_MACHINE','SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'           )
                ConsentPromptBehaviorUser      = @('HKEY_LOCAL_MACHINE','SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'           )
                SCForceOption                  = @('HKEY_LOCAL_MACHINE','SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'           )
                EnableLinkedConnections        = @('HKEY_LOCAL_MACHINE','SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'           )
                fDenyTSConnections             = @('HKEY_LOCAL_MACHINE','SYSTEM\CurrentControlSet\Control\Terminal Server'                    )
                FileAndPrint                   = @('HKEY_LOCAL_MACHINE','SOFTWARE\Policies\Microsoft\WindowsFirewall\StandardProfile\Services')
                PhysicalHostName               = @('HKEY_LOCAL_MACHINE','SOFTWARE\Microsoft\Virtual Machine\Guest\Parameters'                 )
                PhysicalHostNameFullyQualified = @('HKEY_LOCAL_MACHINE','SOFTWARE\Microsoft\Virtual Machine\Guest\Parameters'                 )
                ProductName                    = @('HKEY_LOCAL_MACHINE','SOFTWARE\Microsoft\Windows NT\CurrentVersion'                        )
                AutorecoverMOFs                = @('HKEY_LOCAL_MACHINE','SOFTWARE\Microsoft\Wbem\CIMOM'                                       )
            } #@

            # get Hive,Key,Value for common values
            if ($PSCmdlet.ParameterSetName -eq 'Common') {
                $Hive  = $wkvHt.Item($Common)[0]
                $Key   = $wkvHt.Item($Common)[1]
                $Value = $Common
            } #if

            # root hives used by PowerShell,.NET,WMI respectively
            $hiveHt = [ordered]@{
                HKEY_CLASSES_ROOT     = @('HKCR','ClassesRoot'    ,2147483648)
                HKEY_CURRENT_USER     = @('HKCU','CurrentUser'    ,2147483649)
                HKEY_LOCAL_MACHINE    = @('HKLM','LocalMachine'   ,2147483650)
                HKEY_USERS            = @('HKU' ,'Users'          ,2147483651)
                HKEY_PERFORMANCE_DATA = @('HKPD','PerformanceData',2147483652) # 2147483652: undocumented, not tested
                HKEY_CURRENT_CONFIG   = @('HKCC','CurrentConfig'  ,2147483653)
                HKEY_DYN_DATA         = @('HKDD','DynData'        ,2147483654)
            } #@

            # WMI reg value types
            $wmiValueTypes = [ordered]@{
                1  = 'REG_SZ'
                2  = 'REG_EXPAND_SZ'
                3  = 'REG_BINARY'
                4  = 'REG_DWORD' 
                7  = 'REG_MULTI_SZ'
                11 = 'REG_QWORD'
            } #@

        #endregion

        #region FUNCTIONS

            function netGetKey ($comp,$hive,$key          ) {
                try {
                    $root = $hiveHt.Item($hive)[1]
                    Write-Verbose "Read Registry of '$comp' via .NET"
                    Write-Verbose "'$root','$key'"
                    $netKey = ([Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey($root,$comp)).OpenSubKey($key)
                    $regSubKeys = $netKey.GetSubKeyNames()
                    $regValues = [ordered]@{}
                    $netKey.GetValueNames() | % {$regValues.Add($_,"$($netKey.GetValueKind($_)): $($netKey.GetValue($_))")}
                    Write-Verbose 'Success'
                    @(".NET :  $hive`\$key",$regSubKeys,$regValues)
                } catch {
                    #Write-Verbose $Error[0].Exception.Message
                    'failed'
                } #try-catch
            } #function

            function netGetVal ($comp,$hive,$key,$val     ) {
                try {
                    $root = $hiveHt.Item($hive)[1]
                    Write-Verbose "Read Registry of '$comp' via .NET"
                    Write-Verbose "'$root','$key','$val'"
                    $regVal = (([Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey($root,$comp)).OpenSubKey($key)).GetValue($val)
                    Write-Verbose "Success, '$val' is '$regVal'"
                    $regVal
                } catch {
                    #Write-Verbose $Error[0].Exception.Message
                    'failed'
                } #try-catch
            } #function

            function netSetVal ($comp,$hive,$key,$val,$set) {
                try {
                    $root = $hiveHt.Item($hive)[1]
                    Write-Verbose "Set Registry of '$comp' via .NET"
                    Write-Verbose "'$root','$key','$val','$set'"
                    (([Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey($root,$comp)).OpenSubKey($key,$true)).SetValue($val,$set)
                    Write-Verbose 'Success'
                } catch {
                    #Write-Verbose $Error[0].Exception.Message
                } #try-catch
            } #function

            function wmiGetKey ($comp,$hive,$key          ) {
                try {
                    $root = $hiveHt.Item($hive)[2]
                    Write-Verbose "Read Registry of '$comp' via WMI"
                    Write-Verbose "'$root','$key'"
                    $wmiKey = [WMIClass]"\\$comp\ROOT\DEFAULT:StdRegProv"
                    $regSubKeys = ($wmiKey.EnumKey($root,$key)).sNames
                    $regValueObject = $wmiKey.EnumValues($root,$key)
                    $regValues = [ordered]@{}
                    foreach ($val in $regValueObject.sNames) {
                        $regType = $wmiValueTypes.$($regValueObject.Types.Item($regValueObject.sNames.IndexOf($val)))
                        $regVal = switch ($regType) {
                            'REG_SZ'        {($wmiKey.GetStringValue(        $root,$key,$val)).sValue}
                            'REG_EXPAND_SZ' {($wmiKey.GetExpandedStringValue($root,$key,$val)).sValue}
                            'REG_BINARY'    {($wmiKey.GetBinaryValue(        $root,$key,$val)).uValue}
                            'REG_DWORD'     {($wmiKey.GetDWORDValue(         $root,$key,$val)).uValue}
                            'REG_MULTI_SZ'  {($wmiKey.GetMultiStringValue(   $root,$key,$val)).sValue}
                            'REG_QWORD'     {($wmiKey.GetQWORDValue(         $root,$key,$val)).uValue}
                        } #switch
                        $regValues.Add($val,"$regType`: $regVal")
                    } #foreach
                    Write-Verbose 'Success'
                    @("WMI :  $hive`\$key",$regSubKeys,$regValues)
                } catch {
                    #Write-Verbose $Error[0].Exception.Message
                    'failed'
                } #try-catch
            } #function

            function wmiGetVal ($comp,$hive,$key,$val     ) {
                try {
                    $root = $hiveHt.Item($hive)[2]
                    Write-Verbose "Read Registry of '$comp' via WMI"
                    Write-Verbose "'$root','$key','$val'"
                    $wmiKey = [WMIClass]"\\$comp\ROOT\DEFAULT:StdRegProv"
                    $regValueObject = $wmiKey.EnumValues($root,$key)
                    $regType = $wmiValueTypes.$($regValueObject.Types.Item($regValueObject.sNames.IndexOf($val)))
                    $regVal = switch ($regType) {
                        'REG_SZ'        {($wmiKey.GetStringValue(        $root,$key,$val)).sValue}
                        'REG_EXPAND_SZ' {($wmiKey.GetExpandedStringValue($root,$key,$val)).sValue}
                        'REG_BINARY'    {($wmiKey.GetBinaryValue(        $root,$key,$val)).uValue}
                        'REG_DWORD'     {($wmiKey.GetDWORDValue(         $root,$key,$val)).uValue}
                        'REG_MULTI_SZ'  {($wmiKey.GetMultiStringValue(   $root,$key,$val)).sValue}
                        'REG_QWORD'     {($wmiKey.GetQWORDValue(         $root,$key,$val)).uValue}
                    } #switch
                    Write-Verbose "Success, '$val' is '$regVal'"
                    $regVal
                } catch {
                    #Write-Verbose $Error[0].Exception.Message
                    'failed'
                } #try-catch
            } #function

            function wmiSetVal ($comp,$hive,$key,$val,$set) {
                try {
                    $root = $hiveHt.Item($hive)[2]
                    Write-Verbose "Set Registry of '$comp' via WMI"
                    Write-Verbose "'$root','$key','$val','$set'"
                    $wmiKey = [WMIClass]"\\$comp\ROOT\DEFAULT:StdRegProv"
                    $regValueObject = $wmiKey.EnumValues($root,$key)
                    $regType = $wmiValueTypes.$($regValueObject.Types.Item($regValueObject.sNames.IndexOf($val)))
                    $null = switch ($regType) {
                        'REG_SZ'        {$wmiKey.SetStringValue(        $root,$key,$val,$set)}
                        'REG_EXPAND_SZ' {$wmiKey.SetExpandedStringValue($root,$key,$val,$set)}
                        'REG_BINARY'    {$wmiKey.SetBinaryValue(        $root,$key,$val,$set)}
                        'REG_DWORD'     {$wmiKey.SetDWORDValue(         $root,$key,$val,$set)}
                        'REG_MULTI_SZ'  {$wmiKey.SetMultiStringValue(   $root,$key,$val,$set)}
                        'REG_QWORD'     {$wmiKey.SetQWORDValue(         $root,$key,$val,$set)}
                    } #switch
                    Write-Verbose 'Success'
                } catch {
                    #Write-Verbose $Error[0].Exception.Message
                } #try-catch
            } #function

            function psrGetKey ($comp,$hive,$key          ) {
                try {
                    $root = $hiveHt.Item($hive)[0]
                    Write-Verbose "Read Registry of '$comp' via PSRemote"
                    Write-Verbose "'$root','$key'"
                    $regSubKeys,$regValues = Invoke-Command -ArgumentList $("$root`:\$key") -ComputerName $comp -ScriptBlock {(Get-ChildItem $args[0]).Name | Split-Path -Leaf; Get-ItemProperty $args[0]}
                    Write-Verbose 'Success'
                    @("PSRemote :  $hive`\$key",$regSubKeys,$regValues)
                } catch {
                    #Write-Verbose $Error[0].Exception.Message
                    'failed'
                } #try-catch
            } #function

            function psrGetVal ($comp,$hive,$key,$val     ) {
                try {
                    $root = $hiveHt.Item($hive)[0]
                    Write-Verbose "Read Registry of '$comp' via PSRemote"
                    Write-Verbose "'$root','$key','$val'"
                    # syntax for arguments(2): 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion','ProductName'
                    #$regVal = Invoke-Command -ComputerName $comp -ArgumentList $("$root`:\$key"),$val -ScriptBlock {Get-ItemProperty -Path $args[0] -Name $($args[1]} -ErrorAction Stop
                    # syntax for argument(1): 'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProductName'
                    $regVal = Invoke-Command -ComputerName $comp -ArgumentList $("$root`\$key`\$val") -ScriptBlock {(New-Object -ComObject Wscript.Shell).RegRead($args[0])} -ErrorAction Stop
                    Write-Verbose "Success, '$val' is '$regVal'"
                    $regVal
                } catch {
                    #Write-Verbose $Error[0].Exception.Message
                    'failed'
                } #try-catch
            } #function

            function psrSetVal ($comp,$hive,$key,$val,$set) {
                try {
                    $root = $hiveHt.Item($hive)[0]
                    Write-Verbose "Set Registry of '$comp' via PSRemote"
                    Write-Verbose "'$root','$key','$val','$set'"
                    # syntax for arguments(3): 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion','ProductName','New Value'
                    Invoke-Command -ArgumentList $("$root`:\$key"),$val,$set -ComputerName $comp -ScriptBlock {Set-ItemProperty -Path $args[0] -Name $args[1] -Value $args[2] -Force}
                    # syntax for arguments(2): 'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProductName','New Value'
                    #Invoke-Command -ArgumentList $("$root`\$key`\$val"),$set -ComputerName $comp -ScriptBlock {(New-Object -ComObject Wscript.Shell).RegWrite($args[0],$args[1])}
                    Write-Verbose 'Success'
                } catch {
                    #Write-Verbose $Error[0].Exception.Message
                } #try-catch
            } #function

        #endregion

        #region CODE

            $ComputerName = $ComputerName.Trim().ToUpper()
            if (($ComputerName -eq 'LOCALHOST') -or ($ComputerName -eq '.')) {$ComputerName = $env:COMPUTERNAME}

            try {$compFqdn = (Resolve-DnsName $ComputerName -Type A -ErrorAction Stop).Name | Select-Object -Unique}
            catch {if ($Error[0]) {$Error[0].ToString()}; exit}

            $ErrorActionPreference = 'Stop'

        #endregion

    } #begin

    process {

        if (!$PSBoundParameters.ContainsKey('Set')) {

        #region GET KEY or VALUE

            if ($Value) {
                # get Value
                switch ($Method) {
                    'NET' {
                        $res = netGetVal $compFqdn $Hive $Key $Value
                    } #NET
                    'WMI' {
                        $res = wmiGetVal $compFqdn $Hive $Key $Value
                    } #WMI
                    'PSR' {
                        $res = psrGetVal $compFqdn $Hive $Key $Value
                    } #PSR
                    'Any' {
                        $res = netGetVal $compFqdn $Hive $Key $Value
                        if ($res -eq 'failed') {$res = wmiGetVal $compFqdn $Hive $Key $Value}
                        if ($res -eq 'failed') {$res = psrGetVal $compFqdn $Hive $Key $Value}
                    } #Any
                    'Info' {
                        $res = [pscustomobject][ordered]@{
                            'Time Stamp'          = Get-Date -Format G
                            'Computer Name'       = $ComputerName
                            'Computer FQDN'       = $compFqdn
                            'Registry Path'       = "$($hiveHt.Item($Hive)[0])`\$Key"
                            'Registry Value'      = $Value
                            'Result via .NET'     = netGetVal $compFqdn $Hive $Key $Value
                            'Result via WMI'      = wmiGetVal $compFqdn $Hive $Key $Value
                            'Result via PSRemote' = psrGetVal $compFqdn $Hive $Key $Value
                        } #@
                    } #All
                } #switch
            } else {
                # get Key
                switch ($Method) {
                    'NET' {
                        $res = netGetKey $compFqdn $Hive $Key
                    } #NET
                    'WMI' {
                        $res = wmiGetKey $compFqdn $Hive $Key
                    } #WMI
                    'PSR' {
                        $res = psrGetKey $compFqdn $Hive $Key
                    } #PSR
                    'Any' {
                        $res = netGetKey $compFqdn $Hive $Key
                        if ($res -eq 'failed') {$res = wmiGetKey $compFqdn $Hive $Key}
                        if ($res -eq 'failed') {$res = psrGetKey $compFqdn $Hive $Key}
                    } #Any
                    'Info' {
                        $res = [pscustomobject][ordered]@{
                            'Time Stamp'               = Get-Date -Format G
                            'Computer Name'            = $ComputerName
                            'Computer FQDN'            = $compFqdn
                            'Registry Path'            = "$($hiveHt.Item($Hive)[0])`\$Key"
                            'Read Access via .NET'     = if ((netGetKey $compFqdn $Hive $Key) -ne 'failed') {$true} else {$false}
                            'Read Access via WMI'      = if ((wmiGetKey $compFqdn $Hive $Key) -ne 'failed') {$true} else {$false}
                            'Read Access via PSRemote' = if ((psrGetKey $compFqdn $Hive $Key) -ne 'failed') {$true} else {$false}
                        } #@
                    } #All
                } #switch

            } #if-else

        #endregion

        } else {

        #region SET VALUE

            if (!$Value) {Write-Warning 'Value not specified, unable to set'; return}
            if ($Method -eq 'Info') {Write-Warning '-Method Info and -Set <> parameters can not be used together'; return}

            if ($Force -or ($PSCmdlet.ShouldProcess($ComputerName,"Set Registry Value '$Value' to $Set"))) {

                switch ($Method) {
                    'NET' {
                        $res = netGetVal $compFqdn $Hive $Key $Value
                        if ($res -eq $Set) {Write-Verbose "Value '$Value' is already '$res'. Will not attempt to set."; return}
                        netSetVal $compFqdn $Hive $Key $Value $Set
                        $res = netGetVal $compFqdn $Hive $Key $Value
                    } #NET
                    'WMI' {
                        $res = wmiGetVal $compFqdn $Hive $Key $Value
                        if ($res -eq $Set) {Write-Verbose "Value '$Value' is already '$res'. Will not attempt to set."; return}
                        wmiSetVal $compFqdn $Hive $Key $Value $Set
                        $res = wmiGetVal $compFqdn $Hive $Key $Value
                    } #WMI
                    'PSR' {
                        $res = psrGetVal $compFqdn $Hive $Key $Value
                        if ($res -eq $Set) {Write-Verbose "Value '$Value' is already '$res'. Will not attempt to set."; return}
                        psrSetVal $compFqdn $Hive $Key $Value $Set
                        $res = psrGetVal $compFqdn $Hive $Key $Value
                    } #PSR
                    'Any' {
                        # test which method is working (Read)
                        $res = netGetVal $compFqdn $Hive $Key $Value
                        if ($res -ne 'failed') {$met = 'NET'}
                        else {
                            $res = wmiGetVal $compFqdn $Hive $Key $Value
                            if ($res -ne 'failed') {$met = 'WMI'}
                            else {
                                $res = psrGetVal $compFqdn $Hive $Key $Value
                                if ($res -ne 'failed') {$met = 'PSR'}
                                else {$met = $null}
                            } #if-else
                        } #if-else
                        # attempt to Set regisrty using method that worked for Read
                        switch ($met) {
                            'NET' {
                                $res = netGetVal $compFqdn $Hive $Key $Value
                                if ($res -eq $Set) {Write-Verbose "Value '$Value' is already '$res'. Will not attempt to set."; return}
                                netSetVal $compFqdn $Hive $Key $Value $Set
                                $res = netGetVal $compFqdn $Hive $Key $Value
                            } #'NET'
                            'WMI' {
                                $res = wmiGetVal $compFqdn $Hive $Key $Value
                                if ($res -eq $Set) {Write-Verbose "Value '$Value' is already '$res'. Will not attempt to set."; return}
                                wmiSetVal $compFqdn $Hive $Key $Value $Set
                                $res = wmiGetVal $compFqdn $Hive $Key $Value
                            } #'WMI'
                            'PSR' {
                                $res = psrGetVal $compFqdn $Hive $Key $Value
                                if ($res -eq $Set) {Write-Verbose "Value '$Value' is already '$res'. Will not attempt to set."; return}
                                psrSetVal $compFqdn $Hive $Key $Value $Set
                                $res = psrGetVal $compFqdn $Hive $Key $Value
                            } #'PSR'
                            default {
                                Write-Verbose 'Remote Registry access failed by all methods'
                            } #default
                        } #switch
                    } #Any
                    default {
                        Write-Verbose "Unknown method '$Method'"
                    } #default
                } #switch

            } #if-else

        #endregion
 
        } #if-else
        
    } #process

    end {

        return $res
    
    } #end

} #function


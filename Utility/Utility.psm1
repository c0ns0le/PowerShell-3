<#
    .DESCRIPTION
        Collection of general-purpose helper functions.

    .REQUIRED MODULES

    .FUNCTIONS
        Add-PSModulePath
        Publish-ThisModule
        Get-ModuleHelp
        Test-Module
        Test-Elevated
        Set-PSWindowTitle

        Test-IPv4
        Test-TCPPort
        Test-Target

        Invoke-ScriptBlock
        Invoke-Async
        Stop-Async

        ConvertTo-Regex
        ConvertFrom-JsonToHashtable

        Out-Clip
        Out-Voice

        Get-ScreenSaverTimeout
        Set-ScreenSaverTimeout
        Get-ScreenShot
        Set-WindowStyle

    .NOTES
        Company : CenturyLink Cloud
        Author  : Dmitry Gancho

    .LINK

    .SERVICE
        # F8 line below to generate module manifest and optionally copy contents of this module folder to destination folder.
        Publish-ThisModule -Destination "$env:USERPROFILE\Documents\GitHub\toolbox\PowerShell Modules"
#>


#region PS USER ENVIRONMENT

function Add-PSModulePath {
<#
.SYNOPSIS
    Add 'Path' to $env:PSModulePath if not there
.DESCRIPTION
    Author   : Dmitry Gancho
    Last edit: 11/20/2015
.PARAMETER Path
    Required.
.PARAMETER PassThru
    Optional.
.EXAMPLE
    Add-PsModulePath "$env:USERPROFILE\Documents\GitHub\toolbox\PowerShell Modules" -PassThru
.INPUTS
    [string]
.OUTPUTS
    [string[]]
.LINK
#>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory,Position=0,ValueFromPipeline)]
        [string]$Path,

        [switch]$PassThru
    )
    if ($env:PSModulePath -notmatch ($Path -replace '\\','\\')) {
        $env:PSModulePath += ";$Path"
    }
    if ($PassThru) {
        $env:PSModulePath -split ';'
    }
}


function Publish-ThisModule {
<#
.SYNOPSIS
    Generates module manifest for module, currently opened in PS ISE.
    Manifest is based on content of comment_based_help in the beginning of the module.
    If param Destination is specified, content of the folder is copied to Destination.
    Files matching '_*.*' are excluded.
.DESCRIPTION
    Author    : Dmitry Gancho, dmitry.gancho@ctl.io
    Last edit : 11/28/2015
    Version   : 1.1
.PARAMETER Destination
    Optional.
    PS Modules Root folder to which module will be copied
.EXAMPLE
    Publish-ThisModule
.EXAMPLE
    Publish-ThisModule -Destination "$env:USERPROFILE\Documents\GitHub\toolbox\PowerShell Modules"
.INPUTS
    [string]
.OUTPUTS
    [PSCustomObject[]]
.LINK
#>
    [CmdletBinding()]
    param (
        [string]$Destination
    )

    # function to get section or key value from comment_base_help header
    function get-section {
        param(
            [string]$name='.*',
            [string]$key
        )

        # get section as [string]
        $section = $modHeader -split "`n\s*\." | Select-String -Pattern "^\s*$name" -CaseSensitive
        # get section lines as [string[]] without '.<SECTION NAME>'
        $lines = $section -split "`n" -notlike $name
        # get single value if key is provided, otherwise return full section, exc. empty lines
        if ($key) {
            ($lines -like "*$key*" -split ':' | select -la 1) -replace "^ *| *$"
        } else {
            $lines -replace "^ *| *$"
        }
    }
    
    # save current file
    $psISE.CurrentFile.Save()
    # collect module data into variables
    $modFolderPath = Split-Path -Path $psISE.CurrentFile.FullPath -Parent
    $modFolderName = Split-Path -Path $modFolderPath -Leaf
    $modFileName   = Split-Path -Path $psISE.CurrentFile.FullPath -Leaf
    $modName,$null = $modFileName -split '\.'
    $modContent = (Get-Content -Path $psISE.CurrentFile.FullPath) -join "`n"
    $modHeader = $modContent.Substring(($modContent.IndexOf('<'+'#')),($modContent.IndexOf('#'+'>')+2))
    $manifestPath = $psISE.CurrentFile.FullPath -replace '\.psm1','.psd1'
    # generate info for manifest
    $param = @{
        Path               = $manifestPath
        RootModule         = $modName
        FunctionsToExport  = (get-section -name FUNCTIONS)
        Description        = ((get-section -name DESCRIPTION) -join "`n")
        Author             = (get-section -name NOTES -key Author)
        CompanyName        = (get-section -name NOTES -key Company)
        ModuleVersion      = (Get-Date -f M.dd)
        Copyright          = ("(c) $(Get-Date -f yyyy) $(get-section -name NOTES -key Company). All rights reserved.")
        RequiredModules    = (get-section -name 'REQUIRED MODULES')
        NestedModules      = (get-section -name 'NESTED MODULES')
        RequiredAssemblies = (get-section -name 'REQUIRED ASSEMBLIES')
        PrivateData        = @{KB = (get-section -name LINK)}
    }
    # generare manifest
    New-ModuleManifest @param
    # re-save to UTF-8 encoded file (for GutHub to recognize at text)
    [System.Io.File]::ReadAllText($manifestPath) | Out-File -FilePath $manifestPath -Encoding utf8 -Force
    # import module and report
    Import-Module -Name $modName -Global -Force -PassThru -ErrorAction SilentlyContinue | `
    Format-List Name,Description,Version,Author,CompanyName,Moduletype,ModuleBase,Path,@{
        Label = 'ExportedCommands'
        Expression = {$_.ExportedCommands.Keys -join "`n"}
    }
    # copy all files except '_*' and report
    if ($Destination) {
        if (-not (Test-Path -Path $Destination\$modFolderName)) {
            New-Item -Path $Destination\$modFolderName -ItemType Directory -Force
        }
        Copy-Item -Recurse -PassThru -Force -Path $modFolderPath\* -Exclude _* -Destination $Destination\$modFolderName\
    }
}


function Get-ModuleHelp {
<#
.SYNOPSIS
    Get help summary for a module and exported functions.
.DESCRIPTION
    Author    : Dmitry Gancho, dmitry.gancho@ctl.io
    Last edit : 11/28/2015
    Version   : 1.0
.PARAMETER Name
    Optional.
    Module Name
.PARAMETER Detailed
    Optional.
    Detailed help infomation for functions
.EXAMPLE
    Get-Module | Get-ModuleHelp
.EXAMPLE
    Get-ModuleHelp Utility,Credential -Detailed
.EXAMPLE
    Get-ModuleHelp -Name Microsoft.WSMan.Management
.INPUTS
    [string[]]
.OUTPUTS
    [PSCustomObject[]]
.LINK
#>
    [CmdletBinding()]
    param(
        [switch]$Detailed,
        [switch]$Online
    )

    DynamicParam {
        $dictionary = New-Object Management.Automation.RuntimeDefinedParameterDictionary
        
        #region parameter Name
        $paramName = 'Name'
        $attributes = New-Object Management.Automation.ParameterAttribute
        $attributes.Position = 0
        $attributes.Mandatory = $true
        $attributes.ValueFromPipeline = $true
        $attributes.ValueFromPipelineByPropertyName = $true
        $values = Get-Module | Select-Object -ExpandProperty Name
        $collection = New-Object Collections.ObjectModel.Collection[System.Attribute]
        $collection.Add($Attributes)
        $collection.Add((New-Object Management.Automation.ValidateSetAttribute($values)))
        $parameter = New-Object Management.Automation.RuntimeDefinedParameter($paramName,[string[]],$collection)
        $dictionary.Add($paramName,$parameter)
        #endregion

        $dictionary
    }

    process {
        foreach ($name in $dictionary.Name.Value) {

            Write-Verbose "Module Name : '$Name'"
            $module = Get-Module -Name $Name

            # open online KB
            if ($Online -and $module.PrivateData.ContainsKey('KB')) {
                Start-Process $module.PrivateData.KB -ErrorAction SilentlyContinue
            }

            # module infromation
            [pscustomobject][ordered]@{
                Name        = $module.Name
                Description = $module.Description
                Version     = $module.Version
                Author      = $module.Author
                Copyright   = $module.Copyright
                ModuleType  = $module.ModuleType
                ModuleBase  = $module.ModuleBase
            } | Format-List

            # functions list
            $functionNames = $module.ExportedCmdlets.Keys + $module.ExportedFunctions.Keys
            $functions = @{}
            foreach ($functionName in $functionNames) {
                $help = Get-Help -Name $functionName
                Write-Verbose "Function Name : '$functionName'"
                $syn = if ($help.Synopsis) {
                    ($help.Synopsis -replace "^\s.*`n") + "`n"
                } else {
                    $null
                }
                $desc = if ($Detailed) {
                    try {
                        ($help.Description.Text -join "`n") + "`n"
                    } catch {
                        $null
                    }
                } else {
                    $null
                }
                $description = if ($syn) {
                    if ($desc) {
                        $syn,$desc -join "`n"
                    } else {
                        $syn
                    }
                } else {
                    $desc
                }
                $functions.Add($functionName,$description)
            }
            $functions.GetEnumerator() | Sort-Object -Property Key | Format-Table -AutoSize -Wrap `
                @{
                    Label = 'Function Name'
                    Expression = {$_.Key + '  '}
                },
                @{
                    Label = ('Synopsis' + $(if ($Detailed) {' / Description'}))
                    Expression = {$_.Value}
                }
        }
    }
}


function Test-Module {
<#
    .SYNOPSIS
        Test for a module or a PS Snapin
        Imports into current session if available
    .DESCRIPTION
        Author    : Dmitry Gancho, dmitry.gancho@ctl.io
        Last edit : 11/18/2015
        Version   : 1.0
    .PARAMETER Name
        Module or PSSnapin name
    .EXAMPLE
        Test-Module -Name ControlAPI
    .EXAMPLE
        Test-Module -Name Posh-SSH
    .EXAMPLE
        Test-Module -Name VeeamPSSnapin
    .INPUTS
        [string]
    .OUTPUTS
        [bool]
    .LINK
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory,ValueFromPipeline)]
        [string]$Name
    )
    # verify module is installed, install if not
    if (-not (Get-Module -Name $Name) -and -not (Get-PSSnapin -Name $Name -ErrorAction Ignore)) {
        if (Get-Module -Name $Name -ListAvailable) {
            Import-Module -Name $Name
        } elseif (Get-PSSnapin -Name $Name -Registered -ErrorAction Ignore) {
            Add-PSSnapin -Name $Name
        } else {
            # special handling for Posh-SSH module
            if ($Name -eq 'Posh-SSH') {
                $uri = 'https://gist.github.com/darkoperator/6152630/raw/c67de4f7cd780ba367cccbc2593f38d18ce6df89/instposhsshdev'
                $webClient = New-Object -TypeName System.Net.WebClient
                $script = $webClient.DownloadString($uri)
                Invoke-Expression -Command $script | Out-Null
            }
        }
    }
    [bool]((Get-Module -Name $Name) -or (Get-PSSnapin -Name $Name -ErrorAction Ignore))
}


function Test-Elevated {
<#
.SYNOPSIS
    Test whether current PS session is elevated (aka 'as administrator')
.DESCRIPTION
    Author    : Dmitry Gancho, dmitry@ganco.com
    Last edit : 7/5/2014
    Version   : 1.0
.EXAMPLE
    Test-Elevated
.INPUTS
    none
.OUTPUTS
    [bool]
.LINK
#>
    [CmdletBinding()]param()
    ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}


function Enable-_WSManCredSSPClient {
<#
.SYNOPSIS
    Enable WSMan CredSSP client mode on local computer.
.DESCRIPTION
    Author    : Dmitry Gancho, dmitry@ganco.com
    Last edit : 3/23/2015
    Version   : 1.0
.EXAMPLE
    Enable-WSManCredSSPClient
.INPUTS
    none
.OUTPUTS
    [string]
.LINK
    http://blogs.msdn.com/b/wmi/archive/2009/07/24/powershell-remoting-between-two-workgroup-machines.aspx
#>
    [CmdletBinding()] param()
    Write-Host "This function requires additional testing. It will now exit" -ForegroundColor Red
    break
    $script = {
        function add-regvalue {
            param (
                [Parameter(Mandatory)]
                [string]$path,
                [string]$name,
                [string]$value
            )
            # check reg key path
            if (-not (Test-Path $path)) {
                New-Item -Path (Split-Path $path -Parent) -Name (Split-Path $path -Leaf) | Out-Null
            }
            if ($name) {
                # check reg key property
                if (-not (Get-ItemProperty -Path $path -Name $name -ErrorAction Ignore)) {
                    New-ItemProperty -Path $path -Name $name -Value $value | Out-Null
                }
                # check reg key property value
                if ((Get-ItemPropertyValue -Path $path -Name $name) -ne $value) {
                    Set-ItemProperty -Path $path -Name $name -Value $value
                }
            }
        }

        Enable-WSManCredSSP -DelegateComputer * -Role Client -Force | Out-Null
    
        $root = 'HKLM:\Software\Policies\Microsoft\Windows\CredentialsDelegation'
        $props = @{
            'AllowFreshCredentials' = 1
            'ConcatenateDefaults_AllowFresh' = 1
            'AllowFreshCredentialsWhenNTLMOnly' = 1
            'ConcatenateDefaults_AllowFreshNTLMOnly' = 1
            'AllowFreshCredentials\1' = 'wsman/*'
            'AllowFreshCredentialsWhenNTLMOnly\1' = 'wsman/*'
        }

        $props.Keys | ForEach-Object {
            $path = Join-Path -Path $root -ChildPath (Split-Path -Path $_ -Parent)
            $name = Split-Path -Path $_ -Leaf
            $value = $props.$_
            add-regvalue -path $path -name $name -value $value
        }
        Get-WSManCredSSP
    }
    Invoke-ScriptBlock -ScriptBlock $script -Elevate
}


function Set-PSWindowTitle {
<#
.SYNOPSIS
    Set PS window title to following format:
    <username> on <computername> ~ <PSHostName> <PSHostVersion> ~ <LongDate>
.DESCRIPTION
    Author   : Dmitry Gancho
    Last edit: 3/20/2015
.EXAMPLE
    Set-PSWindowTitle
.INPUTS
    none
.OUTPUTS
    none
.LINK
#>
    $elevated = if (([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {' (elevated)'}
    $title = @(
        "$($env:USERNAME.ToLower())$elevated on $($env:COMPUTERNAME.ToUpper())",
        "$($Host.Name) $($Host.Version)",
        "$((Get-Date).ToLongDateString())"
    )
    $Host.UI.RawUI.set_WindowTitle($title -join ' ~ ')
}

#endregion


#region NETWORK TOOLS

function Test-IPv4 {
<#
    .SYNOPSIS
        Tests if parameter matches IPv4 pattern.
    .DESCRIPTION
        Author    : Dmitry Gancho, dmitry.gancho@ctl.io
        Last edit : 11/18/2015
        Version   : 1.0
    .PARAMETER Ip
        IP to test
    .EXAMPLE
        Test-IPv4 -Ip 192.168.0.1
    .EXAMPLE
        Test-IPv4 -Ip 'this is not an IP address'
    .INPUTS
        [string]
    .OUTPUTS
        [bool]
    .LINK
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory,Position=0,ValueFromPipeline)]
        [string]$ip
    )
    $ip -match "\b(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}\b"
}


function Test-TCPPort {
<#
    .SYNOPSIS
        Tests for device response on a TCP Port.
    .DESCRIPTION
        Author    : Dmitry Gancho, dmitry.gancho@ctl.io
        Last edit : 11/18/2015
        Version   : 1.0
    .PARAMETER Device
        Required.
        Device name or IP address.
    .PARAMETER Device
        Required.
        TCP Port.
    .EXAMPLE
        Test-TCPPort -Device WA1-SRX-CORE -TCPPort 22
    .INPUTS
        [string]
        [int32]
    .OUTPUTS
        [bool]
    .LINK
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory,Position=0,ValueFromPipeline)]
        [Alias('name','target')]
        [string]$Device,

        [Parameter(Mandatory,Position=1)]
        [Alias('port')]
        [int32]$TCPPort
    )
    $tcpClient = New-Object System.Net.Sockets.TcpClient
    [void]$tcpClient.ConnectAsync($Device,$TCPPort)

    # wait
    Start-Sleep -Milliseconds 500

    # check and report
    $output = $tcpClient.Connected
    $tcpClient.Close()
    $tcpClient.Dispose()
    $output
}


function Test-Target {
<#
    .SYNOPSIS
        Performs multiply connectivity tests to a target.
    .DESCRIPTION
        Author    : Dmitry Gancho, dmitry.gancho@ctl.io
        Last edit : 11/18/2015
        Version   : 1.0
    .PARAMETER Target
        Optional.
        Target Name or IP address.
        If not provided, defaults to localhost.
    .EXAMPLE
        Test-Target
        
        Time Stamp         : 11/21/2015 5:33 PM
        Target             : DG
        DNS HostName       : DG
        DNS IP AddressList : 10.1.1.15
                             192.168.1.3
        Ping 10.1.1.15     : 0,0,0,0 ms
        TCP Ports          : 135,139,445,3389,5985
    .EXAMPLE
        Test-Target microsoft.com
        
        Time Stamp         : 11/21/2015 5:34 PM
        Target             : microsoft.com
        DNS HostName       : microsoft.com
        DNS IP AddressList : 191.239.213.197
                             104.40.211.35
                             104.43.195.251
                             23.100.122.175
                             23.96.52.53
        Ping               : to,to,to,to
        TCP Ports          : 80,443
    .INPUTS
        [string]
    .OUTPUTS
        [PSCustomObject]
    .LINK
#>
    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline)]
        [String]$Target = $env:COMPUTERNAME
    ) #param


    #region FUNCTIONS


    function invokeAsync {
        param(
            [scriptblock]$scriptblock,
            [object]$param
        ) #param
        # create and start StopWatch
        $stopwatch = New-Object -TypeName System.Diagnostics.Stopwatch
        $stopwatch.Start()
        # create a runspace
	    $runspace = [RunspaceFactory]::CreateRunspace()
	    $runspace.ThreadOptions = 'ReuseThread'
	    $runspace.ApartmentState = 'STA'
        $runspace.Open()
        # set variables
        $runspace.SessionStateProxy.SetVariable('param',$param)
        $runspace.SessionStateProxy.SetVariable('sw',$stopwatch)
        # create a pipeline
        $pipeline = $runspace.CreatePipeline()
        # add ScripBlock
        $pipeline.Commands.AddScript($scriptblock)
        # begin execution
        $pipeline.InvokeAsync()
        # return
        return @{
            pl = $pipeline
            sw = $stopwatch
        } #@
    } #function


    function stopAsync {
        param(
            [System.Collections.Hashtable]$hash,
            [System.Int32]$wait = 1
        ) #param
        # create timeout
        $to = [System.TimeSpan]::FromSeconds($wait)
        # wait
        while (($hash.sw.Elapsed -lt $to) -and ($hash.pl.PipelineStateInfo.State -ne 'Completed')) {
            Start-Sleep -Milliseconds 100
        } #while
        # stop pipeline
        $hash.pl.StopAsync()
        # get state
        $state = [string]$hash.pl.PipelineStateInfo.State
        # read result
        $result = if ($state -eq 'Completed') {
            $hash.pl.Output.ReadToEnd()
            [void]$hash.pl.Runspace.CloseAsync()
    	    [void]$hash.pl.Dispose()
        } else {
            $null
        } #if-else
        # stop stopwatch
        if ($hash.sw.IsRunning) {
            $hash.sw.Stop()
        } #if
        # return result, runtime (in seconds) and state
        if (!$result) {$result = 'timeout'}
        return @{
            res = $result
            rt = $hash.sw.ElapsedMilliseconds / 1000
            st = $state
        } #@
    } #function


    $dnsScript = {
        $ErrorActionPreference = 'Stop'
        [string]$name = $param
        $output = try {
            $res = [net.dns]::Resolve($name)
            @{
                HostName    = [string]$res.HostName
                Aliases     = [array]$res.Aliases
                AddressList = [array]$res.AddressList.IPAddressToString
            } #@
        } catch {
            $Error[0].Exception.Message
        } #try-catch
        $sw.Stop()
        return $output
    } #dnsScript


    $pngScript = {
        # tests icmp ping response on target
        # input [string] name or fqdn or ipaddress
        # output [System.Net.NetworkInformation.PingReply[]] or [string[]]
        [string]$target = $param
        # set output variable to collect results
        $output = 1..4 | ForEach-Object {
            try {
                (New-Object -TypeName System.Net.NetworkInformation.Ping).Send($target,1000) # timeout in ms
            } catch {
                $_.Exception.Message
            } #try-catch
            Start-Sleep -Milliseconds 500
        } #%
        $sw.Stop()
        return $output
    } #pngScript


    $tcpScript = {
        # test TCP ports access on target
        # returns [hashtable] of port # : $true or $false
        [string]$target = $param
        $wait = 2 # in seconds

        # define list of TCP Ports to test
        $tcpPorts = @()
        # http://en.wikipedia.org/wiki/List_of_TCP_and_UDP_port_numbers
        $tcpPorts += 21   # FTP
        $tcpPorts += 22   # SSH: secure logins, file transfers (scp, sftp) and port forwarding
        $tcpPorts += 23   # TELNET
        $tcpPorts += 25   # SMTP
        $tcpPorts += 53   # DNS Server
        $tcpPorts += 80   # HTTP
        $tcpPorts += 88   # Kerberos—authentication system
        $tcpPorts += 101  # NIC host name
        $tcpPorts += 135  # DCE/RPC Locator service
        $tcpPorts += 137  # NetBIOS Name Service
        $tcpPorts += 139  # NetBIOS Datagram Service
        $tcpPorts += 143  # SMTPs
        $tcpPorts += 156  # SQL Service
        $tcpPorts += 161  # SSH: SNMP Service
        $tcpPorts += 162  # SSH: SNMP Service
        $tcpPorts += 199  # SSH: SNMP Service
        $tcpPorts += 389  # Lightweight Directory Access Protocol (LDAP)
        $tcpPorts += 443  # HTTPS
        $tcpPorts += 445  # SMB over IP / Microsoft DS
        $tcpPorts += 514  # Shell—used to execute non-interactive commands on a remote system (Remote Shell, rsh, remsh)
        $tcpPorts += 546  # DHCP Client
        $tcpPorts += 547  # DHCP Server
        $tcpPorts += 636  # LDAPS Servce
        $tcpPorts += 992  # TELNET protocol over TLS/SSL
        $tcpPorts += 1433 # SQL Default Service
        $tcpPorts += 1434 # SQL Browser Service (to named instances)
        $tcpPorts += 1688 # KMS Service
        $tcpPorts += 1723 # MS VPN (PPTP)
        $tcpPorts += 2179 # VMConnect to Hyper-V hosts (RDP protocol)
        $tcpPorts += 2383 # SQL Server Analysis Services Port (SQL 2005 / 2008)
        $tcpPorts += 3389 # Terminal Server (RDP protocol)
        $tcpPorts += 3516 # Smartcard Port
        $tcpPorts += 5500 # VNC remote desktop protocol — for incoming listening viewer
        $tcpPorts += 5723 # SCOM Channel
        $tcpPorts += 5985 # Windows PowerShell Default psSession Port
        $tcpPorts += 5986 # Windows PowerShell Default psSession Port

        # create hash of TCP Clients
        $tcpClients = @{}
        $tcpPorts | ForEach-Object {
            $tcpClient = New-Object System.Net.Sockets.TcpClient
            [void]$tcpClient.ConnectAsync($target,$_)
            $tcpClients.$_ = $tcpClient
        } #%

        # wait
        sleep $wait

        # create hash of results
        $output = @{}
        $tcpClients.Keys | ForEach-Object {
            $output.$_ = $tcpClients.$_.Connected
            $tcpClients.$_.Close()
            $tcpClients.$_.Dispose()
        } #% 

        # exit
        $sw.Stop()
        $output
    } #tcpScript


    #endregion


    #region PROCESS

    # define hash table
    $hash = @{}

    # DNS job to get IP addresses
    $dnsInstance = invokeAsync $dnsScript $Target
    # collect job results
    $hash.Dns = stopAsync $dnsInstance -wait 5

    # other jobs
    $ip = if ($hash.Dns.res -is [hashtable] -and $hash.Dns.res.AddressList.count -ge 1) {
        ([array]$hash.Dns.res.AddressList)[0]
    } else {$null}
    if (-not $ip) {$ip = $Target}
                    
    # we have at least 1 IP address
    $instances = @{}
    $instances.pngInstance = invokeAsync $pngScript $ip # ping test
    $instances.tcpInstance = invokeAsync $tcpScript $ip # TCP Ports test
    # collect jobs results into hashtable
    $to = 30
    $instances.Keys | ForEach-Object {
        $hash.($_ -replace 'Instance') = stopAsync $instances.$_ -wait $to
    } #%


#    return $hash

    #endregion


    #region PUBLISH


    # consolidate

    #region PING test/data
    $hash.PNG.Result = $hash.png.res.Status -contains 'Success'
    $hash.PNG.IP     = $hash.png.res | ForEach-Object {if ($_.Address) {$_.Address.IPAddressToString}} | select -Unique
    $hash.PNG.RTT    = ($hash.png.res | ForEach-Object {if ($_.Status -eq 'Success') {$_.RoundtripTime} else {'to'}}) -join ','
    if ($hash.PNG.RTT -match '\d') {$hash.PNG.RTT += ' ms'}
    #endregion


    #region TCP Ports
    $hash.TcpOpened = @()
    $hash.TcpClosed = @()
    foreach ($port in $hash.TCP.Res.Keys) {
        switch ($hash.TCP.Res.Item($port)) {
            $True   {$hash.TcpOpened += $port}
            $false  {$hash.TcpClosed += $port}
            default {}
        } #switch
    } #foreach
    #endregion


    # DETAILED report
    $output = [ordered]@{}
    $output.'Time Stamp' = Get-Date -f g
    $output.'Target' = $Target
    $output.'DNS HostName' = if ($hash.DNS.res -is [hashtable]) {$hash.DNS.res.HostName}
    $output.'DNS IP AddressList' = if ($hash.DNS.res -is [hashtable]) {$hash.DNS.res.AddressList -join "`n"}
    $output."Ping $($hash.Png.IP)" = $hash.Png.RTT
    $output.'TCP Ports' = ($hash.TcpOpened | sort) -join ','
    
    return [pscustomobject]$output
    #endregion

}

#endregion


#region CODE PROCESSING
 
function Invoke-ScriptBlock {
<#
.SYNOPSIS
    Executes script block under same/different credentials
    and/or elevated instance of PowerShell.
    Returning object is serialized.
.DESCRIPTION
    Author    : Dmitry Gancho, dmitry@ganco.com
    Last edit : 3/16/2015
    Version   : 1.0
.PARAMETER  Scriptblock
    Required.
    Scriptblock to invoke
.PARAMETER  ArgumentList
    Optional.
    Arguments for the scriptblock.
.PARAMETER  Credential
    Optional.
    Credential.
.PARAMETER  Elevated
    Optional.
    Run elevated (aka 'as administrator')
.PARAMETER  Profile
    Load PS user profile
.EXAMPLE
    $scr = {
        "Parameter : $($args[0])"
        "IsAdmin   : $(([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))"
    } #scr
    Invoke-ScriptBlock -ScriptBlock $scr -ArgumentList TEST -Elevate
.INPUTS
    [scriptblock]
    [array]
    [PSCredential]
.OUTPUTS
    [object]
.LINK
#>
    [CmdletBinding()]
    param(
        [Parameter(Position=0)]
        [alias('script')]
        [scriptblock]$ScriptBlock,

        [Parameter(Position=1)]
        [alias('args')]
        [array]$ArgumentList,

        [Parameter(Position=2)]
        [alias('cred')]
        [pscredential]$Credential,

        [Parameter()]
        [alias('e')]
        [switch]$Elevate = $false,

        [Parameter()]
        [alias('p')]
        [switch]$Profile = $false
    ) #param

    $ErrorActionPreference = 'Stop'
    $scenarios = @{
        ASS = 'User - same; Elevation - Standard > Standard'
        ASE = 'User - same; Elevation - Standard > Elevated'
        AES = 'User - same; Elevation - Elevated > Standard'
        AEE = 'User - same; Elevation - Elevated > Elevated'
        BSS = 'User - other; Elevation - Standard > Standard'
        BSE = 'User - other; Elevation - Standard > Elevated'
        BES = 'User - other; Elevation - Elevated > Standard'
        BEE = 'User - other; Elevation - Elevated > Elevated'
    } #@

    # define scenario
    if (!$Credential -or ($Credential.UserName -eq $env:USERNAME)) {
        $scenario = 'A'
    } else {
        $scenario = 'B'
    }#if

    if (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        $scenario += 'S'
    } else {
        $scenario += 'E'
    }#if

    if (!$Elevate) {
        $scenario += 'S'
    } else {
        $scenario += 'E'
    }#if
    Write-Verbose "Scenario $scenario : $($scenarios.get_Item($scenario))"


    # script block for Standard > Elevated (xSE,BEE) scenarios
    $elevScrBlock = {

        param(
            [string]$scrStr=$null,
            [array]$argList=$null,
            [bool]$profile=$false
        ) #param

        $ErrorActionPreference = 'Stop'
        Set-StrictMode -Version Latest

        $inputFile  = [IO.Path]::GetTempFileName()
        $outputFile = [IO.Path]::GetTempFileName()	
        $argList | Export-CliXml -Depth 1 $inputFile

        $commandString = "
            Set-Location '$($pwd.Path)'
            [array]`$params = Import-CliXml '$inputFile'
            `$output = &{$scrStr} @params *>&1
            Export-CliXml -Depth 1 -In `$output '$outputFile'
        " #"
        $commandBytes = [System.Text.Encoding]::Unicode.GetBytes($commandString)
        $encodedCommand = [Convert]::ToBase64String($commandBytes)
        $commandLine = if (!$profile) {'-NoProfile '} else {$null}
        $commandLine += "-EncodedCommand $encodedCommand"

        $params = @{
            FilePath     = (Get-Command powershell).Definition
            ArgumentList = $commandLine
            WindowStyle  = 'Hidden'
            Wait         = $true
            Verb         = 'RunAs'
        } #@
        Start-Process @params

        Import-CliXml $outputFile
        Remove-Item $outputFile
        Remove-Item $inputFile

    } #$elevScrBlock


    $res = switch ($scenario) {
    

        # ASS: User - same; Elevation - Standard > Standard
        ASS {
            #Invoke-Command -ScriptBlock $ScriptBlock -ArgumentList $ArgumentList
            &$ScriptBlock @ArgumentList
        } #ASS


        # ASE: User - same; Elevation - Standard > Elevated
        ASE {
            #Invoke-Command -ScriptBlock $elevScrBlock -ArgumentList $ScriptBlock,$ArgumentList,$Profile
            $arguments = $ScriptBlock,$ArgumentList,$Profile
            &$elevScrBlock @arguments
        } #ASE


        # AES: User - same; Elevation - Elevated > Standard
        AES {
            $jobParams = @{
                ScriptBlock  = $ScriptBlock
                ArgumentList = $ArgumentList
                Credential   = Import-Credential $env:USERNAME
                InitializationScript = if ($Profile) {{
                    "$PSHOME\PROFILE.ps1","$env:USERPROFILE\Documents\WindowsPowerShell\PROFILE.ps1" | ForEach-Object {
                    if (Test-Path $_) {&$_}}}} else {$null}
            } #@
            $job = Start-Job @jobParams
            $job | Receive-Job -Wait -Force
            $job | Remove-Job -Force
        } #AES


        # AEE: User - same; Elevation - Elevated > Elevated
        AEE {
            #Invoke-Command -ScriptBlock $ScriptBlock -ArgumentList $ArgumentList
            &$ScriptBlock @ArgumentList
        } #AEE


        # BSS: User - other; Elevation - Standard > Standard
        BSS {
            $jobParams = @{
                ScriptBlock  = $ScriptBlock
                ArgumentList = $ArgumentList
                Credential   = $Credential
                InitializationScript = if ($Profile) {{
                    "$PSHOME\PROFILE.ps1","$env:USERPROFILE\Documents\WindowsPowerShell\PROFILE.ps1" | ForEach-Object {
                    if (Test-Path $_) {&$_}}}} else {$null}
            } #@
            $job = Start-Job @jobParams
            $job | Receive-Job -Wait -Force
            $job | Remove-Job -Force
        } #BSS


        # BSE: User - other; Elevation - Standard > Elevated
        BSE {
            $jobParams = @{
                ScriptBlock  = $elevScrBlock
                ArgumentList = $ScriptBlock,$ArgumentList,$Profile
                Credential   = $Credential
                InitializationScript = {$null}
            } #@
            $job = Start-Job @jobParams
            $job | Receive-Job -Wait -Force
            $job | Remove-Job -Force
        } #BSE


        # BES: User - other; Elevation - Elevated > Standard
        # jobA - under current user to deelevate
        # jobB - inside jobA under other user (deelevated)
        BES {
            $jobParams = @{
                ScriptBlock  = {
                    $jobParams = @{
                        ScriptBlock  = [scriptblock]::Create($args[0])
                        ArgumentList = $args[1]
                        Credential   = $args[2]
                        InitializationScript = if ($args[3]) {{
                            "$PSHOME\PROFILE.ps1","$env:USERPROFILE\Documents\WindowsPowerShell\PROFILE.ps1" | ForEach-Object {
                            if (Test-Path $_) {&$_}}}} else {$null}
                    } #@
                    $job = Start-Job @jobParams
                    $job | Receive-Job -Wait -Force
                    $job | Remove-Job -Force
                }
                ArgumentList = $ScriptBlock,$ArgumentList,$Credential,$Profile
                Credential   = Import-Credential $env:USERNAME
            } #@
            $job = Start-Job @jobParams
            $job | Receive-Job -Wait -Force
            $job | Remove-Job -Force
        } #BES


        # BEE: User - other; Elevation - Elevated > Elevated
        BEE {
            $jobParams = @{
                ScriptBlock  = $elevScrBlock
                ArgumentList = $ScriptBlock,$ArgumentList,$Profile
                Credential   = $Credential
                InitializationScript = {$null}
            } #@
            $job = Start-Job @jobParams
            $job | Receive-Job -Wait -Force
            $job | Remove-Job -Force
        } #BEE

        default {
            "Unrecognized scenario : $scenario"
        } #default

    } #switch
    
    #just in case
    Set-PSWindowTitle | Out-Null

    # return results type [array]
    [array]$res

}


function Invoke-Async {
<#
.SYNOPSIS
    Invokes script block asyncronously and returns [hashtable] of:
    .pl as [System.Management.Automation.Runspaces.Pipeline]
    .sw as [System.Diagnostics.Stopwatch]
.DESCRIPTION
    Author    : Dmitry Gancho, dmitry@ganco.com
    Last edit : 4/6/2015
    Version   : 1.0
.PARAMETER  Scriptblock
    Scriptblock to invoke.
.PARAMETER  Param
    Parameters for the scriptblock
.EXAMPLE
    $scr = {
        $text1 = $param[0]
        $text2 = $param[1]
        return "$text1 $text2"
    }
    Invoke-Async $scr -param 'Hello','World'
.INPUTS
    [scriptblock]
    [object]
.OUTPUTS
    [hashtable]
.LINK
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory,Position=0,ValueFromPipeline)]
        [scriptblock]$Scriptblock,

        [Parameter()]
        [object]$Param
    ) #param
    # create and start StopWatch
    $stopwatch = New-Object -TypeName System.Diagnostics.Stopwatch
    $stopwatch.Start()
    # create a runspace
	$runspace = [RunspaceFactory]::CreateRunspace()
	$runspace.ThreadOptions = 'ReuseThread'
	$runspace.ApartmentState = 'STA'
    $runspace.Open()
    # set variables
    $runspace.SessionStateProxy.SetVariable('param',$param)
    $runspace.SessionStateProxy.SetVariable('sw',$stopwatch)
    # create a pipeline
    $pipeline = $runspace.CreatePipeline()
    # add ScripBlock
    $pipeline.Commands.AddScript($scriptblock)
    # begin execution
    $pipeline.InvokeAsync()
    # return
    return @{
        pl = $pipeline
        sw = $stopwatch
    } #@
}


function Stop-Async {
<#
.SYNOPSIS
    Stops execution of a runspace and returns all results already available
.DESCRIPTION
    Author    : Dmitry Gancho, dmitry@ganco.com
    Last edit : 1/6/2015
    Version   : 1.0
.PARAMETER  hash
    [hashtable] of:
    .pl as [System.Management.Automation.Runspaces.Pipeline]
    .sw as [System.Diagnostics.Stopwatch]
.PARAMETER  wait
    [int32] wait time in seconds
.EXAMPLE
    Stop-Async -hash $hash -wait 5
.INPUTS
    [hashtable]
    [int32]
.OUTPUTS
    [hashtable]
.LINK
#>
    [CmdletBinding()]
    param(
        [System.Collections.Hashtable]$Hash,
        [System.Int32]$Wait = 1
    ) #param
    # create timeout
    $to = [System.TimeSpan]::FromSeconds($wait)
    # wait
    while (($hash.sw.Elapsed -lt $to) -and ($hash.pl.PipelineStateInfo.State -ne 'Completed')) {
        Start-Sleep -Milliseconds 100
    } #while
    # stop pipeline
    $hash.pl.StopAsync()
    # get state
    $state = [string]$hash.pl.PipelineStateInfo.State
    # read result
    $result = if ($state -eq 'Completed') {
        $hash.pl.Output.ReadToEnd()
        [void]$hash.pl.Runspace.CloseAsync()
    	[void]$hash.pl.Dispose()
    } else {
        $null
    } #if-else
    # stop stopwatch
    if ($hash.sw.IsRunning) {
        $hash.sw.Stop()
    } #if
    # return result, runtime (in seconds) and state
    if (!$result) {$result = 'timeout'}
    return @{
        res = $result
        rt = $hash.sw.ElapsedMilliseconds / 1000
        st = $state
    } #@
}

#endregion


#region DATA CONVERSION

function ConvertTo-Regex {
<#
.SYNOPSIS
    Converts string to regex-compatible by prefixing special regex charachters with escape charachter '\'
.DESCRIPTION
    Author    : Dmitry Gancho, dmitry@ganco.com
    Last edit : 11/21/2015
    Version   : 1.0
.EXAMPLE
    ConvertTo-Regex 192.168.1.1
    192\.168\.1\.1
.PARAMETER String
    Required.
    String to convert
.INPUTS
    [string]
.OUTPUTS
    [string]
.LINK
#>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory,ValueFromPipeline)]
        [string]$String
    )
    $chars = '^','$','[',']','{','}','(',')','<','>','\','|','/','.','*','+','?'
    ($string.GetEnumerator() | ForEach-Object {if ($_ -in $chars) {"\$_"} else {$_}}) -join $null
}


function ConvertFrom-JsonToHashtable {
<#
.SYNOPSIS
    Converts Json [string] to [hashtable]
.DESCRIPTION
    Author   : Dmitry Gancho
    Last edit: 11/20/2015
.PARAMETER JsonString
    Required.
    Json formatted string
.EXAMPLE
    ConvertFrom-JsonToHashtable '{"Item Name":"Item Value"}'

    Name                           Value                                           
    ----                           -----                                           
    Item Name                      Item Value                                      
.INPUTS
    [string]
.OUTPUTS
    [hashtable]
.LINK
#>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory,ValueFromPipeline)]
        [string]$JsonString
    )
    $hash = [ordered]@{}
    ($JsonString | ConvertFrom-Json).psobject.properties | ForEach-Object {$hash.($_.Name) = $_.Value}
    $hash
}

#endregion


#region DATA REDIRECTION

function Out-Clip {
<#
.SYNOPSIS
    Takes object from pipeline, converts to string and copies into clipboard
    The object is passed further down the pipeline intact
.DESCRIPTION
    Author    : Dmitry Gancho, dmitry@ganco.com
    Last edit : 17/1/2015
    Version   : 1.0
.EXAMPLE
    Get-Process notepad | Out-Clip -Passthru
.INPUTS
    [object] from pipeline.
.OUTPUTS
    [object]
.LINK
#>
    [switch]$PassThru = $false
    if ($PassThru) {
        $input | Tee-Object -Variable obj
    } else {
        $obj = $input
    } #if-else
    # remove empty lines
    #$str = ($obj | Out-String) -replace "\n\W"
    $str = $obj | Out-String
    if ($str -ne [string]$null) {
        Add-Type -AssemblyName System.Windows.Forms
        [Windows.Forms.Clipboard]::Clear()
        [Windows.Forms.Clipboard]::SetText($str)
    } #if
}


function Out-Voice {
<#
.SYNOPSIS
    Outputs string to voice using background job.
    Does not block execution.
.DESCRIPTION
    Author    : Dmitry Gancho, dmitry@ganco.com
    Last edit : 18/4/2015
    Version   : 1.0
.PARAMETER Text
    Text to speak
.PARAMETER Passthru
.EXAMPLE
    Out-Voice -Text 'Hello world'
.EXAMPLE
    'Hello world' | Out-Voice -Passthru
.INPUTS
    [string]
.OUTPUTS
    [string]
.LINK
#>
    [Cmdletbinding()]
    param(
        [Parameter(ValueFromPipeline,ValueFromPipelineByPropertyName)]
        [string]$Text,
        [switch]$PassThru
    ) #param
    
    $ErrorActionPreference = 'Stop'
    trap {[string]$_; continue}
    if ($PassThru) {$Text}

    $jobsName = 'Out-Voice'

    $params = @{
        Name = $jobsName
        ArgumentList = $Text
        ScriptBlock = {
            Add-Type -AssemblyName System.Speech
            $speak = New-Object System.Speech.Synthesis.SpeechSynthesizer
            $zira = $speak.GetInstalledVoices().VoiceInfo | Where-Object Name -Like '*Zira*' | select -expand Name
            if ($zira) {$speak.SelectVoice($zira)} #if
            $speak.Speak($args[0])
            #[void](New-Object -ComObject SAPI.SpVoice).Speak($args[0])
        } #ScriptBlock
    } #@
    $job = Start-Job @params

    $params = @{
        InputObject = $job
        EventName = 'StateChanged'
        SourceIdentifier = $jobsName
        Action = {
            Unregister-Event -SourceIdentifier $event.SourceIdentifier -Force
            # two jobs have to be removed: -Name $event.Sender.Name and -Name $event.SourceIdentifier
            # in this case they both have same names, so one line is enough
            Remove-Job -Name $event.SourceIdentifier -Force
        } #Action
    } #@
    Register-ObjectEvent @params -ErrorAction Ignore | Out-Null

}

#endregion


#region GUI

function Get-ScreenSaverTimeout {
<#
.SYNOPSIS
    Get screensaver timeout in minutes.
.DESCRIPTION
.EXAMPLE
    Get-ScreenSaverTimeout
.INPUTS
    none
.OUTPUTS
    [int32]
.LINK
    https://powershellreflections.wordpress.com/2011/08/02/control-your-screensaver-with-powershell/
#>
    $signature = @"
        [DllImport("user32.dll")]
        public static extern bool SystemParametersInfo(int uAction, int uParam, ref int lpvParam, int flags);
"@
    try {
        $systemParamInfo = Add-Type -MemberDefinition $signature -Name ScreenSaver -PassThru -ErrorAction Stop
    } catch {
    } finally {
        [Int32]$seconds = 0
        [void]$systemParamInfo::SystemParametersInfo(14,0,[REF]$seconds,0)
        $($seconds/60)
    }
}

 
function Set-ScreenSaverTimeout {
<#
.SYNOPSIS
    Set screensaver timeout.
.DESCRIPTION
.PARAMETER  Minutes
    [int32]
.EXAMPLE
    Set-ScreenSaverTimeout -Minutes 99
.INPUTS
    [int32]
.OUTPUTS
    none
.LINK
    https://powershellreflections.wordpress.com/2011/08/02/control-your-screensaver-with-powershell/
#>
  param ([Int32]$Minutes)
    $signature = @"
        [DllImport("user32.dll")]
        public static extern bool SystemParametersInfo(int uAction, int uParam, ref int lpvParam, int flags);
"@
    try {
        $systemParamInfo = Add-Type -MemberDefinition $signature -Name ScreenSaver -passThru -ErrorAction Stop
    } catch {
    } finally {
        $seconds = $Minutes * 60
        [Int32]$nullVar = 0
        $systemParamInfo::SystemParametersInfo(15,$seconds,[REF]$nullVar,2)
    }
}


function Get-ScreenShot {
<#
.SYNOPSIS
    Takes a screenshot and saves it to a file.
.DESCRIPTION
    The Get-Screenshot Function uses the System.Drawing .NET assembly to
    take a screenshot, and then saves it to a file.
.PARAMETER Path
    The path where the file will be stored. If a trailing backslash is used
    the operation will fail.
.PARAMETER Format
    One of 'jpeg','bmp','gif','png'
.LINK
    http://joeit.wordpress.com/
#>
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory,Position=0)]
        [String]$Path,
        [ValidateSet('jpeg','bmp','gif','png')]
        [Alias('f')]
        [string]$Format='jpeg'
    )#End Param

    $asm0 = [System.Reflection.Assembly]::LoadWithPartialName("System.Drawing")
    Write-Verbose "Assembly loaded: $asm0"
    $asm1 = [System.Reflection.Assembly]::LoadWithPartialName("System.Windows.Forms")
    Write-Verbose "Assembly Loaded: $asm1"
    $screen = [System.Windows.Forms.Screen]::PrimaryScreen.Bounds

    $Bitmap = New-Object System.Drawing.Bitmap $screen.width,$screen.height
    $Size = New-Object System.Drawing.Size $screen.width,$screen.height
    $FromImage = [System.Drawing.Graphics]::FromImage($Bitmap)
    $FromImage.copyfromscreen(0,0,0,0,$Size,([System.Drawing.CopyPixelOperation]::SourceCopy))
    $Timestamp = Get-Date -uformat "%Y_%m_%d_@_%H%M_%S"

    if ([IO.Directory]::Exists($Path)) {
        Write-Verbose "Directory $Path already exists."
    } else {
        [IO.Directory]::CreateDirectory($Path) | Out-Null
        Write-Verbose "Folder $Path does not exist, creating..."
    }

    $FileName = "$Timestamp`_screenshot.$Format"
    $Target = Join-Path -Path $Path -ChildPath $FileName
    switch ($Format) {
        jpeg {$Bitmap.Save($Target,([System.Drawing.Imaging.ImageFormat]::Jpeg))}
        bmp  {$Bitmap.Save($Target,([System.Drawing.Imaging.ImageFormat]::Bmp ))}
        gif  {$Bitmap.Save($Target,([System.Drawing.Imaging.ImageFormat]::Gif ))}
        png  {$Bitmap.Save($Target,([System.Drawing.Imaging.ImageFormat]::Png ))}
        default {}
    }
    Write-Verbose "File saved to: '$target'"
}


function Set-WindowStyle {
<#
.SYNOPSIS
    Windows operations for a given process.
.DESCRIPTION
    Windows operations for a given process.
.PARAMETER  ProcessId
    [int32]
.PARAMETER  Style
    [string] windows stype
.EXAMPLE
    Get-Process Outlook | select -exp id | Set-WindowsStyle -Style MINIMIZE
.INPUTS
    [int32]
    [string]
.OUTPUTS
    none
.LINK
    https://gist.github.com/jakeballard/11240204
#>
    param (
        [Parameter(Mandatory,Position=0,ValueFromPipeline)]
        [int32]$ProcessId,

        [Parameter()]
        [ValidateSet('FORCEMINIMIZE','HIDE','MAXIMIZE','MINIMIZE','RESTORE', 
                     'SHOW','SHOWDEFAULT','SHOWMAXIMIZED','SHOWMINIMIZED', 
                     'SHOWMINNOACTIVE','SHOWNA','SHOWNOACTIVATE','SHOWNORMAL')]
        [string]$Style='SHOW'
    )

    $WindowStates = @{
        'FORCEMINIMIZE'   = 11
        'HIDE'            = 0
        'MAXIMIZE'        = 3
        'MINIMIZE'        = 6
        'RESTORE'         = 9
        'SHOW'            = 5
        'SHOWDEFAULT'     = 10
        'SHOWMAXIMIZED'   = 3
        'SHOWMINIMIZED'   = 2
        'SHOWMINNOACTIVE' = 7
        'SHOWNA'          = 8
        'SHOWNOACTIVATE'  = 4
        'SHOWNORMAL'      = 1
    }
    $MainWindowHandle = (Get-Process -Id $ProcessId).MainWindowHandle
    # type may already exist, don't know how to verify
    # therefore try to add
    try {
        $signature = @"
        [DllImport("user32.dll")] 
        public static extern bool ShowWindowAsync(IntPtr hWnd, int nCmdShow); 
"@
        Add-Type -MemberDefinition $signature -Namespace Win32Functions -Name Win32ShowWindowAsync -ErrorAction Stop
    } catch {
    } finally {
        [void][Win32Functions.Win32ShowWindowAsync]::ShowWindowAsync($MainWindowHandle,$WindowStates[$Style])
        Write-Verbose ("Set Window Style '{1} on '{0}'" -f $MainWindowHandle,$Style)
    }
}

#endregion



### Aliases and Export ###
New-Alias -Name test -Value Test-Target -Scope Global -Force
New-Alias -Name t    -Value Test-Target -Scope Global -Force
#Export-ModuleMember -Function *

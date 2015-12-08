<#
    .DESCRIPTION
        Collection of functions to perform tasks on Juniper devices remotely via SSH Shell Stream.

        Typical workflow to retrieve information from a Juniper device (series of commands):
        1. Establish connection
            $session = New-JuniperCliSession <DeviceName>
        2. Invoke required commands in sequence and process results
            Invoke-JuniperCliCommand <command> -Session $session
        ...
        3. Close connection
            Remove-RemoteSession -Session $session

        Alternative workflow to retrieve information from a Juniper device (single command):
        1. Invoke required command and process results
            Invoke-JuniperCliCommand <command>
        Connection is closed automatically.

    .REQUIRED MODULES
        Utility
        Credential
        Infrastructure
        Posh-SSH

    .FUNCTIONS
        New-JuniperCliSession
        Start-JuniperCliMode
        Invoke-JuniperCliCommand
        Test-JuniperVPNIPSec

    .NOTES
        Company : CenturyLink Cloud
        Author  : Dmitry Gancho

    .LINK
        https://support.ctl.io/hc/en-us/articles/206757223

    .SERVICE
        # F8 line below to generate module manifest and copy files of this module to destination forlder
        Publish-ThisModule #-Destination "$env:USERPROFILE\Documents\GitHub\toolbox\PowerShell Modules"
#>


#region ADD MODULES
    Test-Module -Name Posh-SSH
#endregion



#region COMMON

function New-JuniperCliSession {
<#
    .SYNOPSIS
        Opens remote SSH Shell Stream Session to a Juniper device enters CLI mode.
        If Juniper device and localhost are in different Datacenters,
        the session is opened via a PS Session to a NOC server.
    .DESCRIPTION
        Author    : Dmitry Gancho, dmitry.gancho@ctl.io
        Last edit : 11/23/2015
        Version   : 1.0
    .PARAMETER Device
        Required.
        Juniper device name.
    .PARAMETER Known
        Required.
        One of known SRX devices.
    .PARAMETER Credential
        Optional.
        Credential for Device.
    .EXAMPLE
        New-JuniperCliSession -Device WA1-SRX-EDGE
    .EXAMPLE
        New-JuniperCliSession -Known WA1-SRX-EDGE
    .INPUTS
        [string]
    .OUTPUTS
        [PSSession] PS session to a NOC box, where Shell Stream Session to Device is opened.
        Shell Stream Session is saved in variable $StreamSession.
        [StreamSession] if session opened locally.
    .LINK
        https://support.ctl.io/hc/en-us/articles/206757223
#>
    [CmdletBinding(DefaultParameterSetName='unknown')]
    param(
        [Parameter(Mandatory,ValueFromPipeline,Position=0,ParameterSetName='unknown')]
        [string]$Device
    )

    DynamicParam {
        $dictionary = New-Object -TypeName System.Management.Automation.RuntimeDefinedParameterDictionary
        
        #region parameter Known
        $paramName = 'Known'
        $paramType = [string]
        $attributes = New-Object Management.Automation.ParameterAttribute
        $attributes.Position = 0
        $attributes.Mandatory = $true
        $attributes.ParameterSetName = 'known'
        $values = Find-InfrastructureDevices *SRX* | Select-Object -ExpandProperty Name
        $collection = New-Object Collections.ObjectModel.Collection[System.Attribute]
        $collection.Add($Attributes)
        if ($values) {$collection.Add((New-Object Management.Automation.ValidateSetAttribute($values)))}
        $parameter = New-Object Management.Automation.RuntimeDefinedParameter($paramName,$paramType,$collection)
        $dictionary.Add($paramName,$parameter)
        #endregion

        #region parameter Credential
        $paramName = 'Credential'
        $paramType = [PSCredential]
        $attributes = New-Object Management.Automation.ParameterAttribute
        $collection = New-Object Collections.ObjectModel.Collection[System.Attribute]
        $collection.Add($Attributes)
        $parameter = New-Object Management.Automation.RuntimeDefinedParameter($paramName,$paramType,$collection)
        $dictionary.Add($paramName,$parameter)
        #endregion

        $dictionary
    }

    process {
        # set variables from $dictionary
        $dictionary.Keys | ForEach-Object {
            New-Variable -Name $_ -Value $dictionary.$_.Value -Scope Script -Force
        }
        if ($PSCmdlet.ParameterSetName -eq 'known') {
            $Device = $Known
        }
        # verify $Device is not an IP address
        if (Test-IPv4 -ip $Device) {
            Write-Error "'$Device' is an IP address. Please specify a device Name, i.e. 'WA1-SRX-EDGE'."
            break
        }

        # get credential for Device
        if (-not $Credential) {
            $Credential = Import-Credential -FriendlyName $Device -NewIfNotFound
        }
        Write-Verbose "Credential : '$($Credential.ToString())'"

        # get DC name for Device
        $dc = $device.Substring(0,3)
        Write-Verbose "DC : '$dc'"

        # get DC name for localhost
        $hostDc = $env:COMPUTERNAME.Substring(0,3)
        Write-Verbose "Localhost DC : '$hostDc'"

        # deside if NOC is required
        $useNoc = $dc -ne $hostDc
        Write-Verbose "Using NOC : $useNoc"

        if ($useNoc) {
            # get NOC for that DC
            $noc = Find-InfrastructureDevices $dc*NOC* | select -fi 1 | select -exp Name
            if (-not $noc) {
                Write-Error "Failed to find a NOC server for DC '$dc'"
                break
            }
            Write-Verbose "NOC Server : '$noc'"

            # create PS session to NOC server
            Write-Verbose "Creating PS Session to '$noc'"
            if ($env:USERDOMAIN -eq 'T3N') {
                $session = New-RemoteSession -Device $noc
            } else {
                $t3nCredential = Import-Credential -FriendlyName T3N -NewIfNotFound
                Write-Verbose "T3N Credential : '$t3nCredential'"
                $session = New-RemoteSession -Device $noc -Credential $t3nCredential
            }
            Write-Verbose "PS Session : '$session'"
            if (-not $session) {
                Write-Error "PS Session to '$noc' failed." -Category ConnectionError -TargetObject $noc
                break
            }

            # setup enviroment
            Write-Verbose "Importing required modules"
            Invoke-RemoteSession -Session $session -ScriptBlock {
                $Path = 'E:\CloudLSE\Scripts\toolbox\PowerShell Modules'
                if ($env:PSModulePath -notmatch ($Path -replace '\\','\\')) {
                    $env:PSModulePath += ";$Path"
                }
                Import-Module -Name Utility,Credential,Infrastructure,Juniper -Global -Force
                Test-Module -Name Posh-SSH | Out-Null
            }

            # create a Shell Stream Session from NOC to Device 
            Write-Verbose "Opening Remote SSH Shell Stream Session to '$Device'"
            Invoke-RemoteSession -Session $session -ArgumentList $credential,$Device -ScriptBlock {
                param(
                    [PSCredential]$credential,
                    [string]$device
                )
                $StreamSession = New-RemoteSession -Device $device -SshStream -Credential $credential
                Start-JuniperCliMode -Session $StreamSession | Out-Null
            }
        } else {
            # directly from local host, no NOC
            Write-Verbose "Opening Remote SSH Shell Stream Session to '$Device'"
            $session = New-RemoteSession -Device $device -SshStream -Credential $credential
            Start-JuniperCliMode -Session $session | Out-Null
        }

        # return PSSession or StreamSession object
        return $session
    }
}


function Start-JuniperCliMode {
<#
    .SYNOPSIS
        Enters CLI mode in SSH Shell Stream Session to a Juniper device.
        Runs set of commands:
            cli
            set cli screen-width 0
            set cli screen-length 0
    .DESCRIPTION
        Author    : Dmitry Gancho, dmitry.gancho@ctl.io
        Last edit : 11/18/2015
        Version   : 1.0
    .PARAMETER  Session
        Required.
        SSH Shell Stream Session.
    .EXAMPLE
        $Session = New-RemoteSession -Device WA1-SRX-CORE -SshStream
        Start-JuniperCliMode -Session $Session
    .INPUTS
        [SSHShellStream]
    .OUTPUTS
        [string[]]
    .LINK
        https://support.ctl.io/hc/en-us/articles/206757223
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][Alias('stream')]
        [Renci.SshNet.ShellStream]$Session
    )
    Invoke-RemoteSession -Command 'cli' -Session $Session
    Invoke-RemoteSession -Command 'set cli screen-width 0' -Session $Session
    Invoke-RemoteSession -Command 'set cli screen-length 0' -Session $Session
}


function Invoke-JuniperCliCommand {
<#
    .SYNOPSIS
        Invokes command in SSH Shell Stream Session to a Juniper device.
        If Session parameter is specified, the session remains open.
        If Session parameter is not specified, a new session is opened, command executed, then session is closed.
    .DESCRIPTION
        Author    : Dmitry Gancho, dmitry.gancho@ctl.io
        Last edit : 11/22/2015
        Version   : 1.0
    .PARAMETER Command
        Required.
        Command to invoke.
    .PARAMETER Common
        Required.
        Command from pre-defined selection of commonly used commands.
    .PARAMETER  arg
        Optional.
        Agrument to replace '<agr>' in Command
    .PARAMETER  Session
        Optional.
        SSH Shell Stream Session.
    .EXAMPLE
        $Session = New-JuniperCliSession WA1-SRX-EDGE
        Invoke-JuniperCliCommand 'show chassis routing-engine' -Session $Session
    .EXAMPLE
        Invoke-JuniperCliCommand 'show configuration | display set | match "<arg>"' -arg '172\.16\.1\.48\/32|10\.80\.156\.0\/24' -Session $Session
    .EXAMPLE
        Invoke-JuniperCliCommand 'show log screen-log | last <arg>' -arg 100 -Session $Session
    .EXAMPLE
        Invoke-JuniperCliCommand 'show configuration firewall' -Session $Session
    .EXAMPLE
        'show log kmd | match 108.60.55.2 | match error' | Invoke-JuniperCliCommand -Session $Session
    .EXAMPLE
        'show configuration snmp' | Invoke-JuniperCliCommand -Session $Session
    .INPUTS
        See parameters
    .OUTPUTS
        [string[]]
    .LINK
        https://support.ctl.io/hc/en-us/articles/206757223
#>
    [CmdletBinding(DefaultParameterSetName='Command')]
    param (
        [Parameter(Mandatory,ValueFromPipeline,Position=0,ParameterSetName='Command')]
        [string]$Command,

        [Parameter()]
        [object]$Session
    )

    DynamicParam {
        # declarations
        # http://the.earth.li/~sgtatham/putty/0.53b/htmldoc/Chapter7.html
        try {
            Add-Type -Language CSharp -ErrorAction Stop @"
                public class qstring {
                    public qstring(string quotedString) : this(quotedString, "'") {}
                    public qstring(string quotedString, string quoteCharacter) {
                        OriginalString = quotedString;
                        _quoteCharacter = quoteCharacter;
                    }
                    public string OriginalString { get; set; }
                    string _quoteCharacter;
                    public override string ToString() {
                        if (OriginalString.Contains(" ")) {
                            return string.Format("{1}{0}{1}", OriginalString, _quoteCharacter);
                        } else {
                            return OriginalString;
                        }
                    }
                }
"@      } catch {}
        $dictionary = New-Object Management.Automation.RuntimeDefinedParameterDictionary

        # param Common
        $paramName = 'Common'
        $paramType = [qstring]
        $values = @(
            'show system alarms'
            'show chassis routing-engine'
            'show security ipsec security-associations'
            'show log screen-log | last <arg>'
            'show security ipsec sa | match <arg>'
            'show configuration | display set | match "<arg>"'
            'show security policies detail policy-name <arg> | match ipsec'
            'show security ipsec security-associations index <arg>'
            'request security ike debug-disable'
            'show log kmd | match <arg> | match error'
            'show configuration snmp'
            'show configuration firewall'
        ) | ForEach-Object {[qstring]$_.ToString()}
        $attributes = New-Object Management.Automation.ParameterAttribute
        $attributes.ParameterSetName = $paramname
        $attributes.Position = 0
        $attributes.Mandatory = $true
        $attributes.ValueFromPipeline = $true
        $collection = New-Object Collections.ObjectModel.Collection[Attribute]
        $collection.Add($attributes)
        $collection.Add((New-Object Management.Automation.ValidateSetAttribute($values)))
        $parameter = New-Object Management.Automation.RuntimeDefinedParameter($paramName,$paramType,$collection)
        $dictionary.Add($paramname,$parameter)

        # param arg
        $paramName = 'arg'
        $paramType = [string]
        $attributes = New-Object Management.Automation.ParameterAttribute
        $collection = New-Object Collections.ObjectModel.Collection[System.Attribute]
        $collection.Add($Attributes)
        $parameter = New-Object Management.Automation.RuntimeDefinedParameter($paramName,$paramType,$collection)
        $dictionary.Add($paramname,$parameter)

        # param Device
        $paramName = 'Device'
        $paramType = [string]
        $attributes = New-Object Management.Automation.ParameterAttribute
        $values = Find-InfrastructureDevices *SRX* | Select-Object -ExpandProperty Name
        $collection = New-Object Collections.ObjectModel.Collection[System.Attribute]
        $collection.Add($Attributes)
        if ($values) {$collection.Add((New-Object Management.Automation.ValidateSetAttribute($values)))}
        $parameter = New-Object Management.Automation.RuntimeDefinedParameter($paramName,$paramType,$collection)
        $dictionary.Add($paramName,$parameter)

        # return
        $dictionary
    }

    process {
        $dictionary.Keys | ForEach-Object {
            New-Variable -Name $_ -Value ($dictionary.$_.value -replace "^'|'$")
        }
        if ($PSCmdlet.ParameterSetName -eq 'common') {
            $Command = $Common
        }
        $Command = $Command -replace '<arg>',$arg
        Write-Verbose "Command : '$Command'"

        if (-not $Session) {
            if ($Device) {
                $Session = New-JuniperCliSession -Device $Device
                $removeOnExit = $true
            } else {
                Write-Error "You must specify a Session or a Device."
                break
            }
        } else {
            $removeOnExit = $false
        }

        switch ($Session.GetType().Name) {
            ShellStream {
                Write-Verbose "Invoking '$Command' in Stream Session"
                Invoke-RemoteSession -Command $Command -Session $Session
            }
            PSSession {
                Write-Verbose "Invoking '$Command' in PS Session"
                Invoke-RemoteSession -Session $Session -ArgumentList $command -ScriptBlock {
                    param(
                        [string]$command
                    )
                    Invoke-JuniperCliCommand -Command $command -Session $StreamSession
                }
            }
            default {
                Write-Error "Unknown Session '$Session' type: [$($Session.GetType().FullName)]"
            }
        }
        if ($removeOnExit) {
            Write-Verbose "Removing PS Session"
            Remove-RemoteSession -Session $Session
        }
    }
}

#endregion


#region TASKS

function Test-JuniperVPNIPSec {
<#
    .SYNOPSIS
        Connect to <DC>-SRX-CORE device and test VPN IPSec Ph1 and Ph2
    .DESCRIPTION
        Author    : Dmitry Gancho, dmitry.gancho@ctl.io
        Last edit : 11/21/2015
        Version   : 1.0
    .PARAMETER Datacenter
        Required.
        Datacenter name
    .PARAMETER PeerPublicIp
        Required.
        Peer (initiator) public IP address.
    .PARAMETER SourceSubnet
        Required.
        Peer local subnet.
    .PARAMETER DestinationSubnet
        Required.
        CTL Cloud local subnet.
    .EXAMPLE
        Test-JuniperVPNIPSec -dc WA1 -ip 209.67.114.22 -source 172.16.1.48/32 -dest 10.80.156.0/24
    .EXAMPLE
        Test-JuniperVPNIPSec -dc WA1 -ip 66.193.111.170 -source 192.168.10.0/24 -dest 10.82.209.0/24 -Verbose
    .LINK
        https://support.ctl.io/hc/en-us/articles/206757223
#>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory,Position=0)]
        [Alias('dc')]
        [ValidateSet(
            'CA1',
            'CA2',
            'CA3',
            'DE1',
            'GB1',
            'GB3',
            'IL1',
            'NE1',
            'NY1',
            'SG1',
            'UC1',
            'UT1',
            'VA1',
            'WA1'
        )]
        [string]$Datacenter,

        [Parameter(Mandatory,Position=1)]
        [Alias('ip')]
        [ValidateScript({if ($_ -match "\b(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}\b") 
                        {$true} else {throw "'$_' is not a valid IPv4 address"}})]
        [string]$PeerPublicIp,

        [Parameter(Mandatory)]
        [Alias('source')]
        [string]$SourceSubnet,

        [Parameter(Mandatory)]
        [Alias('dest')]
        [string]$DestinationSubnet
    )

    # set device name
    $device = "$Datacenter-SRX-CORE"

    # create SSH Shell Stream Session
    Write-Verbose "Opening session to device '$device'"
    $session = New-RemoteSession -Device $device -SshStream
    
    # enter CLI mode
    Write-Verbose "Entering CLI mode"
    $response = Start-JuniperCliMode -Session $session
    $response

    # Step 1: Verify Phase 1
    $command = "show security ike security-associations $PeerPublicIp"
    Write-Verbose "Sending command: '$command'"
    $response = Invoke-JuniperCliCommand -Command $command -Session $session
    $response

    # Step 2: Verify Phase 2
    # Verify whether there are any IPSec SAs up for the tunnel:
    $peerRegex = $PeerPublicIp | ConvertTo-Regex
    $command = "show security ipsec sa | match $peerRegex"
    Write-Verbose "Sending command: '$command'"
    $response = Invoke-JuniperCliCommand -Command $command -Session $session
    $response

    # convert IPs to regex-compatible (optional)
    $sourceRegex = $SourceSubnet | ConvertTo-Regex
    $destinRegex = $DestinationSubnet | ConvertTo-Regex

    # Step 3: Find the policy which matches both ranges
    $command = "show configuration | display set | match ""$sourceRegex|$destinRegex"""
    Write-Verbose "Sending command: '$command'"
    $response = Invoke-JuniperCliCommand -Command $command -Session $session
    $response

    $result = $response -match '^set'
    $policies = ($result -split ' ') -match '-ib' | select -Unique
    $pairs = @{}
    $policies | % {
        $pairs.$_ = @{
            source = $result -like "*$_*source*"
            destin = $result -like "*$_*destination*"
        }
    }
    $policyName = $pairs.Keys | ? {($pairs.$_.source -match $sourceRegex) -and ($pairs.$_.destin -match $destinRegex)}
    if ($policyName) {
        $policy = @{
            Name        = $policyName
            Source      = $pairs.$policyName.source
            Destination = $pairs.$policyName.destin
        }
    } else {
        Remove-RemoteSession -Session $session
        Write-Error 'No matching policy found'
    }

    # Step 4: Look at policy details for that policy to extract the IPSec SA index
    $command = "show security policies detail policy-name $($policy.Name) | match ipsec"
    Write-Verbose "Sending command: '$command'"
    $response = Invoke-JuniperCliCommand -Command $command -Session $session
    $response

    $result = $response -match 'Tunnel'
    $index = $result -split ': ' | select -Last 1

    # Step 5: Look at that particular SA
    $command = "show security ipsec security-associations index $index"
    Write-Verbose "Sending command: '$command'"
    $response = Invoke-JuniperCliCommand -Command $command -Session $session
    $response

    # close session
    Write-Verbose "Closing session"
    Remove-RemoteSession -Session $session
}

#endregion


### Aliases and Export ###
Export-ModuleMember -Function *

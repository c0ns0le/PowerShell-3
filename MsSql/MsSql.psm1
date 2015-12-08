<#
    .DESCRIPTION
        Functions to connect and execute queries against a MS SQL Server.
        Can be called from workstation, NOC server, SQL server.

    .FUNCTIONS
        Invoke-SqlQuery

    .NOTES
        Company : CenturyLink Cloud
        Author  : Dmitry Gancho, dmitry.gancho@ctl.io

    .LINK
        https://support.ctl.io/hc/en-us/articles/206634406

    .SERVICE
        # F8 to generate module manifest and copy contents of current folder to destination folder
        Publish-ThisModule -Destination "$env:USERPROFILE\Documents\GitHub\toolbox\PowerShell Modules"
#>


function Invoke-SqlQuery {
<#
    .SYNOPSIS
        Invoke SQL query against a MS SQL server with domain authentication.
        If user is not in the same domain, query executed on SQL server via remote PS session.
        Credential or open PS Session must be provided in parameters.
    .DESCRIPTION
        Author    : Dmitry Gancho
        Last edit : 12/5/2015
        Version   : 1.0
    .EXAMPLE
        Invoke-SqlQuery -Query "SELECT * FROM Devices WHERE Make='Juniper'" -DbName Zoltar -ComputerName WA1T3NSQL20120
        -------------------------------------
        Use this syntax when querying from the same domain (i.e. NOC server).
    .EXAMPLE
        $Credential = Get-Credential -Message "Enter 'T3N' credential:"
        Invoke-SqlQuery -Query "SELECT * FROM Devices WHERE Make='Juniper'" -DbName Zoltar -ComputerName WA1T3NSQL201202 -Credential $Credential
        -------------------------------------
        Use this syntax when querying from other domain (i.e. workstation) and you need to send single query.
    .EXAMPLE
        $Credential = Get-Credential -Message "Enter 'T3N' credential:"
        $Session = New-PSSession -ComputerName WA1T3NSQL201202 -Credential $Credential
        Invoke-SqlQuery -Query "SELECT * FROM Devices WHERE Make='Juniper'" -DbName Zoltar -Session $Session
        Invoke-SqlQuery -Query "SELECT * FROM DeviceInstances" -DbName Zoltar -Session $Session
        Remove-PSSession -Session $Session
        -------------------------------------
        Use this syntax when querying from other domain (i.e. workstation) and you need to send multiply queries.
    .INPUTS
        [string]
        [string]
        [string]
        [PSCredential]
        [Management.Automation.Runspaces.PSSession]
    .OUTPUTS
        [PSObject[]]
    .LINK
        https://support.ctl.io/hc/en-us/articles/206634406
#>
    [CmdletBinding(DefaultParameterSetName='server')]
    param (
        [Parameter(ParameterSetName='server')]
        [Alias('cn')]
        [string]$ComputerName = $env:COMPUTERNAME,

        [Parameter(Mandatory)]
        [string]$DbName,

        [Parameter(Mandatory)]
        [Alias('qry')]
        [string]$Query,

        [Parameter(ParameterSetName='server')]
        [PSCredential]$Credential,

        [Parameter(Mandatory,ParameterSetName='session')]
        [Management.Automation.Runspaces.PSSession]$Session
    )

    if ($PSCmdlet.ParameterSetName -eq 'server') {
        # verify if same domain
        if ($Credential -and ($env:USERDOMAIN -ne $Credential.GetNetworkCredential().Domain)) {
            # need to start new remote PS Session
            $Session = New-PSSession -ComputerName $ComputerName -Credential $Credential
        }
    }

    $scriptBlock = {
        param (
            [string]$dbName,
            [string]$query
        )
        $connString  = "Database = $dbName; Integrated Security = true"
        $connection  = New-Object System.Data.SqlClient.SqlConnection $connString
        $connection.Open()
        $command = $connection.CreateCommand()
        $command.CommandText = $query
        $result = $command.ExecuteReader()
        $table = New-Object System.Data.DataTable
        $table.Load($result)
        $connection.Close()
        $table
    }

    $param = @{
        ScriptBlock = $scriptBlock
        ArgumentList = $DbName,$Query
    }
    if ($Session) {
        $param.Add('Session',$Session)
        $param.Add('HideComputerName',$true)
    }
    Invoke-Command @param | Select-Object -Property * -ExcludeProperty RunspaceId

    if ($PSCmdlet.ParameterSetName -eq 'server') {
        Remove-PSSession -Session $Session
    }
}


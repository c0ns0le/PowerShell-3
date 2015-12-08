<#
    .DESCRIPTION
        Collection of functions for VEEAM.

    .REQUIRED MODULES
        Utility
        Credential
        Infrastructure

    .FUNCTIONS
        Get-VeeamLatestSession
        Get-VeeamVM

    .NOTES
        Company : CenturyLink Cloud
        Author  : Dmitry Gancho

    .LINK

    .SERVICE
        # F8 line below to generate module manifest and copy contents of this module folder to destination folder.
        Publish-ThisModule #-Destination "$env:USERPROFILE\Documents\GitHub\toolbox\Team Scripts\Dmitry Gancho"
#>



function Get-VeeamLatestSession {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory,ValueFromPipeline)]
        [Alias('job')]
        [string[]]$JobName,

        [switch]$Raw
    )
    process {
        foreach ($job in $JobName) {
            # get DC
            $dc = $job.Substring(0,3).ToUpper()
            # get Veeam servers in the DC
            $known = Import-Infrastructure
            $veeams = $known.Veeam.Devices.GetEnumerator() | where Key -Like $dc* | sort Name | select -exp Name
            Write-Verbose "Veeam Servers in $dc`:`n$($veeams -join "`n")"
            # get creds
            $cred = Import-Credential -FriendlyName T3N -NewIfNotFound
            # connect to each Veeam server
            Write-Verbose "Opening PS sessions"
            $sessions = New-PSSession -ComputerName $veeams -Credential $cred -Authentication Credssp
            Write-Verbose "PS sessions : $($sessions.ComputerName -join ',')"
            # search for the job
            Write-Verbose "Invoking search in opened PS sessions"
            $result = Invoke-Command -Session $sessions -ArgumentList $job -ScriptBlock {
                Get-PSSnapin -Registered | Add-PSSnapin
                $WarningPreference = 'SilentlyContinue'
                if (Get-Command -Name Get-VBRBackup -ErrorAction SilentlyContinue) {
                    $job = Get-VBRBackup -Name $args[0]
                    if ($job) {
                        $session = Get-VBRBackupSession -Name ($args[0]+'*') | sort CreationTime | select -Last 1
                        @{
                            Server             = $env:COMPUTERNAME
                            Job                = $job
                            Repository         = $job.GetRepository()
                            TargetHost         = $job.GetTargetHost()
                            Session            = $session
                            Info               = $session.Info
                            Progress           = $session.Progress
                            IsSessionNeedAbort = $session.IsSessionNeedAbort()
                            Objects            = @{
                                Success    = ($session.GetTaskSessionsByStatus('Success').Name -join ',')
                                InProgress = ($session.GetTaskSessionsByStatus('InProgress').Name -join ',')
                                Pending    = ($session.GetTaskSessionsByStatus('Pending').Name -join ',')
                                Warning    = ($session.GetTaskSessionsByStatus('Warning').Name -join ',')
                                Failed     = ($session.GetTaskSessionsByStatus('Failed').Name -join ',')
                            }
                        }
                    }
                }
            }
            # remove PS sessions
            Write-Verbose "Removing PS sessions: $($sessions.ComputerName -join ',')"
            Remove-PSSession -Session $sessions
            if ($Raw) {
                $result
            } else {
                # format results
                [PSCustomObject][ordered]@{
                    'Time Stamp'          = (Get-Date -Format G)
                    'Veeam Server'        = $result.Server
                    'Job Name'            = $result.Job.Name
                    'Job Type'            = $result.Job.JobType
                    'Job VM Count'        = $result.Job.VmCount
                    'Repository'          = $result.Repository.Name
                    'Target Host'         = $result.TargetHost.Name
                    'Session Name'        = $result.Session.Name
                    'Session Algorithm'   = $result.Info.JobAlgorithm
                    'Session Start UTC'   = $result.Progress.StartTime
                    'Session Duration'    = ("{0:h\:mm\:ss}" -f $result.Progress.Duration)
                    'Session End UTC'     = $result.Session.EndTime
                    'Session Avg Speed'   = $(if ($result.Progress.AvgSpeed -gt 0) {"{0:1} MB/s" -f ($result.Progress.AvgSpeed/1MB)})
                    'Session Progress'    = ("{0:0} %" -f $result.Progress.Percents)
                    'Session State'       = $result.Session.State
                    'Session Result'      = $result.Session.Result
                    'Session Need Abort'  = $result.IsSessionNeedAbort
                    'Objects Total'       = $result.Progress.TotalObjects
                    'Objects Processed'   = $result.Progress.ProcessedObjects
                    'Objects Success'     = $result.Objects.Success
                    'Objects In Progress' = $result.Objects.InProgress
                    'Objects Pending'     = $result.Objects.Pending
                    'Objects Warning'     = $result.Objects.Warning
                    'Objects Failed'      = $result.Objects.Failed
                }
            }
        }
    }
}



function Get-VeeamVM {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory,ValueFromPipeline)]
        [Alias('cn')]
        [string[]]$ComputerName,

        [switch]$Raw
    )
    process {
        foreach ($computer in $ComputerName) {
            # get DC
            $dc = $computer.Substring(0,3)
            # get Veeam servers in the DC
            $known = Import-Infrastructure
            $veeams = $known.Veeam.Devices.GetEnumerator() | where Key -Like $dc* | select -exp Name
            Write-Verbose "Veeam Servers:`n$($veeams -join "`n")"
            # get creds
            $cred = Import-Credential -FriendlyName T3N -NewIfNotFound
            # connect to each Veeam server
            Write-Verbose "Opened PS session to '$veeam'"
            $sessions = New-PSSession -ComputerName $veeams -Credential $cred -Authentication Credssp
            # search for the VM and restore points
            Write-Verbose "Invoking search in opened PS sessions"
            $result = Invoke-Command -Session $sessions -ArgumentList $computer -ScriptBlock {
                Get-PSSnapin -Registered | Add-PSSnapin
                $WarningPreference = 'SilentlyContinue'
                if (Get-Command -Name Find-VBRViEntity -ErrorAction SilentlyContinue) {
                    $vm = Find-VBRViEntity -Name $args[0] -VMsAndTemplates
                    if ($vm) {
                        @{
                            Server        = $env:COMPUTERNAME
                            VM            = $vm
                            RestorePoints = Get-VBRRestorePoint -Name $vm.Name
                        }
                    }
                }
            }
            # remove PS sessions
            Write-Verbose "Removing PS sessions"
            Remove-PSSession -Session $sessions
            if ($Raw) {
                $result
            } else {
                # format results
                [PSCustomObject][ordered]@{
                    TimeStamp     = (Get-Date -Format G)
                    VMName        = $result.VM.Name
                    State         = $result.VM.PowerState
                    IsTemplate    = $result.VM.IsTemplate
                    vCenterServer = $result.VM.ConnHost
                    ESXHost       = $result.VM.VmHostName
                    VeeamServer   = $result.Server
                    Folder        = $result.VM.VmFolderName
                    Path          = $result.VM.Path
                    RestorePoints = ($result.RestorePoints.CreationTime -join "`n")
                }
            }
        }
    }
}




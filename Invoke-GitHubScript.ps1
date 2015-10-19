
#function Invoke-GitHubScript {
<#
.SYNOPSIS
    Invokes a script or imports a module from GitHub
.DESCRIPTION
    Invokes a .ps1 script or imports a .psm1 module from GitHub
    This is a standalone function with no dependencies
    and therefore can be used in PROFILE and such
.PARAMETER Path
    Path to a GitHubFile in format 'Owner/Repo/Folder/File'
    IMPORTANT: 'Folder' and 'File' are case-sensitive
.PARAMETER WebSession
    Already authenticated GitHub WebSession. Optional
.EXAMPLE
    Invoke-GitHubScript -GitHubPath MyOrganization/OurRepository/TeamFolder/Subfolder/MyScript.ps1
    Executes a sript from GitHub location
.EXAMPLE
    'MyOrg/OurRepo/TeamFolder/Module.psm1','Myself/MyRepo/Script.ps1' | Invoke-GitHubScript
    Imports a module from one GitHub location and then executes a script from another GitHub location
.NOTES
    Author : Dmitry Gancho
             dmitry@ganco.com
    Date   : 10/18/2015
    Version: 1.0
#>
    param (
        [Parameter(Mandatory,ValueFromPipeline,ValueFromPipelineByPropertyName,Position=0,
            HelpMessage="Path to GitHub file, format: Owner/Repo/Folder/File.ext")]
        [Alias('path')]
        [string[]]$GitHubPath,

        [Parameter()][Alias('ws')]
        [Microsoft.PowerShell.Commands.WebRequestSession]$WebSession
    )
    begin {
        $baseuri = 'https://api.github.com'
        if (-not $WebSession) {
            # get GibHub creds
            $regpath = 'HKCU:\Environment\Credentials\GitHub'
            if ((Test-Path -Path $regpath) -and (&{
                $Script:u = Get-ItemProperty -Path $regpath | select -exp UserName
                $Script:p = Get-ItemProperty -Path $regpath | select -exp Password
                $Script:u -and $Script:p
            })) {
                $user = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR((ConvertTo-SecureString $Script:u)))
                $pass = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR((ConvertTo-SecureString $Script:p)))
            } else {
                $cred = Get-Credential -Message 'Enter credential for GitHub:'
                if (-not $cred) {return $null}
                $user = $cred.Username
                $pass = $cred.GetNetworkCredential().Password
                if (-not $user -or -not $pass) {return $null}
                # offer User to save credential
                [void][Reflection.Assembly]::LoadWithPartialName('System.Windows.Forms')
                [System.Windows.Forms.Application]::EnableVisualStyles()
                if ([Windows.Forms.MessageBox]::Show('Save GitHub credential for future use?','Question',1,'Question') -eq 'OK') {
                    if (-not (Test-Path -Path $regpath)) {New-Item -Path $regpath -Force | Out-Null}
                    $enuser = $user | ConvertTo-SecureString -AsPlainText -Force | ConvertFrom-SecureString
                    $enpass = $pass | ConvertTo-SecureString -AsPlainText -Force | ConvertFrom-SecureString
                    New-ItemProperty -Path $regpath -Name UserName -Value $enuser -PropertyType String -Force | Out-Null
                    New-ItemProperty -Path $regpath -Name Password -Value $enpass -PropertyType String -Force | Out-Null
                }
            }
            # get GitHub authenticated WebSession
            $base64 = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes("$user`:$pass"))
            $headers = @{Authorization = "Basic $base64"}
            Invoke-RestMethod -Uri $baseuri -Headers $headers -SessionVariable Ws | Out-Null
        }
    }
    process {
        $GitHubPath | % {
            # build uri: https://api.github.com/repos/Owner/Repo/contents/Folder/File.ext
            $arr = $_ -split '/'
            $path = ($arr[0..1] + 'contents' + $arr[2..($arr.Count-1)]) -join '/'
            $uri = "$baseuri/repos/$path"
            # get content
            try {
                $response = Invoke-RestMethod -Uri $uri -WebSession $Ws -ErrorAction Stop
            } catch {
                $err = [ordered]@{ERROR_URI = $uri}
                $res = $_.ErrorDetails.Message | ConvertFrom-Json
                $res | gm -type NoteProperty | select -exp Name | % {$err.$_ = $res.$_}
                [PSCustomObject]$err | fl
                continue
            }
            # decrypt content and execute
            $content = [System.Text.Encoding]::ASCII.GetString([System.Convert]::FromBase64String($response.content))
            # not sure why GitHub adds '???' at the beginning of some files, so remove this
            $content = $content -replace '\?\?\?'
            if ($_ -match ".+\.psm1$") {
                    # module .psm1
                    $name = ($_ -split '/' | select -Last 1) -split '\.' | select -First 1 
                    Import-Module (New-Module -Name $name -ScriptBlock ([scriptblock]::Create($content)))
            } else {
                # script .ps1
                Invoke-Expression $content
            }
        }
    }
    end {
        New-Alias -Name igh -Value $MyInvocation.MyCommand.Name -Scope Global -Force
    }
#}

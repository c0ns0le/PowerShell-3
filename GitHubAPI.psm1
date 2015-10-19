
<#
    .NOTES
        Version 1.1
    .DESCRIPTION
        Module to upload/update file to a GitHub repo
        and to download and execute a a file stored on GitHub
        'on-the-fly' without any configuration or installation of
        Git for Windows or other 3-rd party tools
    .REQUIRED MODULES
        Credential
    .FUNCTIONS LIST
        New-GitHubToken
        Get-GitHubAuthorization (not used)
        New-GitHubApiSession
        Receive-GitGubContent
        Invoke-GitHubScript
        Publish-GitGubFile
    .LINK
        https://schacon.github.io/gitbook/1_the_git_object_model.html
#>



function New-GitHubToken {
<#
    .SYNOPSIS
    Generates and returns new GitHub Token
    .DESCRIPTION
    Generates and returns new GitHub Token
    .EXAMPLE
    New-GitHubToken
    .EXAMPLE
    New-GitHubToken -UserName myusername -Password P@ssw0rd!
    .PARAMETER UserName (alias user,u)
    User Name
    .PARAMETER Password (alias pass,p)
    Password
    .PARAMETER FriendlyName
    Friedly Name for the token
    .NOTES
        Author: Dmitry Gancho
                dmitry@ganco.com
        Last edit: 10/17/2015
#>
    [CmdLetBinding()] 
    param (
        [Alias('user','u')]
        [string]$UserName,

        [Alias('pass','p')]
        [string]$Password,

        [Parameter()]
        [Alias('name')]
        [string]$FriendlyName = 'PowerShell'
    ) #param
        
    if (!$UserName -or !$Password) {
        $cred = Import-Credential -FriendlyName GitHub -NewIfNotFound -As HashTable
        $UserName = $cred.UserName
        $Password = $cred.Password
    }

    $tokenUrl = 'https://github.com/settings/tokens/new'

    # login with IE
    $ie = New-Object -ComObject InternetExplorer.Application
    #$ie.visible = $true
    # https://msdn.microsoft.com/en-us/library/dd565688%28v=vs.85%29.aspx
    [void]$ie.navigate($tokenUrl)

    # wait for ie.document to load
    $n=0; while ($ie.busy -and ($n -lt 100)) {$n++; sleep -m 100}
    $n=0; while (!$ie.document -and ($n -lt 50)) {$n++; sleep -m 100}
    Start-Sleep -Seconds 1

    if ($ie.LocationName -like '*Sign in*') {
        # redirected to 'Log in' page
        # enter UserName and Password
        $class = $ie.document.body.getElementsByClassName('input-block')
        ($class | ? id -EQ login_field).Value = $UserName
        ($class | ? Id -EQ password).Value = $Password
        # click log in button
        $control = $ie.document.body.getElementsByClassName('btn') | ? name -EQ commit
        $control.click()
    } elseif ($ie.LocationName -like "*Confirm password*") {
        # redirected to Sudo Mode page
        # enter Password
        $class = $ie.document.body.getElementsByClassName('input-block')
        ($class | ? Id -EQ sudo_password).Value = $Password
        # click log in button
        $control = $ie.document.body.getElementsByClassName('btn') | ? type -EQ submit
        $control.click()
    } #if

    # wait for ie.document to load
    $n=0; while ($ie.busy -and ($n -lt 100)) {$n++; sleep -m 100}
    $n=0; while (!$ie.document -and ($n -lt 50)) {$n++; sleep -m 100}
    Start-Sleep -Seconds 1


    # verify if on desired page
    if ($ie.Document.url -ne $tokenUrl) {
        $errMessage  = "`nERROR: Unable to reach url '$tokenUrl'"
        $errMessage += "`nUserName: '$username' | Password: '$password'"
        Write-Host -Object $errMessage -ForegroundColor Red
        $ie.visible = $true
        break
    }

    # get input form class
    $classform = $ie.document.body.getElementsByClassName('new_oauth_access')
    # get all input controls
    $inputcontrols = $classform[0].getElementsByTagName('input')
    # enter description
    ($inputcontrols | ? type -EQ text).value = "$FriendlyName $(Get-Date -Format g)"
    #  check all checkboxes
    $inputcontrols | ? type -EQ checkbox | % {$_.checked = $true}
    # click 'Generate token' button
    $control = $classform[0].getElementsByTagName('button')
    $control[0].click()

    # wait for ie.document to load
    $n=0; while ($ie.busy -and ($n -lt 100)) {$n++; sleep -m 100}
    $n=0; while (!$ie.document -and ($n -lt 50)) {$n++; sleep -m 100}

    # get Token
    $token = $ie.Document.body.getElementsByTagName('code')[0].outertext

    # save for re-use
    if ($token) {
        Export-Credential -FriendlyName GitHub -EntryName Token -EntryValue $token
    }

    [void]$ie.Quit()
    return $token

} #function



function Get-GitHubAuthorization {
<#
    .SYNOPSIS
    Gets and returns GitHub Application Authorization
    .DESCRIPTION
    Gets and returns GitHub Application Authorization
    Generates new if not found
    .EXAMPLE
    Get-GitHubAuthorization
    .EXAMPLE
    Get-GitHubAuthorization -AuthorizationName PowerShell -WebSession $WebSession -NewIfNotFound
    .PARAMETER AuhorizationName
    Default value: PowerShell
    .PARAMETER WebSession
    Authenticated web session
    .PARAMETER NewIfNotFound
    Switch to create new if not found
    .NOTES
        Author: Dmitry Gancho
        Last edit: 10/9/2015
#>
    [CmdLetBinding()]
    param (
        [Parameter(Position=0)]
        [Alias('name')]
        [string]$AuhorizationName = 'PowerShell',

        [Parameter()]
        [Alias('ws')]
        [Microsoft.PowerShell.Commands.WebRequestSession]$WebSession = (New-GitHubApiSession),

        [Alias('new')]
        [switch]$NewIfNotFound = $false
    )

    $root = 'https://api.github.com'
    $url = 'authorizations'
    $res = Invoke-RestMethod -Method Get -Uri "$root/$url" -WebSession $WebSession -ErrorAction Stop
    $psAuth = $res | ? {$_.app.name -Like "*$AuhorizationName*"}
    if (-not $psAuth -and $NewIfNotFound) {
        New-GitHubToken -FriendlyName $AuhorizationName
        $appAuth = Get-GitHubAppAuthorization -AuhorizationName $AuhorizationName -WebSession $WebSession -NewIfNotFound:$false
    }
    return $psAuth
} #fucntion



function New-GitHubApiSession {
 <#
    .SYNOPSIS
    Initiates and returns new GitHub API WebSession
    .DESCRIPTION
    Initiates and returns new GitHub API WebSession
    .EXAMPLE
    New-GitHubApiSession
    .EXAMPLE
    New-GitHubApiSession -AuthType Basic
    .PARAMETER AuthType
    Allowed values: Basic, Token
    .NOTES
        Author: Dmitry Gancho
        Last edit: 10/17/2015
#>
    [CmdLetBinding()]param ()

    $baseurl = 'https://api.github.com'

    #region get GibHub creds
    $path = 'HKCU:\Environment\Credentials\GitHub'
    if ((Test-Path -Path $path) -and (&{
        $Script:user = Get-ItemProperty -Path $path | select -exp UserName
        $Script:pass = Get-ItemProperty -Path $path | select -exp Password
        $user -and $pass
    })) {
        $user = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR((ConvertTo-SecureString $user)))
        $pass = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR((ConvertTo-SecureString $pass)))
    } else {
        $cred = Get-Credential -Message 'Enter credential for GitHub:'
        if (-not $cred) {return $null}
        $user = $cred.Username
        $pass = $cred.GetNetworkCredential().Password
    }
    if (-not $user -or -not $pass) {return $null}
    #endregion

    #region get GitHub authenticated WebSession
    $base64 = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes("$user`:$pass"))
    $headers = @{Authorization = "Basic $base64"}
    try {
        Invoke-RestMethod -Uri 'https://api.github.com' -Headers $headers -SessionVariable Ws | Out-Null
        return $Ws
    } catch {
        $errmsg  = "`nGET URL: $url"
        $errmsg += "`nERROR: " + $_.ErrorDetails.Message
        $errmsg += "`n" + $_.InvocationInfo.PositionMessage
        Write-Host $errmsg -ForegroundColor Red
        return $null
    }
    #endregion
} #function



function Receive-GitGubContent {
    # IMPORTANT !!!
    # $Path IS CASE CENSITIVE
<#
    .SYNOPSIS
    Gets content from GitHub
    .DESCRIPTION
    Gets content from GitHub:
    - Repositories, for which User is authorized, or
    - Array of objects (directories and/or files) from a directory, or
    - Content of a single file
    .EXAMPLE
    Receive-GitGubContent
    .EXAMPLE
    Receive-GitGubContent -WebSession $WebSession
    .EXAMPLE
    Receive-GitGubContent -OwnerName mycompany -RepositoryName myrepo
    .EXAMPLE
    Receive-GitGubContent -OwnerName mycompany -RepositoryName myrepo -Path 'directory/test powershell script.ps1'
    .PARAMETER Path (case sensitive)
    GitHub path to a file or folder
    .PARAMETER RepositoryName
    Repository name
    .PARAMETER OwnerName
    Organization or User name
    .PARAMETER WebSession
    WebSession
    .NOTES
        Author: Dmitry Gancho
        Last edit: 10/9/2015
#>
    [CmdLetBinding(DefaultParameterSetName='__AllParameterSets')]
    param (
        [Parameter(Position=0,ParameterSetName='__AllParameterSets')]
        [string]$Path,

        [Parameter(Mandatory,Position=1,ParameterSetName='Repository')]
        [Alias('repo')]
        [string]$RepositoryName,

        [Parameter(Mandatory,Position=2,ParameterSetName='Repository')]
        [Alias('owner')]
        [string]$OwnerName,

        [Parameter(ParameterSetName='__AllParameterSets')]
        [Alias('ws')]
        [Microsoft.PowerShell.Commands.WebRequestSession]$WebSession = (New-GitHubApiSession)
    )

    # construct Url
    $baseurl = 'https://api.github.com'
    if ($PsCmdlet.ParameterSetName -eq 'Repository') {
        # get content from a repo
        $url = "$baseurl/repos/$OwnerName/$RepositoryName/contents/$Path" #`?ref=master"
    } else {
        # get list of accessible repos for the user
        $url = "$baseurl/user/repos"
    }

    # invoke
    try {
        $response = Invoke-RestMethod -Uri $url -Method Get -WebSession $WebSession -ErrorAction Stop
    } catch {
        $errmsg  = "`nURL: $url"
        $errmsg += "`nERROR: " + $Error[0].Exception.Message
        Write-Host $errmsg -ForegroundColor Red
    }

    # if response has content property, this is base64 encoded file content, so convert it
    # and remove '???' as GitHub adds this at the beginning of some files
    $response | % {
        try {
            $_.content = ([System.Text.Encoding]::ASCII.GetString([System.Convert]::FromBase64String($_.content)) -replace '\?\?\?')
            $_.encoding = $null
        } catch {}
    } #%

    return $response
} #function 



function Invoke-GitHubScript {
<#
.SYNOPSIS
    Invoke a script or import a module from GitHub
.DESCRIPTION
    Invoke a .ps1 script or import a .psm1 module from GitHub
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
    Date   : 10/17/2015
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
                $Script:user = Get-ItemProperty -Path $regpath | select -exp UserName
                $Script:pass = Get-ItemProperty -Path $regpath | select -exp Password
                $user -and $pass
            })) {
                $user = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR((ConvertTo-SecureString $user)))
                $pass = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR((ConvertTo-SecureString $pass)))
            } else {
                $cred = Get-Credential -Message 'Enter credential for GitHub:'
                if (-not $cred) {return $null}
                $user = $cred.Username
                $pass = $cred.GetNetworkCredential().Password
                if (-not $user -or -not $pass) {return $null}
                # offer User to save credential
                [void][Reflection.Assembly]::LoadWithPartialName('System.Windows.Forms')
                if ([Windows.Forms.MessageBox]::Show('Save GitHub credtial for future use?','Question',1,'Question') -eq 'OK') {
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
}



function Publish-GitGubFile {
    # IMPORTANT !!!
    # $FilePath is case sensitive
    # Directory created if does not exist
<#
    .SYNOPSIS
    Commits single file to GitHub repository
    .DESCRIPTION
    Commits single file to GitHub repository
    Receive-GitGubContent -OwnerName mycompany -RepositoryName myrepo -Path 'directory/test powershell script.ps1'
    .PARAMETER Path (case sensitive)
    GitHub path to a file or folder
    .PARAMETER SourceFile
    Full path to source file
    .PARAMETER Message
    Commit message
    .PARAMETER DirectoryName
    GitHub directory name
    .PARAMETER RepositoryName
    Repository name
    .PARAMETER OwnerName
    Organization or User name
    .PARAMETER WebSession
    WebSession
    .PARAMETER PassThru
    PassThru
    .PARAMETER Force
    Force
    .NOTES
        Author: Dmitry Gancho
        Last edit: 10/9/2015
#>

    [CmdletBinding(SupportsShouldProcess,ConfirmImpact='High')]
    param (
        [Parameter(Mandatory,Position=0)]
        [Alias('file')]
        [string]$SourceFile,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [Alias('msg')]
        [string]$Message,

        [Alias('dir')]
        [string]$DirectoryName = $null,

        [Parameter(Mandatory)]
        [Alias('repo')]
        [string]$RepositoryName,

        [Parameter(Mandatory)]
        [Alias('owner')]
        [string]$OwnerName,

        [Parameter()]
        [Alias('ws')]
        [Microsoft.PowerShell.Commands.WebRequestSession]$WebSession = (New-GitHubApiSession),

        [Parameter()]
        [switch]$PassThru = $false,

        [Parameter()]
        [switch]$Force = $false
    )

    # get and encrypt file content
    if (Test-Path -Path $SourceFile) {
        $content = (Get-Content -Path $SourceFile) -join "`n"
        $base64 = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($content))
    } else {
        $errmsg = "`nERROR: File not found '$SourceFile'"
        Write-Host $errmsg -ForegroundColor Red
        break
    }

    # get file name and path
    $rootUrl = 'https://api.github.com'
    $fileName = Split-Path -Path $SourceFile -Leaf
    $filePath = if ($DirectoryName) {
        "$DirectoryName/$fileName"
    } else {
        $fileName
    }

    # construct url
    $url = "$rootUrl/repos/$OwnerName/$RepositoryName/contents/$filePath"

    # get SHA if file already exists in GitGub
    try {
        $response1 = Invoke-RestMethod -Uri $url -Method Get -WebSession $WebSession -ErrorAction Stop
        $sha = $response1.sha
    } catch {
        $sha = $null
    }

    #construct body
    $body = @{
        message = $Message
        content = $base64
    }
    # add existing file sha to overwrite it
    if ($sha) {$body.sha = $sha}
    $body = $body | ConvertTo-Json

    # https://developer.github.com/v3/repos/contents/
    # PUT /repos/:owner/:repo/contents/:path
    if ($Force -or $PSCmdlet.ShouldProcess($fullpath)) {
        try {
            $response2 = Invoke-RestMethod -Uri $url -Method Put -Body $body -WebSession $WebSession -ErrorAction Stop
        } catch {
            $errmsg  = "`nURL: $url"
            $errmsg += "`nERROR: " + $Error[0].Exception.Message
            Write-Host $errmsg -ForegroundColor Red
        }
        if ($PassThru) {
            return $response2.content
        } else {
            return $null
        }
    } else {
        return $null
    }
} #function



# *** Aliases and Export ***
Export-ModuleMember -Function *



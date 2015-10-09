
# version 4

[CmdletBinding()] param()

function Hello-World {
    param (
        [string]$msg = 'Hello World'
    )
    Write-Host $msg -ForegroundColor Red
}

Hello-World
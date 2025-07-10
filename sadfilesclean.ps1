<#
.SYNOPSIS
  Deletes the folder named "sadfiles" under a target directory. 

.DESCRIPTION
  The script checks for a child folder called "sadfiles" and removes it from the endpoint.
  By default, the target directory is C:\temp\
  
.PARAMETER o
  Specify a different parent directory.

.EXAMPLE
  .\Remove-SadFiles.ps1           # uses C:\temp\
  .\Remove-SadFiles.ps1 -o D:\Work # uses D:\Work
#>

##PARAMETERS
param(
    [Alias('t', 'Target')]
    [string]$TargetPath = 'C:\temp\'
)

try {
    $TargetPath = (Resolve-Path -Path $TargetPath -ErrorAction Stop).ProviderPath.TrimEnd('\') + '\'
    $sadPath = Join-Path -Path $TargetPath -ChildPath 'sadfiles'

    if (Test-Path -Path $sadPath -PathType Container) {
        Remove-Item -Path $sadPath -Recurse -Force -ErrorAction Stop
    }
}
catch {
}
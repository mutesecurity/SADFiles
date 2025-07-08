<#
.SYNOPSIS
    SADFiles - Safe Acquisition of Dangerous Files
    Collects single files or entire folders into passworded archive containers for safe handling. 
    Designed for Microsoft Defender for Endpoint.
    Learn more at https://github.com/mutesecurity/SADFiles/

.DESCRIPTION
    Collects a specified file or folder for analysis purposes:
    - Validates and logs file metadata.
    - Hashes the input file (MD5, SHA1, SHA256).
    - Archives the file using a portable version of 7-Zip with either a static password ("infected") or one provided by the user.
    - Outputs all logs and final archive to a clean directory.
    - Purges 7Z tools after execution to mitigate LOLBin risk (default behavior).
    - Logs success/failure of each step silently for MDE compatibility.

.PARAMETER f
    Full path of the file or folder to be acquired and archived.
    ALIAS: file, folder, target

.PARAMETER o
    Optional custom location for staging files and output.
    ALIAS: out, output, dest

.PARAMETER p
    Optional custom password for archive containing collected file(s).
    ALIAS: password

.PARAMETER hint
    Optional hint line written to the job log, prepended by "Password Hint:". Intended to help you remember a custom password.

.PARAMETER case
    Optional string written to the job log, prepended by "CASE NUMBER:". Intended for case numbers, ticket numbers, unique reference numbers, etc.
    ALIAS: ticket

.SWITCH nohash
    Optional switch to skip metadata logging and hashing of target file(s). The jog log will still list all filenames being collected.

.SWITCH nocleanup
    Optional switch to skip removal of 7Z files after success. Not recommended.

.EXAMPLE USAGE IN LIVE RESPONSE
    run sadfiles.ps1 -parameters "-f C:\Path\To\File.ext"
    run sadfiles.ps1 -parameters "-f C:\Path\To\Folder"

.AUTHOR
    sam@foren.sx
    https://github.com/mutesecurity     
#>

<#
.CHANGELOG

    VERSION:    1.0.5 (release: 2025/07/08)

    - NEW: Added final packaging step:
            → Combines job log and output archive into a single ZIP named after the host (e.g., HOSTNAME.zip)
            → Prevents overwriting by checking for existing files and appending _1, _2, etc. as needed
            → Moves final ZIP to Output directory
            → Deletes original archive and log after packaging

    - NEW: Added -nohash switch:
            → Skips metadata collection and file hashing
            → Still logs full file paths for transparency
            → Useful for quick or sensitive collections

    - IMPROVED: Readme.txt is now optional — skipped silently if missing

#>

## PARAMETERS & SWITCHES
# Setup parameters and switches.
param(
    [Parameter(Mandatory = $true)]
    [Alias("file", "folder", "target")]
    [string]$f, # Mandatory target file/folder

    [Alias("out", "output", "dest")]
    [string]$o, # Optional custom output location

    [Alias("ticket")]
    [string]$case, # Optional case number line in job log

    [Alias("password")]
    [string]$p = "infected", # Optional custom password

    [string]$hint, # Optional hint line in job log

    [switch]$nocleanup, # Optional switch to disable purging of 7Z files after success

    [switch]$nohash # Optional switch to skip hashing and metadata logging
)


## VARIABLES
# Execution timestamp for logging, file naming
$timestamp = Get-Date -Format "yyyyMMddHHmmss"

# Constants
$scriptVersion = "1.0.5"
$computerName = $env:COMPUTERNAME
$debugging = 0

## PATHS
# Determine base path for staging, output
if ($o) {
    $basePath = Join-Path $o "sadfiles"
} else {
    $basePath = "C:\Temp\sadfiles"
}

# Define paths
$stagingPath = Join-Path $basePath "7Z"
$outputPath = Join-Path $basePath "Output"
$logFile = Join-Path $basePath "${timestamp}_job.log"
$errorLog = Join-Path $basePath "error.log"

## FUNCTIONS
# Logging functions
function Write-ErrorLog {
    param([string]$message)
    if ($debugging -ne 1) { return }
    $entry = "$(Get-Date -Format "yyyyMMddHHmmss") $message"
    Add-Content -Path $errorLog -Value $entry
}

function Write-JobLog {
    param([string]$message)
    Add-Content -Path $logFile -Value $message
}

function Log-FileDetails {
    param([string]$filePath)

    $info = Get-Item $filePath
    $md5 = Get-FileHash -Algorithm MD5 -Path $filePath
    $sha1 = Get-FileHash -Algorithm SHA1 -Path $filePath
    $sha256 = Get-FileHash -Algorithm SHA256 -Path $filePath

    Write-JobLog "=== $filePath ==="
    Write-JobLog "Size: $($info.Length) bytes"
    Write-JobLog "Created: $($info.CreationTime)"
    Write-JobLog "Last Modified: $($info.LastWriteTime)"
    Write-JobLog "MD5 Hash: $($md5.Hash)"
    Write-JobLog "SHA1 Hash: $($sha1.Hash)"
    Write-JobLog "SHA256 Hash: $($sha256.Hash)"
    Write-JobLog "=== End ==="
    Write-JobLog ""
}

# Here we go!

try {
    New-Item -Path $outputPath -ItemType Directory -Force | Out-Null

    # Job header
    Write-JobLog "### Safe Acquisition of Dangerous Files ###"
    Write-JobLog ""
    Write-JobLog "Script version: $scriptVersion"
    Write-JobLog "Host: $computerName"
    Write-JobLog "System Time (Local): $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
    Write-JobLog "System Time (UTC): $(Get-Date -Date ([DateTime]::UtcNow) -Format 'yyyy-MM-dd HH:mm:ss')"
    Write-JobLog "System Timezone: $((Get-TimeZone).Id)"
    if ($case) {
        Write-JobLog "CASE NUMBER: $case"
    }
    if ($hint) {
        Write-JobLog "Password Hint: $hint"
    }
    Write-JobLog "Target specified: $f"
    Write-JobLog "Starting the job..."
    Write-JobLog ""

    # Validate that 7Z.zip is where we expect it to be.
    $sourceZip = "C:\ProgramData\Microsoft\Windows Defender Advanced Threat Protection\Downloads\7Z.zip"
    if (-not (Test-Path -Path $sourceZip)) {
        Write-ErrorLog "7Z.zip not found in $sourceZip. Please check it has been pushed."
        Write-JobLog "ERROR: 7Z.zip not found in $sourceZip. Stopping..."
        Start-Sleep -Seconds 1
        exit 1
    }

    if (-not (Test-Path -Path $f)) {
        Write-ErrorLog "Specified file or folder not found. Please check the path."
        Write-JobLog "ERROR: Specified file or folder not found. Stopping..."
        Start-Sleep -Seconds 1
        exit 1
    }

    Expand-Archive -Path $sourceZip -DestinationPath $basePath -Force
    Write-JobLog "INFO: 7Z.exe found and uncompressed to $stagingPath"

    $readmeSource = Join-Path $stagingPath "Readme.txt"
    $readmeDestination = Join-Path $basePath "Readme.txt"
    if (Test-Path $readmeSource) {
        Move-Item -Path $readmeSource -Destination $readmeDestination -Force
        Write-JobLog "INFO: Readme.txt moved to $readmeDestination"
    } else {
        Write-JobLog "INFO: Readme.txt not found in 7Z archive. Skipping..."
    }

    $item = Get-Item $f
    $isDirectory = $item.PSIsContainer
    if ($isDirectory) {
        Write-JobLog "INFO: Input is a directory."
    } else {
        Write-JobLog "INFO: Input is a single file."
    }
    Write-JobLog ""

    # Iterate files and produce metadata logging for each.
    [int]$fileCount = 0
    if ($isDirectory) {
        $files = Get-ChildItem -Path $f -Recurse -File
        foreach ($subfile in $files) {
            if ($nohash) {
                Write-JobLog "$($subfile.FullName)"
            } else {
                Log-FileDetails -filePath $subfile.FullName
            }
            $fileCount++
        }
    } else {
        if ($nohash) {
            Write-JobLog "$f"
        } else {
            Log-FileDetails -filePath $f
        }
        $fileCount = 1
    }
    Write-JobLog " "
    Write-JobLog "INFO: Total files: $fileCount"
    Write-JobLog " "

    # Archive the target (-f) into a password protected zip file. 
    $ZipExe = Join-Path $stagingPath "7z.exe"
    $compressedZipName = "${timestamp}_output.zip"
    $compressedZip = Join-Path $outputPath $compressedZipName

    & $ZipExe a -tzip -p"$p" -y "$compressedZip" "$f" | Out-Null
    Write-JobLog "INFO: File(s) archived successfully: $compressedZip"
    Write-JobLog ""

    Log-FileDetails -filePath $compressedZip
        
    # Cleanup the 7Z files to mitigate LOLBin risks.
    if (-not $nocleanup) {
        Remove-Item -Path $stagingPath -Recurse -Force -ErrorAction SilentlyContinue
        if (-not (Test-Path $stagingPath)) {
            Write-JobLog "INFO: 7Z run files removed."
        } else {
            Write-JobLog "WARNING: 7Z run files could not be removed. Please remove manually."
        }
    } else {
        Write-JobLog "WARNING: Cleanup skipped: -nocleanup was specified."
    }

    # Tail off the job log.
    Write-JobLog "INFO: Job completed successfully. Packaging output and job log for collection."


    # Create final output archive of both the target file(s) and the job log for easy collection using getfile
    # Determine final ZIP name without overwriting existing files
    $baseName = $computerName
    $counter = 0

    do {
        $suffix = if ($counter -eq 0) { "" } else { "_$counter" }
        $finalZipName = "$baseName$suffix.zip"
        $finalZipPath = Join-Path $outputPath $finalZipName
        $counter++
    } while (Test-Path $finalZipPath)

    Compress-Archive -Path $logFile, $compressedZip -DestinationPath $finalZipPath -Force

    if (Test-Path $finalZipPath) {

    # Cleanup original job log and archive after packaging
        Remove-Item -Path $logFile, $compressedZip -Force -ErrorAction SilentlyContinue
    } else {
        Write-JobLog "WARNING: Final package could not be created. Individual files remain."
    }
}
## UNSPECIFIED ERROR HANDLING
catch {
    Write-ErrorLog "Unexpected error: $($_.Exception.Message)"
    Write-JobLog "ERROR: Unexpected error: $($_.Exception.Message). Stopping..."
    Start-Sleep -Seconds 1
    exit 1
}

# Sleep for 1 second to prevent any cutoff of execution.
Start-Sleep -Seconds 1
exit 0

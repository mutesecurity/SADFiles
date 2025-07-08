# SADFiles
**S**afe **A**cquisition of **D**angerous **Files** - Extract malicious files from endpoints without comprimising the analyst system using Microsoft Defender for Endpoint.

## About
SADFiles is a Powershell script designed for Microsoft Defender for Endpoint. It's primary purpose is to package malicious files on an endpoint into a password protected container so that they can be safely pulled over using getfile. This eliminates the risk of generating further alerts (or frustrating quarantine actions), or, worse still, accidental execution and subsequent infection, on the analyst's own endpoint.

## Preparation
SADFiles relies on a lightweight portable version of 7Zip, which you can - and should - DIY yourself using either the official distribution over at https://www.7-zip.org/ or your organisation's own approved version. Do not rely on prepackaged portable versions out there on the web or you might be surprised by what else comes with it. 

* Download and install 7Zip on any system (again, use only the official distribution or the approved version distributed internally by your own organisation).
* Open the Program Files (default: C:\Program Files\7-Zip) and locate 7z.exe and 7z.dll.
* Copy both of those files to a simple archive named 7Z.zip.
* Upload 7Z.zip to the Microsoft Defender for Endpoint Live Response Library.
* Download sadfiles.ps1 from this repo and upload it to the Microsoft Defender for Endpoint Live Response Library.
* That's it. You're ready to go.

## Execution
* Open a Live Response session with your target endpoint.
* Use `putfile 7Z.zip` to push the portable 7Zip package to the target endpoint.
* To grab a single file, use `run sadfiles.ps1 -parameters "-f C:\Path\To\File.ext"`. Make sure you include the extension at the end.
* To grab an entire directory, use `run sadfiles.ps1 -parameters "-f C:\Path\To\Folder"`.
* In your Live Response session, use `cd C:\Temp\sadfiles` to navigate to the sadfiles folder.
* The timestamped job log will be present here. Any errors that occured during runtime are detailed inside, as well as some limited metadata on the file(s) collected (including MD5, SHA1 and SHA256 hashes).
* To recover your output, use the `getfile` command in Live Response to retrieve the archive file within C:\Temp\sadfiles\Output.
* NOTE: The script will remove the 7Zip files automatically on success by default.

## Advanced/Optional Features
* A custom path for staging and output can be defined with `-o`.
* A custom password and password hint can be defined with `-p` and `-hint` respectively.
* You can add a case or ticket number to the job log with `-case` or `-ticket`.
* Hashing large files got you down? Save that pain for Future You with `-nohash`.
* Adding `-nocleanup` to your `run sadfiles.ps1` parameters will skip cleaning up the 7Zip files on the endpoint.
* You can include a text file named "ReadMe.txt" to your 7Z.zip. This will be copied to the sadfiles folder on execution of sadfiles.ps1.

## All Parameters

Current:

| Parameter | Mandatory/Optional | Description |
| --- | --- | --- |
| `-f` | Mandatory | Full path for target file/folder, including file extension (if applicable). |
| `-o` | Optional | Path for staging and output. Defaults to C:\Temp\ |
| `-p` | Optional | Declare a custom password for the archive file. Defaults to "infected". |
| `-hint` | Optional | Write a password hint to the log file. Use ' ' if this contains spaces|

| Switch | Mandatory/Optional | Description |
| --- | --- | --- |
| `-nocleanup` | Optional | Do not delete 7Z execution files from staging directory. Not recommended. |
| `-nohash` | Optional | Skip hashing of the target |

Planned:

| Parameter | Mandatory/Optional | Description |
| --- | --- | --- |
| `-list` | Optional | Used instead of -f. Provide a text file of file paths (seperated by line breaks) as targets. |

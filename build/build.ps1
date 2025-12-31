<#
    .SYNOPSIS
        Builds a PowerShell script that is a self-contained SQLite environment.
    .DESCRIPTION
        Builds a self-contained SQLite environment in the form of a PowerShell script
        that acts as the user interface, along with a database engine and database stored 
        in Alternate Data Streams on the PowerShell script file.
    .INPUTS
        SQLite3.exe
    .OUTPUTS
        main.ps1
    .NOTES
        This utility is for educational purposes only. It should not be considered production-ready,
        best practice, or used for any malicious purpose.
#>

#region SQLITE ENCODING
# update these paths based on your source sqlite3.exe file and desired output location
# TODO: Parameterize this?
try {
    $exePath = "C:\Users\Administrator\Desktop\sqlite3.exe"
    $targetScript = "C:\Users\Administrator\Desktop\main.ps1"
    $fileBytes = [System.IO.File]::ReadAllBytes($exePath)
    $base64 = [Convert]::ToBase64String($fileBytes)
    Write-Host "[BUILD][INF][$(Get-Date -Format FileDateTimeUniversal)]: Encoded SQLite3.exe" -ForegroundColor Green
}
catch {
    Write-Host "[BUILD][ERR][$(Get-Date -Format FileDateTimeUniversal)]: Failed to encode SQLite3.exe" -ForegroundColor Red
    exit 1
}
#endregion SQLITE ENCODING

#region SCRIPT TEMPLATE
# main.ps1 script template
$ScriptBody = @'
param(
    [Parameter(Mandatory=$false)] [string]$Query,
    [Parameter(Mandatory=$false)] [switch]$Help
)

function Show-AppHelp {
@"
# main.ps1

## SYNOPSIS 
A self-contained SQLite database environment.

## DESCRIPTION 
main.ps1 is a PowerShell script that acts as a user interface for a SQLite database.

This solution makes use of several NTFS Alternate Data Streams to store the database
and the database engine in ADSes of the PowerShell script file on disk. The default data
stream contains the content of the PowerShell script while the :DatabaseEngine stream
contains a Base64-encoded binary of the sqlite3.exe and the :DatabaseData stream contains
the actual SQLite database file.

Database schema is dynamic and automatically handled. If you insert a record into a table
that does not exist, it will automatically be created with the columns specified in your
insert operation.

Querying the database returns a DatabaseRecord object that supports being piped to other
PowerShell cmdlets and functions.

## USAGE
### Example 1 - Insert operations
```powershell
.\main.ps1 -Query "INSERT INTO TableName (Column1, Column2) VALUES ('Value1', 'Value2');"
```

Doing this will also automatically create the table specified with the columns specified
if the table does not already exist.

No output is provided upon successful insertion.

### Example 2 - Select operations
```powershell
.\main.ps1 -Query "SELECT * FROM TableName"
```

The output is a DatabaseRecord object (or array of DatabaseRecord objects, if multiple
items are returned). These objects support normal PowerShell operations and pipeline
functionality.

Example output:
```output
ID  Col1    Col2    CreationTime
--  ----    ----    ------------
1   Value1  Value2  12/31/2025 6:53:05 PM
```

## COMPONENTS AND ARTIFACTS
### Persistent Artifacts
These are the only things that stay on the disk permanently after the script finishes.

Script File (main.ps1):
Main stream: Contains the PowerShell code and the Base64-encoded SQLite engine.
Data stream: (main.ps1:Data): A hidden NTFS Alternate Data Stream containing the actual binary SQLite database file. This grows as you add rows.

Win32Ghost Type:
Once the script runs in a session, the Win32Ghost .NET type is stored in the PowerShell process's memory (AppDomain).

### Ephemeral Artifacts
When you strike Enter on a -Query command, the following artifacts appear. They are deleted when the query finishes.

Temporary Engine ($env:TEMP\sqlite_[GUID].exe):
A unique, randomly named executable. This is the binary that handles the SQL logic. It only lives for the duration of the Invoke-SQLiteQuery function.

Session Database ($env:TEMP\db_[GUID].db):
A temporary working copy of your database. SQLite requires a physical file to perform locking and writes. We extract the binary data from the ADS to this file, modify it, and then push the results back to the ADS.

#### Sub-Processes
If you check Task Manager or Get-Process at the exact right millisecond, you will see a process named sqlite_[GUID].exe running as a child of your PowerShell host.

### System Processes & Events
Beyond just files, the system registers the following activities:  
  - Process Creation Events: If you have Audit Process Creation (Event ID 4688) or Sysmon enabled, the OS will log the start and stop of the GUID-named executable.
  - Antimalware Scan Interface (AMSI): Windows Defender will scan the Base64 string as it is decoded in memory and scan the temporary .exe as it is written to the $env:TEMP folder.
  - NTFS Log Transactions: The filesystem logs the creation of the temp files and the update to the named data stream on the script.
  
| Artifact      | Location               | Persistence   | Purpose                                       |
| ------------- | ---------------------- | ------------- | --------------------------------------------- |
| SQL Database  | main.ps1:Data          | Permanent     | Reliable relational storage inside the script |
| Engine Binary | $env:TEMP\sqlite_*.exe | Ephemeral     | Active processing of SQL commands             |
| Working DB    | $env:TEMP\db_*.db      | Ephemeral     | Required for SQLite's ACID compliance         |
| Win32 Logic   | Memory (RAM)           | Session-based | High-speed I/O bridge to bypass PS overhead   |
"@
  
}

# if no param or -help specified, display help
if ( $help -or $PSBoundParameters.Keys.Count -eq 0 ) {
    Show-AppHelp
}

# --- WIN32 IO HANDOFF (PS 5.1 & 7+ Compatible) ---
if ( -not ([System.Management.Automation.PSTypeName]'Win32Ghost').Type ) {
    Add-Type -TypeDefinition @"
    using System;
    using System.IO;
    using System.Runtime.InteropServices;
    using Microsoft.Win32.SafeHandles;

    public class Win32Ghost {
        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        public static extern SafeFileHandle CreateFile(
            string lpFileName, uint dwDesiredAccess, uint dwShareMode,
            IntPtr lpSecurityAttributes, uint dwCreationDisposition,
            uint dwFlagsAndAttributes, IntPtr hTemplateFile);

        public static byte[] ReadAds(string path) {
            SafeFileHandle handle = CreateFile(path, 0x80000000, 7, IntPtr.Zero, 3, 0, IntPtr.Zero);
            if (handle.IsInvalid) return new byte[0];
            using (FileStream fs = new FileStream(handle, FileAccess.Read)) {
                byte[] b = new byte[fs.Length];
                fs.Read(b, 0, (int)fs.Length);
                return b;
            }
        }

        public static void WriteAds(string path, byte[] data) {
            SafeFileHandle handle = CreateFile(path, 0x40000000, 7, IntPtr.Zero, 4, 0, IntPtr.Zero);
            if (handle.IsInvalid) throw new Exception("Win32 Error: " + Marshal.GetLastWin32Error());
            using (FileStream fs = new FileStream(handle, FileAccess.Write)) {
                fs.SetLength(data.Length);
                fs.Write(data, 0, data.Length);
            }
        }
    }
"@
}

# databaserecord class declaration
# this is the type of object returned when you query the database
class DatabaseRecord {
    hidden [datetime]$_RetrievedAt
    DatabaseRecord([hashtable]$row) {
        $this._RetrievedAt = [datetime]::Now
        if ( $row.ContainsKey('ID') ) {
            Add-Member -InputObject $this -NotePropertyName 'ID' -NotePropertyValue ([int32]$row['ID']) 
        }
        foreach ($key in $row.Keys) { 
            if ($key -notin @('ID', 'CreatedAt')) { 
                Add-Member -InputObject $this -NotePropertyName $key -NotePropertyValue $row[$key] 
            } 
        }
        if ($row.ContainsKey('CreatedAt')) { 
            Add-Member -InputObject $this -NotePropertyName 'CreatedAt' -NotePropertyValue ([datetime]::Parse($row['CreatedAt'])) 
        }
    }
}

function Invoke-SQLiteQuery {
    param([string]$SqlStatement)
    $SQLiteBase64 = 'PLACEHOLDER'
    $CurrentScript = (Get-Item $PSCommandPath).FullName
    
    # Generate unique Temp paths for this specific execution
    $UniqueId = [guid]::NewGuid().Guid
    $TempExe = Join-Path $env:TEMP "sqlite_$($UniqueId).exe"
    $TempDb  = Join-Path $env:TEMP "db_$($UniqueId).db"

    try {
        $Bytes = [Convert]::FromBase64String($SQLiteBase64)
        [System.IO.File]::WriteAllBytes($TempExe, $Bytes)
        $dbBytes = [Win32Ghost]::ReadAds($CurrentScript + ":Data")
        if ($dbBytes.Length -gt 0) { [System.IO.File]::WriteAllBytes($TempDb, $dbBytes) }

        # schema is automatically handled
        # if a table does not exist, it is created
        if ($SqlStatement -match "INSERT\s+INTO\s+(\w+)\s*\((.*?)\)\s+VALUES") {
            $Table = $Matches[1]
            $Cols = $Matches[2] -split ',' | ForEach-Object { "$($_.Trim()) TEXT" }
            $SqlStatement = "CREATE TABLE IF NOT EXISTS $Table (ID INTEGER PRIMARY KEY AUTOINCREMENT, $($Cols -join ', '), CreatedAt DATETIME DEFAULT CURRENT_TIMESTAMP);`n" + $SqlStatement
        }

        if ($SqlStatement -match "^\s*SELECT") {
            $rawOutput = & $TempExe -csv -header $TempDb $SqlStatement
            if ($rawOutput) {
                $csvData = $rawOutput | ConvertFrom-Csv
                foreach ($row in $csvData) {
                    $hash = @{}
                    $row.psobject.properties | ForEach-Object { $hash[$_.Name] = $_.Value }
                    [DatabaseRecord]::new($hash)
                }
            }
        } else {
            & $TempExe -header -column $TempDb $SqlStatement
            
            if (Test-Path $TempDb) {
                [Win32Ghost]::WriteAds($CurrentScript + ":Data", [System.IO.File]::ReadAllBytes($TempDb))
            }
        }
    } finally {
        if (Test-Path $TempExe) { Remove-Item $TempExe -Force -ErrorAction SilentlyContinue }
        if (Test-Path $TempDb) { Remove-Item $TempDb -Force -ErrorAction SilentlyContinue }
    }
}

if ($Query) { 
    Invoke-SQLiteQuery -SqlStatement $Query
}
'@
#endregion SCRIPT TEMPLATE

#region OUTPUT
# write main.ps1 and its content
try {
    $FinalCode = $ScriptBody.Replace('PLACEHOLDER', $base64)
    [System.IO.File]::WriteAllText($targetScript, $FinalCode)
    Write-Host "[BUILD][INF][$(Get-Date -Format FileDateTimeUniversal)]: Success!" -ForegroundColor Green
    Write-Host "[BUILD][INF][$(Get-Date -Format FileDateTimeUniversal)]: Self-contained database file located at $targetScript" -ForegroundColor Green
}
catch {
    Write-Host "[BUILD][ERR][$(Get-Date -Format FileDateTimeUniversal)]: Failed to build self-contained database file" -ForegroundColor Red
}
#endregion OUTPUT

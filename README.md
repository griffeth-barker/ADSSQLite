![](/images/ADSSQLite-NoBg-128x128.png)  
  
# ADSSQLite
A SQLite engine, database, and interface contained in a single PowerShell file using NTFS Alternate Data Streams.

> ⚠️  **WARNING**  
> The contents of this repository is for educational purposes only. It should not be considered production-ready, best-practice, etc.
> You should fully understand code before you run it in your system, and you should have authorization to run code on your system.
> The contents of this repository *may* trigger endpoint protection and antivirus, though the contents as published to this repository
> are not malicious.

  
## Getting Started
  1. Download `build.ps1`
  2. Update `$exePath` to reflect the location of your sqlite3.exe binary
  3. Update `$targetScript` to reflect where you'd like the `main.ps1` script to be output
  4. Run `.\build.ps1` to build the script.

## Usage
### Examples
#### Insert operations
```powershell
.\main.ps1 -Query "INSERT INTO TableName (Column1, Column2) VALUES ('Value1', 'Value2');"
```

Doing this will also automatically create the table specified with the columns specified
if the table does not already exist.

No output is provided upon successful insertion.

#### Select operations
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

### COMPONENTS AND ARTIFACTS
#### Persistent Artifacts
These are the only things that stay on the disk permanently after the script finishes.

**Script File** (`main.ps1`):
Main stream: Contains the PowerShell code and the Base64-encoded SQLite engine.
Data stream: (`main.ps1:Data`): A hidden NTFS Alternate Data Stream containing the actual binary SQLite database file. This grows as you add rows.

**Win32Ghost Type**:
Once the script runs in a session, the Win32Ghost .NET type is stored in the PowerShell process's memory (AppDomain).

### Ephemeral Artifacts
When you strike Enter on a -Query command, the following artifacts appear. They are deleted when the query finishes.

**Temporary Engine** (`$env:TEMP\sqlite_\[GUID\].exe`):
A unique, randomly named executable. This is the binary that handles the SQL logic. It only lives for the duration of the Invoke-SQLiteQuery function.

**Session Database** (`$env:TEMP\db_\[GUID\].db`):
A temporary working copy of your database. SQLite requires a physical file to perform locking and writes. We extract the binary data from the ADS to this file, modify it, and then push the results back to the ADS.

##### Sub-Processes
If you check Task Manager or Get-Process at the exact right millisecond, you will see a process named `sqlite_\[GUID\].exe` running as a child of your PowerShell host.

#### System Processes & Events
Beyond just files, the system registers the following activities:  
  - Process Creation Events: If you have Audit Process Creation (Event ID 4688) or Sysmon enabled, the OS will log the start and stop of the GUID-named executable.
  - Antimalware Scan Interface (AMSI): Windows Defender will scan the Base64 string as it is decoded in memory and scan the temporary .exe as it is written to the `$env:TEMP` folder.
  - NTFS Log Transactions: The filesystem logs the creation of the temp files and the update to the named data stream on the script.
  
| Artifact      | Location               | Persistence   | Purpose                                       |
| ------------- | ---------------------- | ------------- | --------------------------------------------- |
| SQL Database  | main.ps1:Data          | Permanent     | Reliable relational storage inside the script |
| Engine Binary | $env:TEMP\sqlite_*.exe | Ephemeral     | Active processing of SQL commands             |
| Working DB    | $env:TEMP\db_*.db      | Ephemeral     | Required for SQLite's ACID compliance         |
| Win32 Logic   | Memory (RAM)           | Session-based | High-speed I/O bridge to bypass PS overhead   |

## Feedback  
Please ⭐ star this repository if it is helpful. Constructive feedback is always welcome, as are pull requests.
Feel free to open an issue on the repository if needed.

# Investigation Notes

## Investigation Directory

All test activity was performed inside:

`C:\FileRenameLab`

This directory was created specifically for the investigation.

## Test Files

The following files were created:

- `Report.txt`
- `Finance.csv`
- `Notes.log`
- `Document1.txt`
- `Document2.txt`
- `Document3.txt`

The files contained harmless test information.

## Baseline Collection

Before performing the file manipulation, the initial file state was collected.

Command:

`Get-ChildItem "C:\FileRenameLab" -File | Select-Object Name, Extension, Length, CreationTime, LastWriteTime`

This provided the original filenames, extensions, file sizes, and timestamps.

## Baseline Hash Collection

SHA256 hashes were collected using:

`Get-ChildItem "C:\FileRenameLab" -File | Get-FileHash -Algorithm SHA256`

The hashes provided a reference point for determining whether file contents changed after the filename manipulation.

## Normal File Renaming

The first operation involved a normal filename change:

`Report.txt`

was renamed to:

`Report-Final.txt`

The file extension remained `.txt`.

This demonstrated ordinary file organization behavior before the suspicious-looking extension manipulation was introduced.

## Extension Manipulation

The next stage changed the extensions by appending `.locked`.

For example:

`Finance.csv`

was renamed to:

`Finance.csv.locked`

Another example was:

`Notes.log`

renamed to:

`Notes.log.locked`

The purpose was to simulate a filename pattern that could appear during ransomware-style activity.

## Bulk File Renaming

Additional test files were created:

`Document1.txt`

`Document2.txt`

`Document3.txt`

These were renamed to:

`Document1.locked`

`Document2.locked`

`Document3.locked`

The bulk operation was useful because large-scale or repeated file manipulation can be more significant during a real investigation than an isolated filename change.

## Content Verification

After the files were renamed, their contents were checked.

For example:

`Get-Content "C:\FileRenameLab\Finance.csv.locked"`

The original test content remained readable.

This demonstrated that the extension change did not automatically mean that the file was encrypted.

## Hash Verification

The SHA256 hash of a renamed file was collected again.

Example:

`Get-FileHash "C:\FileRenameLab\Finance.csv.locked" -Algorithm SHA256`

The result was compared against the original hash collected before renaming.

If the hash remains identical, the evidence supports the conclusion that the file contents did not change.

## Sysmon Event ID 1

Sysmon Event ID 1 was observed through Event Viewer.

The event was reviewed to identify the process responsible for the controlled activity.

Relevant fields include:

- Timestamp
- Image
- CommandLine
- ParentImage
- User
- Process ID
- Process GUID

The process telemetry provides context around how the file manipulation was executed.

## PowerShell Event ID 4104

PowerShell Event ID 4104 was observed through Event Viewer.

The event was reviewed for PowerShell script activity associated with the file-renaming commands.

Potentially useful information includes:

- Timestamp
- Script content
- Rename-Item activity
- FileRenameLab path
- PowerShell execution context

This provides more detailed script-level evidence than process creation alone.

## Sysmon Event ID 3

Sysmon Event ID 3 was obtained through PowerShell.

The event was reviewed for network activity occurring around the file-manipulation timeframe.

Relevant information includes:

- Timestamp
- Process
- Source address
- Destination address
- Destination port
- Protocol

Network activity was treated as supporting evidence rather than proof of file transfer or exfiltration.

## Security Event ID 4688

Windows Security Event ID 4688 was investigated but was not successfully obtained for the PowerShell activity.

This created an evidence gap in the investigation.

The absence of 4688 was documented rather than treated as proof that no process creation occurred.

Sysmon Event ID 1 and PowerShell Event ID 4104 provided alternative process and script-level evidence.

## Evidence Correlation

The investigation correlated multiple evidence sources:

`File-System State`

`↓`

`File Hash`

`↓`

`PowerShell Execution`

`↓`

`Sysmon Event ID 1`

`↓`

`PowerShell Event ID 4104`

`↓`

`Sysmon Event ID 3`

The timestamps were used to determine whether the telemetry represented the same controlled activity.

## Investigation Questions

The following questions guided the analysis:

### What files changed?

The investigation compared the original and resulting filenames.

### Did the extensions change?

Several files received the `.locked` extension.

### Did the contents change?

Content verification showed that the test data remained readable.

### Did the hashes change?

Hash comparison was used to determine whether the underlying contents changed.

### Which process performed the operation?

Sysmon Event ID 1 was used for process-level evidence.

### Was PowerShell involved?

PowerShell Event ID 4104 provided script-level evidence.

### Was network communication observed?

Sysmon Event ID 3 was reviewed for network activity around the execution timeframe.

### Was Security 4688 available?

No relevant Security Event ID 4688 was successfully obtained.


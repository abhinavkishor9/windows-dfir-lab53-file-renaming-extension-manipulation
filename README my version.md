# windows-dfir-lab53-file-renaming-extension-manipulation
## Overview

File renaming means changing the name of an existing file without necessarily changing its contents.

For example:

invoice.pdf
    ↓
invoice.pdf.locked

or:

report.docx
    ↓
report.docx.encrypted

Extension manipulation specifically involves changing the part of the filename that tells Windows what type of file it is.

For example:

document.txt
    ↓
document.exe

The important point is:

Changing a file's extension does not automatically change the underlying file format.

A text file renamed from:

notes.txt

to:

notes.jpg

is still a text file internally. Only its filename changed.

File renaming can be completely legitimate.

For example:

report.docx
    ↓
report-final.docx

is normal user activity.

But large-scale or unusual renaming can be suspicious.

For example:

document1.docx → document1.locked
document2.xlsx → document2.locked
photo1.jpg     → photo1.locked
photo2.jpg     → photo2.locked

If this happens across hundreds or thousands of files, particularly around ransomware activity, it becomes much more concerning.

An attacker may rename files to:

Make files appear encrypted.
Hide the original file type.
Disrupt normal user access.
Mark files that have already been processed.
Make malicious files appear less suspicious.
Obscure evidence during an attack.

Don't investigate only the new filename.

We want to establish:

Original file
     ↓
What changed?
     ↓
New filename
     ↓
Which process performed it?
     ↓
Which user performed it?
     ↓
When did it happen?
     ↓
Were the file contents actually changed?

This distinction is extremely important.

For example:

report.docx → report.locked

does not prove that the file was encrypted.

We need additional evidence to determine whether:

Only the filename changed.
The file contents changed.
The file was replaced.
The file was encrypted.
The file was deleted and recreated.


This lab investigates file renaming and extension manipulation from a Windows DFIR perspective. The investigation focuses on determining whether changes to filenames represent normal file organization, suspicious activity, or behavior that may be associated with ransomware or other malicious activity.

A controlled set of test files was created inside a dedicated investigation directory. The files were renamed and their extensions were manipulated to simulate suspicious file activity. File metadata, file contents, and SHA256 hashes were then compared before and after the changes.

Endpoint telemetry was also reviewed to identify the processes and PowerShell activity associated with the file manipulation. Sysmon Event ID 1, PowerShell Event ID 4104, and Sysmon Event ID 3 were available during the investigation. Windows Security Event ID 4688 was not successfully obtained and was therefore treated as an evidence gap.

## Lab Objectives

- Establish a before-and-after view of files involved in a suspicious rename operation.
- Determine whether the activity affected only filenames/extensions or the actual file contents.
- Use file hashes to provide evidence of whether a file's contents remained unchanged after renaming.
- Examine how individual and bulk file renaming can appear during a Windows investigation.
- Correlate file-manipulation activity with the process that initiated it.
- Examine PowerShell activity to identify commands associated with the file changes.
- Review available endpoint telemetry and determine which evidence sources provide the strongest support for the investigation.
- Assess whether any observed network activity occurred around the file-manipulation timeframe.
- Identify the difference between an unusual file extension and evidence of actual file encryption.
- Document missing or unavailable telemetry, including situations where an expected event cannot be obtained.
- Build an evidence-based sequence of events using timestamps from the available logs.
- Produce a defensible conclusion without assuming that suspicious-looking filenames automatically indicate ransomware.


## Investigation Scenario

A Windows workstation contains several documents in a user directory. The SOC receives an alert after multiple files suddenly appear with unfamiliar extensions.

The analyst needs to determine whether the activity represents:

Normal file organization.
A legitimate administrative script.
A test or automation process.
Suspicious file manipulation.
Possible ransomware-style activity.

The investigation must determine which process renamed the files, which account performed the activity, what changed, and whether the contents were modified or only the filenames.

## Lab Environment

- Operating System: Windows
- Investigation Type: Windows DFIR
- Primary Tools:
  - PowerShell
  - Event Viewer
  - Sysmon
  - Get-FileHash
- Controlled Investigation Directory:

`C:\FileRenameLab`

## Evidence Sources

### Sysmon Event ID 1

Sysmon Event ID 1 was observed through Event Viewer.

It was used to investigate process creation associated with the controlled file-manipulation activity.

Relevant information may include:

- Process Image
- Command Line
- Parent Image
- User
- Process ID
- Process GUID
- Timestamp

### PowerShell Event ID 4104

PowerShell Event ID 4104 was observed through Event Viewer.

It was used to investigate PowerShell script activity associated with the file-renaming operations.

Relevant information may include:

- Script content
- Timestamp
- PowerShell execution context
- Commands related to file manipulation

### Sysmon Event ID 3

Sysmon Event ID 3 was obtained through PowerShell.

It was reviewed to identify network connections occurring around the investigation timeframe.

Relevant information may include:

- Process
- Source IP
- Destination IP
- Destination port
- Protocol
- Timestamp

### Windows Security Event ID 4688

Security Event ID 4688 was investigated but was not successfully obtained for the PowerShell activity.

This was documented as an evidence gap rather than assuming that process creation telemetry was available from the Windows Security log.

## Controlled Test Files

The following types of files were created for the investigation:

- `Report.txt`
- `Finance.csv`
- `Notes.log`
- `Document1.txt`
- `Document2.txt`
- `Document3.txt`

The files contained harmless test data.

## File Manipulation Performed

A normal filename change was first performed:

`Report.txt`

to:

`Report-Final.txt`

Extension manipulation was then simulated:

`Finance.csv`

to:

`Finance.csv.locked`

and:

`Notes.log`

to:

`Notes.log.locked`

Additional test documents were renamed in bulk:

`Document1.txt` → `Document1.locked`

`Document2.txt` → `Document2.locked`

`Document3.txt` → `Document3.locked`

These operations were performed only against the controlled lab files.

## Baseline Collection

Before file manipulation, file metadata was collected using:

`Get-ChildItem "C:\FileRenameLab" -File | Select-Object Name, Extension, Length, CreationTime, LastWriteTime`

SHA256 hashes were also collected:

`Get-ChildItem "C:\FileRenameLab" -File | Get-FileHash -Algorithm SHA256`

The baseline was used for comparison after the files were renamed.

## File Content Verification

After extension manipulation, the contents of renamed files were checked using commands such as:

`Get-Content "C:\FileRenameLab\Finance.csv.locked"`

The content remained readable because the simulation changed the filename rather than encrypting the underlying data.

## Hash Comparison

The SHA256 hash of a renamed file was compared with its original hash.

The purpose was to determine whether the file contents changed.

The forensic principle demonstrated by the lab was:

`Same content + different filename = same SHA256 hash`

Therefore, if the hash remains unchanged after a filename change, the evidence supports file renaming rather than content modification.

## Investigation Workflow

1. Created the controlled investigation directory.
2. Created harmless test files.
3. Collected baseline metadata.
4. Collected baseline SHA256 hashes.
5. Renamed a file normally.
6. Manipulated file extensions.
7. Performed controlled bulk renaming.
8. Verified the contents of renamed files.
9. Compared file hashes.
10. Investigated Sysmon Event ID 1.
11. Investigated PowerShell Event ID 4104.
12. Investigated Sysmon Event ID 3.
13. Attempted to identify Security Event ID 4688.
14. Documented the inability to obtain the expected 4688 event.
15. Correlated available telemetry with the file-manipulation timeframe.
16. Assessed whether the evidence supported renaming or content modification.

## Observed Telemetry

| Source | Event ID | Status | Purpose |
|---|---:|---|---|
| Sysmon | 1 | Observed | Process creation |
| PowerShell | 4104 | Observed | Script Block Logging |
| Sysmon | 3 | Observed | Network connection |
| Windows Security | 4688 | Not obtained | Process creation |


## MITRE ATT&CK Relevance

The investigation may be relevant to:

**T1059.001 — PowerShell**

when PowerShell is used to perform file manipulation.

File and directory manipulation may also be relevant to broader attack behaviors depending on the actual context and intent.

ATT&CK mapping should be based on observed behavior and supporting evidence rather than the presence of a filename extension alone.

## Evidence Gap — Event ID 4688

Windows Security Event ID 4688 was not successfully obtained during the investigation.

This means the investigation could not use Security 4688 as supporting process-creation evidence for the controlled PowerShell activity.

The available evidence instead relied on:

- Sysmon Event ID 1
- PowerShell Event ID 4104
- Sysmon Event ID 3
- File metadata
- File contents
- SHA256 hashes

The absence of 4688 should not be interpreted as evidence that the process did not execute.

## Investigation Limitations

The lab was performed using controlled test files rather than real user or organizational data.

The investigation also depended on the telemetry available on the test system. Security Event ID 4688 was not available for the relevant PowerShell activity.

Sysmon and PowerShell logging configurations can also affect which events are generated and what information they contain.


## Disclaimer

This investigation was performed in a controlled environment using harmless test files. No real organizational files were intentionally modified, encrypted, or destroyed.

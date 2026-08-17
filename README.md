# Windows DFIR Lab 53 — File Renaming / Extension Manipulation Investigation

## Overview

This lab investigates file renaming and extension manipulation from a Windows DFIR perspective. The investigation focuses on determining whether changes to filenames represent normal file organization, suspicious activity, or behavior that may be associated with ransomware or other malicious activity.

A controlled set of test files was created inside a dedicated investigation directory. The files were renamed and their extensions were manipulated to simulate suspicious file activity. File metadata, file contents, and SHA256 hashes were then compared before and after the changes.

Endpoint telemetry was also reviewed to identify the processes and PowerShell activity associated with the file manipulation. Sysmon Event ID 1, PowerShell Event ID 4104, and Sysmon Event ID 3 were available during the investigation. Windows Security Event ID 4688 was not successfully obtained and was therefore treated as an evidence gap.

## Lab Objectives

- Understand the forensic significance of file renaming and extension manipulation.
- Establish a baseline before modifying test files.
- Identify changes between original and modified filenames.
- Determine whether file extensions were changed.
- Verify whether file contents were modified.
- Use SHA256 hashes to compare file state before and after renaming.
- Identify the process responsible for the controlled file manipulation.
- Analyze PowerShell Script Block Logging.
- Review Sysmon process-creation telemetry.
- Review Sysmon network-connection telemetry.
- Document telemetry limitations when expected Windows events are unavailable.
- Distinguish file renaming from actual file encryption or content modification.

## Investigation Scenario

A Windows workstation is suspected of experiencing unusual file activity after several files begin appearing with unfamiliar extensions. The SOC analyst must determine whether the activity represents legitimate file organization, an automated process, or potentially malicious behavior.

A controlled simulation was performed using harmless files in a dedicated investigation directory. Several files were renamed and their extensions were changed to simulate suspicious activity. The investigation then used file metadata, file contents, hashes, PowerShell logging, and Sysmon telemetry to determine what actually changed.

The investigation specifically focuses on whether the files were merely renamed or whether their underlying contents were also modified.

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

## Key Findings

- Controlled test files were successfully renamed.
- Several file extensions were changed to `.locked`.
- The renamed files remained readable.
- File hashes could be used to determine whether file contents changed.
- Sysmon Event ID 1 was observed.
- PowerShell Event ID 4104 was observed.
- Sysmon Event ID 3 was obtained through PowerShell.
- Windows Security Event ID 4688 was not successfully obtained for the PowerShell activity.
- The absence of Event ID 4688 was documented as a telemetry limitation.
- The observed filename changes alone do not prove that ransomware or encryption occurred.

## DFIR Interpretation

File renaming and extension manipulation can be legitimate or malicious depending on the context. A small number of manually renamed files may represent normal user activity, while large-scale renaming to unusual extensions can be a useful indicator during a ransomware investigation.

However, an unusual extension does not prove that the file contents were encrypted. In this lab, the files were renamed without modifying their underlying contents. Hash comparison and content verification provided evidence supporting this conclusion.

The investigation therefore demonstrates why analysts should correlate file-system evidence with process and PowerShell telemetry rather than relying only on filenames.

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

## Conclusion

This investigation demonstrated how suspicious file renaming and extension manipulation can be analyzed without relying solely on the filename. The controlled files were renamed and assigned unfamiliar extensions, but their contents remained unchanged. File hashes and content verification provided evidence that the simulation involved filename manipulation rather than encryption.

Sysmon Event ID 1, PowerShell Event ID 4104, and Sysmon Event ID 3 provided supporting endpoint telemetry. Although Security Event ID 4688 was not successfully obtained, the remaining evidence was sufficient to reconstruct the controlled activity and demonstrate the importance of correlating file-system evidence with process and PowerShell telemetry.

## Skills Demonstrated

- Windows DFIR
- File-System Investigation
- File Renaming Analysis
- Extension Manipulation Analysis
- PowerShell Investigation
- SHA256 Hash Comparison
- Sysmon Event ID 1 Analysis
- Sysmon Event ID 3 Analysis
- PowerShell Event ID 4104 Analysis
- Event Viewer
- Timeline Construction
- Evidence Correlation
- Telemetry Gap Documentation
- Ransomware Behavior Analysis

## Disclaimer

This investigation was performed in a controlled environment using harmless test files. No real organizational files were intentionally modified, encrypted, or destroyed.

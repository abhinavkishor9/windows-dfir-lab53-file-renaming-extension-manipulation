# Timeline — Lab 53 File Renaming / Extension Manipulation Investigation

## Timeline Purpose

This timeline documents the sequence of actions performed during the controlled file-renaming and extension-manipulation investigation.

Actual timestamps from Event Viewer should be inserted where available.

## Investigation Timeline

| Order | Source | Activity | Significance |
|---:|---|---|---|
| 1 | File System | `C:\FileRenameLab` created | Establishes controlled investigation workspace |
| 2 | File System | Test files created | Provides harmless investigation artifacts |
| 3 | File System | Baseline metadata collected | Establishes original file state |
| 4 | File System | Baseline SHA256 hashes collected | Establishes original content state |
| 5 | File System | `Report.txt` renamed to `Report-Final.txt` | Demonstrates normal file renaming |
| 6 | File System | `Finance.csv` renamed to `Finance.csv.locked` | Simulates extension manipulation |
| 7 | File System | `Notes.log` renamed to `Notes.log.locked` | Simulates suspicious-looking extension change |
| 8 | File System | Additional document files created | Provides multiple files for bulk manipulation |
| 9 | File System | Multiple `.txt` files renamed to `.locked` | Simulates bulk file renaming |
| 10 | File System | Renamed file contents checked | Determines whether files remain readable |
| 11 | File System | SHA256 hashes checked again | Determines whether underlying contents changed |
| 12 | Event Viewer | Sysmon Event ID 1 observed | Provides process creation evidence |
| 13 | Event Viewer | PowerShell Event ID 4104 observed | Provides PowerShell script-level evidence |
| 14 | PowerShell | Sysmon Event ID 3 queried | Provides network connection evidence |
| 15 | Event Viewer | Security Event ID 4688 investigated | Expected process telemetry not successfully obtained |
| 16 | DFIR Analysis | Available telemetry correlated | Connects process, script, network, and file activity |
| 17 | DFIR Analysis | Before/after file state compared | Determines actual file changes |
| 18 | DFIR Analysis | Final assessment completed | Distinguishes renaming from content modification |

## Baseline State

Before file manipulation, the investigation collected:

- Filename
- Extension
- File size
- Creation time
- Last write time
- SHA256 hash

This established the original state of the controlled files.

## File Renaming Activity

The first rename demonstrated normal file organization:

`Report.txt`

became:

`Report-Final.txt`

The extension remained `.txt`.

This provided a comparison against the later extension manipulation.

## Extension Manipulation Activity

The controlled simulation then produced:

`Finance.csv` → `Finance.csv.locked`

`Notes.log` → `Notes.log.locked`

Additional files were renamed:

`Document1.txt` → `Document1.locked`

`Document2.txt` → `Document2.locked`

`Document3.txt` → `Document3.locked`

These changes simulated a pattern that could be suspicious in a real ransomware investigation.

## Content Verification

After renaming, the contents of selected files were checked.

The files remained readable.

This demonstrated that the simulated activity changed the filenames rather than encrypting the underlying content.

## Hash Comparison

SHA256 hashes were collected before and after the file renaming.

The purpose was to determine whether the underlying file contents changed.

The forensic logic was:

`Same SHA256`

`+`

`Different filename`

`=`

`Evidence supporting filename-only manipulation`

## Sysmon Event ID 1

Sysmon Event ID 1 was observed through Event Viewer.

The event was reviewed to identify the process associated with the controlled activity.

Relevant information includes:

- Timestamp
- Image
- CommandLine
- ParentImage
- User
- Process ID
- Process GUID

## PowerShell Event ID 4104

PowerShell Event ID 4104 was observed through Event Viewer.

The event was reviewed for script activity associated with the file-renaming operations.

Potentially useful indicators include:

- `Rename-Item`
- `FileRenameLab`
- `.locked`
- Script execution timestamp

## Sysmon Event ID 3

Sysmon Event ID 3 was obtained through PowerShell.

It was reviewed for network activity around the investigation timeframe.

The event was treated as supporting telemetry only.

A network connection does not independently establish that files were transmitted or exfiltrated.

## Security Event ID 4688

Security Event ID 4688 was investigated but was not successfully obtained for the PowerShell activity.

This was documented as an evidence gap.

The investigation therefore relied on:

- Sysmon Event ID 1
- PowerShell Event ID 4104
- Sysmon Event ID 3
- File metadata
- File contents
- SHA256 hashes

## Evidence Correlation

The investigation evidence chain can be represented as:

`Original File State`

↓

`Baseline SHA256`

↓

`File Rename / Extension Manipulation`

↓

`Sysmon Event ID 1`

↓

`PowerShell Event ID 4104`

↓

`Sysmon Event ID 3`

↓

`Post-Activity File State`

↓

`Hash Comparison`

↓

`Final Assessment`

## Evidence Interpretation

The available evidence supports controlled filename and extension manipulation.

The files remained readable, and hash comparison provided a method for determining whether their contents were modified.

The evidence does not support automatically concluding that the files were encrypted or that ransomware was present.

## Evidence Gaps

The main evidence gap was:

`Windows Security Event ID 4688 — Not obtained`

This limitation should be preserved in the final investigation documentation.

The absence of 4688 does not establish that no process creation occurred.

## Final Timeline Assessment

The investigation demonstrated a sequence in which controlled files were renamed and their extensions were manipulated, followed by endpoint telemetry collection and file-state verification.

Sysmon Event ID 1 and PowerShell Event ID 4104 provided process and script-level evidence, while Sysmon Event ID 3 provided network telemetry. File contents and SHA256 hashes provided the strongest evidence for determining whether the underlying data changed.

The final assessment should distinguish clearly between:

`Filename manipulation`

and:

`Actual content modification or encryption`

## Analyst Note

Replace any logical ordering with the actual timestamps from Event Viewer when finalizing the investigation.

Do not invent timestamps.

If exact timestamps are unavailable, describe the events in sequence and explicitly state that exact timing could not be established.

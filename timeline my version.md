# Timeline 

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


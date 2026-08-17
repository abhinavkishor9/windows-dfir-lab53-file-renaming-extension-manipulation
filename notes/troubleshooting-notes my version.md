# Troubleshooting Notes 

## 1. Security Event ID 4688 Was Not Found

### Problem

Windows Security Event ID 4688 was expected for the PowerShell process but could not be obtained.

### Possible Causes

- Process Creation auditing may not be enabled.
- The relevant event may not have been generated.
- The Security log may not contain the required timeframe.
- Events may have been overwritten.
- The event may have been filtered or unavailable through the current audit configuration.

### Investigation Approach

The investigation was not stopped because of the missing 4688 event.

Instead, the following available evidence was used:

- Sysmon Event ID 1
- PowerShell Event ID 4104
- Sysmon Event ID 3
- File metadata
- File contents
- SHA256 hashes

### DFIR Interpretation

The absence of Event ID 4688 should be documented as a telemetry limitation.

It should not be interpreted as proof that PowerShell did not execute.

---

## 2. Sysmon Event ID 1 Was Available

### Observation

Sysmon Event ID 1 was observed through Event Viewer.

### Purpose

The event was used to investigate process creation associated with the controlled file-manipulation activity.

### Relevant Fields

- Image
- CommandLine
- ParentImage
- User
- Process ID
- Process GUID
- Timestamp

### DFIR Note

Sysmon Event ID 1 provided useful process-level evidence in the absence of Security Event ID 4688.

---

## 3. PowerShell Event ID 4104 Was Available

### Observation

PowerShell Event ID 4104 was observed through Event Viewer.

### Purpose

The event was used to investigate the PowerShell script activity associated with the file-renaming operations.

### Useful Information

- Script content
- Timestamp
- Rename-Item commands
- Investigation directory
- PowerShell context

### DFIR Note

Event ID 4104 can provide more detailed visibility into PowerShell activity than process creation telemetry alone.

---

## 4. Sysmon Event ID 3 Was Obtained Through PowerShell

### Observation

Sysmon Event ID 3 was queried using PowerShell.

### Purpose

The event was reviewed to determine whether network connections occurred around the file-manipulation timeframe.

### Important Limitation

A Sysmon Event ID 3 connection does not prove that files were uploaded or exfiltrated.

The destination, process, port, timing, and additional evidence must be investigated.

---

## 5. File Extension Changed but File Still Opens

### Observation

A file such as:

`Finance.csv`

was renamed to:

`Finance.csv.locked`

but its contents remained readable.

### Explanation

Renaming a file does not automatically change its underlying data.

The file can still contain the same data even though Windows sees a different extension.

### DFIR Significance

This is why analysts should not automatically interpret `.locked` or `.encrypted` as proof of ransomware encryption.

---

## 6. Hash Remained the Same After Renaming

### Observation

The SHA256 hash of a renamed file can remain identical to the hash collected before the rename.

### Explanation

A cryptographic hash is based on file contents.

Changing only the filename does not change those contents.

Therefore:

`Same SHA256 + different filename = contents unchanged`

### DFIR Significance

Hash comparison provides strong evidence for distinguishing filename manipulation from content modification.

---

## 7. Hash Changed After a File Operation

### Possible Interpretation

If the hash changes, the file contents changed.

However, the hash change alone does not establish malicious encryption.

Possible explanations include:

- Legitimate file modification.
- Application-generated metadata changes.
- File conversion.
- Content replacement.
- Encryption.
- Malware modification.

Additional evidence is required.

---

## 8. Bulk Rename Command Does Not Mean Ransomware

### Observation

Multiple files were renamed with `.locked`.

### Incorrect Conclusion

`The files were renamed, therefore ransomware encrypted them.`

### Correct Approach

Investigate:

- Number of files affected
- File types affected
- Process responsible
- User account
- Command line
- File hashes
- File contents
- Timing
- Network activity
- Other suspicious processes

### DFIR Principle

Filename patterns are indicators, not conclusions.

---

## 9. PowerShell Activity Is Not Automatically Malicious

### Observation

PowerShell was involved in the file manipulation.

### Explanation

PowerShell is a legitimate Windows administration and automation tool.

The analyst should determine:

- Who executed PowerShell.
- What command was executed.
- Which files were targeted.
- Whether the activity was expected.
- Whether additional suspicious activity occurred.

### DFIR Principle

Investigate the behavior and context, not just the tool name.

---

## 10. Event Timestamps Do Not Match Exactly

### Problem

Sysmon, PowerShell, and other Windows events may have slightly different timestamps.

### Possible Causes

- Different event-generation stages.
- Logging delays.
- Timestamp resolution.
- Time-zone or display differences.
- Event processing delays.

### Resolution

Use a reasonable time window around the file-manipulation activity and correlate:

- Process ID
- Process GUID
- Command line
- User
- File path
- Event timestamp

---

## 11. Event ID 4104 Does Not Contain the Expected Command

### Possible Causes

- Script Block Logging configuration.
- Event filtering.
- Event truncation.
- The relevant command occurred outside the queried range.
- The activity was executed in a way that did not produce the expected script-block content.

### Recommended Approach

Search a wider timeframe:

`Get-WinEvent -FilterHashtable @{LogName="Microsoft-Windows-PowerShell/Operational"; Id=4104}`

Then filter the results for:

`Rename-Item`

or:

`FileRenameLab`

### DFIR Note

Do not assume that missing 4104 content means the script did not execute.

---

## 12. Sysmon Event ID 3 Is Missing

### Possible Causes

- No qualifying network connection occurred.
- Sysmon network monitoring is not configured.
- The relevant event is outside the queried timeframe.
- Sysmon configuration filters the event.

### DFIR Interpretation

No Event ID 3 does not prove that the host had no network activity.

It only means that the expected Sysmon network telemetry was not available for the investigation.

---

## 13. Files Were Renamed Accidentally

### Recovery

Because the lab files are controlled test files, they can be renamed back manually.

For example:

`Finance.csv.locked`

can be renamed back to:

`Finance.csv`

using:

`Rename-Item "C:\FileRenameLab\Finance.csv.locked" "Finance.csv"`

The same approach can be used for the other controlled files.

---

## 14. File Contents Cannot Be Read After Extension Manipulation

### Explanation

Changing the extension may cause Windows or an associated application to interpret the file differently.

This does not necessarily mean that the contents were encrypted.

### Recommended Approach

Use:

`Get-Content`

when working with text-based test files.

For binary files, use hashes and appropriate file-analysis tools rather than assuming that the extension determines the file's actual format.

---


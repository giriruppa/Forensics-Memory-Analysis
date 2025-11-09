# Forensics-Memory-Analysis

⚠️Safety & Legal Notice This repository contains analysis artifacts for a malicious sample. Do not execute the sample on your host. Use an isolated, fully patched analysis VM (e.g., FLARE VM), with no network or with controlled FakeNet/FakeDNS. This content is for educational/research use only.

Memory forensics, network artifacts, process &amp; DLL analysis (Volatility3 + FTK), reverse engineering with IDA Pro. Report + tools + sanitized artifacts.

### Executive summary

This sample is a small **(12 KB)** managed **.NET executable compiled with Microsoft Visual C#**. Analysis of the PE headers and imports indicates it is a **.NET (CLR) application:** the **entry point calls** into the **CLR (_CorExeMain)** and the **binary imports mscoree.dll**. The presence of function names such as **CreateDecryptor** and use of **MemoryStream indicate encryption/decryption** functionality. The sample contains a suspicious URL seen during automated scanning and lacks a valid certificate or debug symbols. The compiler **timestamp appears falsified.** Overall, the binary exhibits behavior and artifacts consistent with a **suspicious/malicious .NET program** that performs network activity and cryptographic operations.

---

## 1) Debugging Analysis (Q2)

### Tool Used: Pe Studio + IDA Pro Freeware 2024 + Hex-Rays Decompiler

- Observed behavior during execution (CorExeMain → CLR Execution)
- Exception or anti-debug behavior
- Threads created and handles
- DLLs loaded (ntdll.dll, kernelbase.dll, user32.dll, etc.)
- PDB and ImageBase details
- Workflow/graph view (explain hidden reference and function calls)
- Key API references and function tracing
- Findings (e.g., network activity, suspicious calls, encryption functions)
- Screenshots: debugger, graph view, stack, registers

---

## 2) Memory Forensics 
### Tool Used: FTK Imager + Volatility3
4.1. Memory Dump Details

Path: C:\Users\FlareVM\Documents\Ram Dump\memdump.mem

---

### Tool: Volatility3
```bash
Command used:

python vol.py -f "memdump.mem" windows.info
```

- Extracted metadata (Kernel base, OS version, processors, build, timestamp)

--- 

#### Process Enumeration
``` bash
Command: windows.pslist, windows.pstree

```
- Key PIDs (Explorer.exe, malware.exe, ShellExperienceHost.exe)

- Suspicious parent-child relationships

- Finding: malware.exe (PID 5544) spawned by explorer.exe

---

#### Handles & File Extraction
```bash
Command:

python vol.py -f "memdump.mem" windows.handles --pid 1124 | select-string "File"

```
---

#### Purpose and interpretation

- File dumping with windows.dumpfiles

- Recovered file details (path, type, size)

---

#### Network Connections
```bash
Command: windows.netstat
```
- Observed connections (e.g., 192.168.254.128)

- Explanation of UDP → TCP transition (beaconing, NAT traversal, C2)

- Analysis of IPs and protocols

--- 

#### Malfind (Injected Code Detection)
``` bash
Command:

python vol.py -f "memdump.mem" windows.malfind
```

- Finding: RWX memory region containing shellcode in PID 1124
- Interpretation and next steps

--- 

#### Correlation Between Memory and Debugging Findings

- Relationship between loaded modules and API calls
- Confirmed malicious behavior via memory inspection
- Network & file artifacts match IDA findings

 Example: HTTPClient activity → C2 URL in VirusTotal

--- 
#### Recommended actions

##### (Keep these recommendations actionable and conservative pending dynamic analysis)

- 1)**Treat the sample as malicious/suspicious** — handle only in controlled, air-gapped analysis environments (sandbox or isolated VM snapshots). Do not run on production systems.

- 2)**Network containment:** block the observed suspicious URL and related domains at perimeter controls (proxy/IDS/URL filtering) and consider blocking filemail.com paths used in the sample if confirmed malicious by further analysis.

- 3)**Endpoint detection:** add the SHA-256 and filename as IOCs to endpoint protection and EDR solutions to detect or quarantine occurrences.

- 4)**Further analysis:** perform dynamic analysis in a safe sandbox to observe runtime behavior — network calls, process creation, file system or registry modifications, and any second-stage payloads. Capture full packet captures for network indicators.

- 5)**YARA / detection rules:** craft YARA signatures based on unique strings (e.g., function names and assembly GUID) and ImpHash for retrospective scanning across repositories and endpoint stores.

- 6)**Update threat intel:** share the sample hash and observed IOCs with internal threat intel teams or community feeds (e.g., VirusTotal) for broader context and correlation.

---

#### Attachments / Evidence

Screenshots and static analysis captures (as provided) show the PE headers, import table, entry point (0x0000450E), referenced namespaces, cryptographic function names, suspicious URL, and VirusTotal scan summary. These artifacts support the findings above.

---

#### References

- Volatility3 Documentation
- IDA Pro Freeware Guide
- VirusTotal Reports
- FTK Imager User Manual
- Microsoft API Reference

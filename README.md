# Forensics-Memory-Analysis

⚠️Safety & Legal Notice This repository contains analysis artifacts for a malicious sample. Do not execute the sample on your host. Use an isolated, fully patched analysis VM (e.g., FLARE VM), with no network or with controlled FakeNet/FakeDNS. This content is for educational/research use only.

Memory forensics, network artifacts, process &amp; DLL analysis (Volatility3 + FTK), reverse engineering with IDA Pro. Report + tools + sanitized artifacts.

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

#### References

- Volatility3 Documentation
- IDA Pro Freeware Guide
- VirusTotal Reports
- FTK Imager User Manual
- Microsoft API Reference

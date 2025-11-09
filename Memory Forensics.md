# Tool Used : 3) FTK Imager for Memory(RAM) Capture 

<img width="940" height="529" alt="image" src="https://github.com/user-attachments/assets/eaf4e359-1a5d-411b-98ff-bb6ed14db3a8" />

# Tool Used : 4) Volatility 3 ram dump analysis for memory forsenics

``` bash
1)	Cmd :
python vol.py -f "C:\Users\FlareVM\Documents\Ram Dump\memdump.mem" windows.info
```
- Getting information about the machine of during the ram dump. 

<img width="968" height="544" alt="image" src="https://github.com/user-attachments/assets/f96634e8-9a85-43e6-96bb-680cde8317a8" />

### Parsed Output (Cleaned Up)

| Field                     |      Value (approx.) | Description                                                                                                                                 |
| ------------------------- | -------------------: | ------------------------------------------------------------------------------------------------------------------------------------------- |
| Kernel Base               |     `0xf804e64ee000` | The base virtual address of the Windows kernel (`ntoskrnl.exe`) in memory. All kernel-mode symbols and modules are loaded relative to this. |
| PsLoadedModuleList        |     `0xf804e670f3a0` | The address of the linked list of loaded kernel modules (drivers, kernel components). Volatility uses this to enumerate modules.            |
| Symbols                   |                    — | Volatility indicates whether it could find symbol information (PDB) for debugging/translation of kernel structures.                         |
| Is64Bit                   |             **True** | Confirms this is a 64-bit Windows memory image.                                                                                             |
| IsPAE                     |            **False** | PAE (Physical Address Extension) is not used (common for 64-bit systems, only 32-bit uses PAE).                                             |
| Layer Name                |       `memory_layer` | Internal Volatility reference — the analysis layer used to interpret raw memory.                                                            |
| KdVersionBlock            |                    — | Kernel debugger version block — structure holding OS version/build info for kernel debugging.                                               |
| Major/Minor Version       |               `10.x` | Indicates this is Windows 10.                                                                                                               |
| Machine Type              | `Intel x64 (0x8664)` | Architecture type — confirms x64 processor type.                                                                                            |
| Windows Internal Version  |         `10.0.19041` | Internal build number (Windows 10 version 2004 / 20H1).                                                                                     |
| KeNumberProcessors        |                  `2` | Number of logical processors (CPU cores) at time of dump.                                                                                   |
| System Time               |         `2025-10-28` | Timestamp from the system at the moment the dump was taken. Useful for timeline correlation in forensics.                                   |
| NtSystemRoot              |         `C:\Windows` | The root directory of the Windows installation in the memory image.                                                                         |
| Product Type              |     `NtProductWinNt` | Indicates this is a Workstation edition (not Server or Domain Controller).                                                                  |
| PE Major/Minor OS Version |               `10.0` | Matches the Windows kernel version — confirms consistency with OS version.                                                                  |
| PE Machine                |             `0x8664` | The PE header field confirming x64 architecture.                                                                                            |
| PE TimeDateStamp          |   `Fri May 29, 2020` | The build date/time of the kernel image (`ntoskrnl.exe`) — matches Windows 10 version 2004.                                                 |

This metadata indicates the memory dump was taken from a **Windows 10 x64 (build 19041)** system with **2 logical CPUs**, and the system time when captured was **2025-10-28**. Volatility successfully resolved the kernel base and module list, enabling enumeration of processes, DLLs, and network connections for deeper analysis.

---

``` bash
2)	Cmd :
python vol.py -f "C:\Users\FlareVM\Documents\Ram Dump\memdump.mem" windows.pslist | more 
```
- Get the process id and offset of during the ram dump  
<img width="940" height="529" alt="image" src="https://github.com/user-attachments/assets/a9bb6462-8830-4cf7-ac90-1e4b6167bd72" />

<img width="940" height="529" alt="image" src="https://github.com/user-attachments/assets/fa59128b-6d20-42b5-867d-14f4551bc0df" />

- 1) pid 3944 --> 7684  shell experience 
- 2) pid 1124 7764 --> 5544 malware .exe

---

```bash
3) Cmd:
python vol.py -f "C:\Users\FlareVM\Documents\Ram Dump\memdump.mem" windows.pslist | select-string "chrome"
```
<img width="940" height="529" alt="image" src="https://github.com/user-attachments/assets/77f9187f-08ee-4b7f-8f27-255bcf05b1cc" />

---

```bash
4) Cmd:
Show help for a plugin
python vol.py -f "C:\Users\FlareVM\Documents\Ram Dump\memdump.mem" windows.handles --pid 1124 | more
```
<img width="940" height="529" alt="image" src="https://github.com/user-attachments/assets/abb6acb6-d9e6-426c-b43e-a3a829e56db3" />

<img width="940" height="529" alt="image" src="https://github.com/user-attachments/assets/24fcc463-82e8-422c-80f1-c642d5bf55a4" />

- Kernelbase.dll call here for transferring the file

---

- Filter handles output for File handles
```bash
5) Cmd:
python vol.py -f "C:\Users\FlareVM\Documents\Ram Dump\memdump.mem" windows.handles --pid 1124 | select-string "File" | more
```
- Purpose: show only file-related handles.

<img width="940" height="529" alt="image" src="https://github.com/user-attachments/assets/99c184f8-46c4-4543-9b8c-1cac031874b8" />

- Crypt32.dll is called to do the

- This command lists all open handles (objects like files, registry keys, sockets, etc.) for the process with PID 1124 (in my case, ShellExperienceHost.exe) and filters the output to show only file-related handles.
**Explanation:**
- -f "memdump.mem" → specifies the memory dump file.
- windows.handles → Volatility 3 plugin that enumerates handle objects (like files, keys, mutexes, pipes, etc.).
- --pid 1124 → limits the search to a specific process (helps narrow down analysis).
- | select-string "File" → PowerShell filter to show only handles of type File.
- **Why we use it:**
- This step is used to:
- Identify which files or directories a process was interacting with.
- Detect suspicious or malicious file access (e.g., temporary payloads, encrypted data, deleted malware files).
- Extract file virtual addresses (VA) for later use in windows.dumpfiles.

---

### 2   malware --- pid 3944 

<img width="940" height="529" alt="image" src="https://github.com/user-attachments/assets/b00bd761-7a3d-4f43-97f8-0f89efba3d06" />
<img width="877" height="493" alt="image" src="https://github.com/user-attachments/assets/751d2a69-7b9d-48c0-90d3-2863da5e61ff" />

- This command extracts (dumps) a specific file from memory using its virtual address (VA) found in the previous step.
**Explanation:**
- windows.dumpfiles → plugin that extracts file data directly from memory.
- --pid 3944 → again targets the same process.
- --virtaddr 0xc003eeb2b080 → this address points to the FileObject structure in memory for that specific file.
- -o "dump" → specifies an output directory where the dumped file will be saved.
**Why we use it:**
- This is used to recover a file that was opened or loaded in memory 

---

#### Net scan while doing network identify the  TCP 4 connection that  IP 
**192.168.254.128**
- Here commonly use UDP first (for discovery/NAT traversal/beaconing) and then open a TCP connection for reliable command-and-control or exfiltration.
<img width="727" height="409" alt="image" src="https://github.com/user-attachments/assets/3faf075a-0641-4287-934f-1821fb3b3530" />

<img width="821" height="462" alt="image" src="https://github.com/user-attachments/assets/155ab2e0-16eb-4923-aff8-2404301169bd" />

#### Udp connection is establish then it is done
- Note : UDP is lightweight & fire-and-forget. Good for quick beacons (small packets) to see if a controller is reachable.
- NAT traversal / hole punching. UDP hole punching (and STUN) can create a path through NATs; once the path exists, TCP or higher-level protocols can be used.
- Stealth / opportunism. UDP can slip through poorly filtered firewalls; after confirming reachability, the malware upgrades to TCP for reliable transfer.
- Protocol framing. Some malware uses UDP for discovery and negotiation (which port, protocol version, auth), then opens an authenticated TCP session (or QUIC over UDP).
- Fallback & multi-channel C2. If TCP is blocked, the malware may try UDP or DNS; or do UDP beacon → TCP payload.
- **Examples:** beacon (UDP) → rendezvous server responds → client opens TCP backchannel to send large files or interactive C2.

<img width="883" height="497" alt="image" src="https://github.com/user-attachments/assets/c84511b0-e102-47da-863c-53d2feef17d2" />
Search the ip with string identify the connection

---

#### Assemble language and,jae..etc.
- **Finding:** malfind reported a private RWX memory region in PID 1124 containing probable shellcode.

Ps tree of the pid –1124

<img width="901" height="381" alt="image" src="https://github.com/user-attachments/assets/bacee402-a0bb-4de3-927f-3af23a9330bc" />

<img width="940" height="529" alt="image" src="https://github.com/user-attachments/assets/257a6a37-1d8a-4102-b74e-7d3cebba351a" />

#### Process tree finding (Volatility windows.pstree)
- **Memory image:** C:\Users\FlareVM\Documents\Ram Dump\memdump.mem
- **Volatility plugin:** windows.pstree
- **Observation: malware.exe (PID 5544)** is present as a child process under the user shell (explorer.exe). The process path is C:\Users\FlareVM\Documents\malware.exe. Process create time recorded by pslist is 2025-10-28 16:11:32 UTC.
- **Interpretation:** Execution from a user profile directory and parented by explorer.exe is consistent with a user-level dropper or socially-engineered execution. This is suspicious and warrants further evidence collection (memory region dump, module enumeration, network correlation).

---

```bash
Cmd:
windows.ldrmodules (and related DLL/module plugins)
```
<img width="940" height="529" alt="image" src="https://github.com/user-attachments/assets/d4e46f21-64d9-494d-bdbc-0fe4abf5bed9" />

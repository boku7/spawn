#include <windows.h>
#include "beacon.h"

DECLSPEC_IMPORT WINBASEAPI WINBOOL WINAPI KERNEL32$CreateProcessA(LPCSTR lpApplicationName, LPSTR lpCommandLine, LPSECURITY_ATTRIBUTES lpProcessAttributes, LPSECURITY_ATTRIBUTES lpThreadAttributes, WINBOOL bInheritHandles, DWORD dwCreationFlags, LPVOID lpEnvironment, LPCSTR lpCurrentDirectory, LPSTARTUPINFOA lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation);
DECLSPEC_IMPORT WINBASEAPI void __cdecl MSVCRT$memset(void *dest, int c, size_t count);

#define intZeroMemory(addr,size) MSVCRT$memset((addr),0,size)

void SpawnProcess(char * procName) {
    PROCESS_INFORMATION pInfo;
    STARTUPINFO sInfo;
    intZeroMemory(&sInfo, sizeof(sInfo));
    sInfo.cb = sizeof(sInfo);
    intZeroMemory(&pInfo, sizeof(pInfo));
    WINBOOL success = KERNEL32$CreateProcessA(0, procName, 0, 0, 0, CREATE_SUSPENDED, 0, 0, &sInfo, &pInfo);
    if (success == 1){
        BeaconPrintf(CALLBACK_OUTPUT, "Your new process %s has been spawned in a suspended state!",procName);
    }
    else{
        BeaconPrintf(CALLBACK_OUTPUT, "Uh oh, your process failed to spawn. Typically this is because the EXE does not exist. You're beacon has likely died.. All is doomed.. :'(");
    }
}

void go(char * args, int len) {
    SpawnProcess(args);
}

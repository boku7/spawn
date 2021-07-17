#include <windows.h>
#include "beacon.h"

DECLSPEC_IMPORT WINBASEAPI WINBOOL WINAPI KERNEL32$CreateProcessA(LPCSTR lpApplicationName, LPSTR lpCommandLine, LPSECURITY_ATTRIBUTES lpProcessAttributes, LPSECURITY_ATTRIBUTES lpThreadAttributes, WINBOOL bInheritHandles, DWORD dwCreationFlags, LPVOID lpEnvironment, LPCSTR lpCurrentDirectory, LPSTARTUPINFOA lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation);
DECLSPEC_IMPORT WINBASEAPI DWORD WINAPI KERNEL32$GetTickCount (VOID);
//DECLSPEC_IMPORT WINBASEAPI int WINAPI KERNEL32$lstrlenA(LPCSTR);
DECLSPEC_IMPORT WINBASEAPI void __cdecl MSVCRT$memset(void *dest, int c, size_t count);

#define intZeroMemory(addr,size) MSVCRT$memset((addr),0,size)

void SpawnProcess(char * procName) {
    PROCESS_INFORMATION pInfo;
    STARTUPINFO sInfo;
    intZeroMemory(&sInfo, sizeof(sInfo));
    sInfo.cb = sizeof(sInfo);
    intZeroMemory(&pInfo, sizeof(pInfo));
    WINBOOL success = KERNEL32$CreateProcessA(0, procName, 0, 0, 0, CREATE_SUSPENDED, 0, 0, &sInfo, &pInfo);
    BeaconPrintf(CALLBACK_OUTPUT, "%d", success);
}

void go(char * args, int len) {
    /*
    datap parser;
    char * arg1;
    char * arg2;
    BeaconDataParse(&parser, args, len);
    arg1 = BeaconDataExtract(&parser, NULL);
    arg2 = BeaconDataExtract(&parser, NULL);
    BeaconPrintf(CALLBACK_OUTPUT, "Args: %s", args);
    BeaconPrintf(CALLBACK_OUTPUT, "Arg2: %s", arg2);
    */
    SpawnProcess(args);
}
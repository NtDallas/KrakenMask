#include <stdio.h>
#include <stdio.h>

#include <Windows.h>
#include "ntdll.h"

#define MODULE_SIZE(x)      ((PIMAGE_NT_HEADERS)((UINT_PTR)x + ((PIMAGE_DOS_HEADER)x)->e_lfanew))->OptionalHeader.SizeOfImage

typedef NTSTATUS(NTAPI* _NtAlertResumeThread)   (HANDLE, PULONG);
typedef NTSTATUS(NTAPI* _NtSignalAndWaitForSingleObject) (HANDLE, HANDLE, BOOL, PLARGE_INTEGER);

typedef struct _USTRING
{
    DWORD	Length;
    DWORD	MaximumLength;
    PVOID	Buffer;
} USTRING, * PUSTRING;

VOID    KrakenSleep(
    _In_    DWORD   dwSleepTime,
    _In_    LPVOID  lpAddr,
    _In_    DWORD   dwSize
);

LPVOID  lpGetGadgetlpNtTestAlert(
    _In_    LPVOID  lpModuleAddr
);

LPVOID lpGetGadgetJmpRax(
    _In_    LPVOID  lpModuleAddr
);


VOID main()
{
    printf(" ____  __.              __                     _____                 __     ________     _______   \n");
    printf("|    |/ _|___________  |  | __ ____   ____    /     \\ _____    _____|  | __ \\_____  \\    \\   _  \\  \n");
    printf("|      < \\_  __ \\__  \\ |  |/ // __ \\ /    \\  /  \\ /  \\\\__  \\  /  ___/  |/ /  /  ____/    /  /_\\  \\ \n");
    printf("|    |  \\ |  | \\/ __  \\|    <\\  ___/|   |  \\/    Y    \\/ __ \\_\\___ \\|    <  /       \\    \\  \\_/   \\\n");
    printf("|____|__ \\|__|  (____  /__|_ \\\\___  >___|  /\\____|__  (____  /____  >__|_ \\ \\_______ \\ /\\ \\_____  /\n");
    printf("        \\/           \\/     \\/    \\/     \\/         \\/     \\/     \\/     \\/         \\/ \\/       \\/ \n");
    printf("\tBy @RtlDallas, KrakenMask 2.0\n");

    while (TRUE)
    {
        printf("Zzzz Zzzz Zzzz...\n");
        LPVOID  lpModuleAddr = GetModuleHandle(NULL);

        KrakenSleep(5 * 1000,
            lpModuleAddr,
            MODULE_SIZE(lpModuleAddr));
    }

}

VOID KrakenSleep(
    _In_    DWORD   dwSleepTime,
    _In_    LPVOID  lpAddr,
    _In_    DWORD   dwSize
)
{
    CONTEXT ctx = { 0 };
    ctx.ContextFlags = CONTEXT_ALL;

    CONTEXT ctxSync     = { 0 };
    CONTEXT ctxRW       = { 0 };
    CONTEXT ctxEnc      = { 0 };
    CONTEXT ctxDelay    = { 0 };
    CONTEXT ctxDec      = { 0 };
    CONTEXT ctxRWX      = { 0 };
    CONTEXT ctxEvent    = { 0 };
    CONTEXT ctxEnd      = { 0 };

    HANDLE hEventEnd    = CreateEventW(0, 0, 0, 0);
    HANDLE hEventSync   = CreateEventW(0, 0, 0, 0);

    // USTRING encryption args for SystemFunction032 (RC4 encrypt)
    BYTE    bEncKey[] = "ENCRYPT_KEY_123";
    USTRING uKey = { 0 };
    USTRING uData = { 0 };

    uKey.Buffer = &bEncKey;
    uKey.Length = uKey.MaximumLength = 16;

    uData.Buffer = lpAddr;
    uData.Length = uData.MaximumLength = dwSize;

    // Solve module addr
    LPVOID  lpNtdll = GetModuleHandleA("ntdll.dll");
    LPVOID  lpKernel32 = GetModuleHandleA("Kernel32.dll");
    if (!lpNtdll || !lpKernel32)
        return;

    LPVOID  lpCryptsp = GetModuleHandleA("cryptsp.dll");
    if (!lpCryptsp)
    {
        lpCryptsp = LoadLibraryA("cryptsp.dll");
        if (!lpCryptsp)
            return;
    }

    // Solve gadget addr
    LPVOID  lpRetGadget             = lpGetGadgetlpNtTestAlert(lpNtdll);
    LPVOID  lpJmpGadget             = lpGetGadgetJmpRax(lpKernel32);
    LPVOID  lpNtContinueGadget      = (UINT_PTR)GetProcAddress(lpNtdll, "LdrInitializeThunk") + 19;

    if (!lpRetGadget || !lpJmpGadget || !lpNtContinueGadget)
        return;

    // Solve function addr
    LPVOID  lpNtTestAlert                       = GetProcAddress(lpNtdll, "NtTestAlert");
    LPVOID  lpRtlExitUserThread                 = GetProcAddress(lpNtdll, "RtlExitUserThread");
    LPVOID  lpSystemFunction032                 = GetProcAddress(lpCryptsp, "SystemFunction032");
    LPVOID  lpTpReleaseCleanupGroupMembers      = (UINT_PTR)GetProcAddress(lpNtdll, "TpReleaseCleanupGroupMembers") + 0x450;
    LPVOID  lpNtAlertResumeThread               = GetProcAddress(lpNtdll, "NtAlertResumeThread");
    LPVOID  lpNtSignalAndWaitForSingleObject    = GetProcAddress(lpNtdll, "NtSignalAndWaitForSingleObject");

    if (!lpNtTestAlert || !lpRtlExitUserThread || !lpSystemFunction032 || !lpTpReleaseCleanupGroupMembers || !lpNtAlertResumeThread || !lpNtSignalAndWaitForSingleObject)
        return;

    // Setup heap for NtTestAlert gadget
    HANDLE  hKrakenHeap = HeapCreate(HEAP_NO_SERIALIZE, 0, 0);
    if (!hKrakenHeap)
        return;

    LPVOID  lpFakeStackRW = HeapAlloc(hKrakenHeap, HEAP_ZERO_MEMORY, 0x5000);
    ((UINT_PTR)lpFakeStackRW) += 0x1000;

    LPVOID  lpFakeStackRWX = HeapAlloc(hKrakenHeap, HEAP_ZERO_MEMORY, 0x5000);
    ((UINT_PTR)lpFakeStackRWX) += 0x1000;

    if (!lpFakeStackRWX || !lpFakeStackRW)
        return;

    *(PULONG_PTR)lpFakeStackRW = (ULONG_PTR)lpRetGadget;
    *(PULONG_PTR)lpFakeStackRWX = (ULONG_PTR)lpRetGadget;

    // Create thread
    DWORD dwTid = 0;
    HANDLE hThread = CreateThread(NULL, 65535, lpTpReleaseCleanupGroupMembers, NULL, CREATE_SUSPENDED, &dwTid);
    if (!hThread)
        return;

    if (hThread != NULL)
    {
        DWORD   dwOldProtect = 0;

        if (!GetThreadContext(hThread, &ctx))
            return;

        memcpy(&ctxSync, &ctx, sizeof(CONTEXT));
        memcpy(&ctxRW, &ctx, sizeof(CONTEXT));
        memcpy(&ctxEnc, &ctx, sizeof(CONTEXT));
        memcpy(&ctxDelay, &ctx, sizeof(CONTEXT));
        memcpy(&ctxDec, &ctx, sizeof(CONTEXT));
        memcpy(&ctxRWX, &ctx, sizeof(CONTEXT));
        memcpy(&ctxEvent, &ctx, sizeof(CONTEXT));
        memcpy(&ctxEnd, &ctx, sizeof(CONTEXT));

        ctxSync.Rip = lpJmpGadget;
        ctxSync.Rax = WaitForSingleObject;
        ctxSync.Rcx = hEventSync;
        ctxSync.Rdx = INFINITE;
        *(PULONG_PTR)ctxSync.Rsp = (ULONG_PTR)lpNtTestAlert;

        ctxRW.Rip = lpJmpGadget;
        ctxRW.Rax = VirtualProtect;
        ctxRW.Rcx = lpAddr;
        ctxRW.Rdx = dwSize;
        ctxRW.R8 = PAGE_READWRITE;
        ctxRW.R9 = &dwOldProtect;
        ctxRW.Rsp = lpFakeStackRW;

        ctxEnc.Rip = lpJmpGadget;
        ctxEnc.Rax = lpSystemFunction032;
        ctxEnc.Rcx = &uData;
        ctxEnc.Rdx = &uKey;
        *(PULONG_PTR)ctxEnc.Rsp = (ULONG_PTR)lpNtTestAlert;

        ctxDelay.Rip = lpJmpGadget;
        ctxDelay.Rax = WaitForSingleObject;
        ctxDelay.Rcx = (HANDLE)-1;
        ctxDelay.Rdx = dwSleepTime;
        *(PULONG_PTR)ctxDelay.Rsp = (ULONG_PTR)lpNtTestAlert;

        ctxDec.Rip = lpJmpGadget;
        ctxDec.Rax = lpSystemFunction032;
        ctxDec.Rcx = &uData;
        ctxDec.Rdx = &uKey;
        *(PULONG_PTR)ctxDec.Rsp = (ULONG_PTR)lpNtTestAlert;

        ctxRWX.Rip = lpJmpGadget;
        ctxRWX.Rax = VirtualProtect;
        ctxRWX.Rcx = lpAddr;
        ctxRWX.Rdx = dwSize;
        ctxRWX.R8 = PAGE_EXECUTE_READWRITE;
        ctxRWX.R9 = &dwOldProtect;
        ctxRWX.Rsp = lpFakeStackRWX;

        ctxEvent.Rip = lpJmpGadget;
        ctxEvent.Rax = SetEvent;
        ctxEvent.Rcx = hEventEnd;
        *(PULONG_PTR)ctxEvent.Rsp = (ULONG_PTR)lpNtTestAlert;

        ctxEnd.Rip = lpJmpGadget;
        ctxEnd.Rax = lpRtlExitUserThread;
        ctxEnd.Rcx = 0;
        *(PULONG_PTR)ctxEnd.Rsp = (ULONG_PTR)lpNtTestAlert;

        QueueUserAPC((PAPCFUNC)lpNtContinueGadget, hThread, &ctxSync);
        QueueUserAPC((PAPCFUNC)lpNtContinueGadget, hThread, &ctxRW);
        QueueUserAPC((PAPCFUNC)lpNtContinueGadget, hThread, &ctxEnc);
        QueueUserAPC((PAPCFUNC)lpNtContinueGadget, hThread, &ctxDelay);
        QueueUserAPC((PAPCFUNC)lpNtContinueGadget, hThread, &ctxRWX);
        QueueUserAPC((PAPCFUNC)lpNtContinueGadget, hThread, &ctxDec);
        QueueUserAPC((PAPCFUNC)lpNtContinueGadget, hThread, &ctxEvent);
        QueueUserAPC((PAPCFUNC)lpNtContinueGadget, hThread, &ctxEnd);

        ULONG abcd = 0;
        ((_NtAlertResumeThread)lpNtAlertResumeThread)(hThread, &abcd);
        ((_NtSignalAndWaitForSingleObject)lpNtSignalAndWaitForSingleObject)(hEventSync, hEventEnd, TRUE, NULL);

    }

    CloseHandle(hThread);
    CloseHandle(hEventEnd);
    CloseHandle(hEventSync);
    HeapDestroy(hKrakenHeap);

    return;
}



LPVOID  lpGetGadgetlpNtTestAlert(
    _In_    LPVOID  lpModuleAddr
)
{
    // pattern of "CALL ZwTestAlert" gadget
    BYTE pattern[] = { 0x48, 0x83, 0xEC, 0x28, 0xF7, 0x41, 0x04, 0x66, 0x00, 0x00, 0x00, 0x74, 0x05 };

    for (SIZE_T i = 0; i < (MODULE_SIZE(lpModuleAddr) - 12); i++) {
        if (memcmp((PBYTE)lpModuleAddr + i, pattern, 12) == 0) {
            return (UINT_PTR)lpModuleAddr + i + 0xd;
        }
    }

    return NULL;
}

LPVOID lpGetGadgetJmpRax(
    _In_    LPVOID  lpModuleAddr
)
{
    // pattern of "JMP RAX" gadget
    BYTE pattern[] = { 0xFF, 0xE0 };
    for (SIZE_T i = 0; i < (MODULE_SIZE(lpModuleAddr) - 2); i++) {
        if (memcmp((PBYTE)lpModuleAddr + i, pattern, 2) == 0) {
            return (UINT_PTR)lpModuleAddr + i;
        }
    }

    return NULL;
}

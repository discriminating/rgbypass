#include <windows.h>
#include <tlhelp32.h>
#include <string.h>
#include <stdio.h>
#include <stdbool.h>

#ifdef UNICODE
#undef MODULEENTRY32
#undef Module32First
#undef Module32Next
#undef GetModuleHandleEx
#endif

HINSTANCE _GetModuleHandleExA(HANDLE hTargetProc, const char* szModuleName)
{
    MODULEENTRY32 ME32;
    memset(&ME32, 0, sizeof(ME32));
    ME32.dwSize = sizeof(ME32);

    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, GetProcessId(hTargetProc));
    if (hSnap == INVALID_HANDLE_VALUE)
        while (GetLastError() == ERROR_BAD_LENGTH)
            if (CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, GetProcessId(hTargetProc)) != INVALID_HANDLE_VALUE)
                break;

    if (hSnap == INVALID_HANDLE_VALUE || !hSnap)
        return NULL;

    BOOL bRet = Module32First(hSnap, &ME32);
    do
    {
        if (!_stricmp(ME32.szModule, szModuleName))
            break;

        bRet = Module32Next(hSnap, &ME32);
    } while (bRet);

    CloseHandle(hSnap);

    if (!bRet)
        return NULL;

    return ME32.hModule;
}

HINSTANCE _GetModuleHandleExW(HANDLE hTargetProc, const wchar_t* szModuleName)
{
    MODULEENTRY32W ME32;
    memset(&ME32, 0, sizeof(ME32));
    ME32.dwSize = sizeof(ME32);

    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, GetProcessId(hTargetProc));
    if (hSnap == INVALID_HANDLE_VALUE)
        while (GetLastError() == ERROR_BAD_LENGTH)
        {
            hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, GetProcessId(hTargetProc));

            if (hSnap != INVALID_HANDLE_VALUE)
                break;
        }

    if (hSnap == INVALID_HANDLE_VALUE || !hSnap)
        return NULL;

    BOOL bRet = Module32FirstW(hSnap, &ME32);
    do
    {
        if (!_wcsicmp(ME32.szModule, szModuleName))
            break;

        bRet = Module32NextW(hSnap, &ME32);
    } while (bRet);

    CloseHandle(hSnap);

    if (!bRet)
        return NULL;

    return ME32.hModule;
}

bool Forward(DWORD FuncRVA, HANDLE hTargetProc, BYTE* localBase, void** pOut);

bool GetProcAddressEx(HANDLE hTargetProc, HINSTANCE hModule, const char* szProcName, void** pOut)
{
    BYTE* modBase = (BYTE*)hModule;

    if (!modBase)
        return false;

    BYTE* pe_header = (BYTE*)malloc(0x1000);
    if (!pe_header)
        return false;

    if (!ReadProcessMemory(hTargetProc, modBase, pe_header, 0x1000, NULL))
    {
        free(pe_header);

        return false;
    }

    IMAGE_NT_HEADERS* pNT = (IMAGE_NT_HEADERS*)(pe_header + ((IMAGE_DOS_HEADER*)pe_header)->e_lfanew);
    IMAGE_DATA_DIRECTORY* pExportEntry = &pNT->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];

    DWORD ExportSize = pExportEntry->Size;
    DWORD ExportDirRVA = pExportEntry->VirtualAddress;

    if (!ExportSize)
    {
        free(pe_header);

        return false;
    }

    BYTE* export_data = (BYTE*)malloc(ExportSize);
    if (!export_data)
    {
        free(pe_header);

        return false;
    }

    if (!ReadProcessMemory(hTargetProc, modBase + ExportDirRVA, export_data, ExportSize, NULL))
    {
        free(export_data);
        free(pe_header);

        return false;
    }

    BYTE* localBase = export_data - ExportDirRVA;
    IMAGE_EXPORT_DIRECTORY* pExportDir = (IMAGE_EXPORT_DIRECTORY*)export_data;

    if ((uintptr_t)szProcName <= MAXWORD)
    {
        WORD Base = LOWORD(pExportDir->Base - 1);
        WORD Ordinal = LOWORD(szProcName) - Base;
        DWORD FuncRVA = ((DWORD*)(localBase + pExportDir->AddressOfFunctions))[Ordinal];

        free(export_data);
        free(pe_header);

        if (FuncRVA >= ExportDirRVA && FuncRVA < ExportDirRVA + ExportSize)
			return Forward(FuncRVA, hTargetProc, localBase, pOut);

        *pOut = modBase + FuncRVA;
        return true;
    }

    DWORD max = pExportDir->NumberOfNames - 1;
    DWORD min = 0;
    DWORD FuncRVA = 0;

    while (min <= max)
    {
        DWORD mid = (min + max) / 2;

        DWORD CurrNameRVA = ((DWORD*)(localBase + pExportDir->AddressOfNames))[mid];
        char* szName = (char*)(localBase + CurrNameRVA);

        int cmp = strcmp(szName, szProcName);

        if (cmp < 0) min = mid + 1;
        else if (cmp > 0) max = mid - 1;
        else
        {
            FuncRVA = ((DWORD*)(localBase + pExportDir->AddressOfFunctions))
                [((WORD*)(localBase + pExportDir->AddressOfNameOrdinals))[mid]];

            break;
        }
    }

    free(export_data);
    free(pe_header);

    if (!FuncRVA)
        return false;

    if (FuncRVA >= ExportDirRVA && FuncRVA < ExportDirRVA + ExportSize)
		return Forward(FuncRVA, hTargetProc, localBase, pOut);

    *pOut = modBase + FuncRVA;

    return true;
}

bool Forward(DWORD FuncRVA, HANDLE hTargetProc, BYTE* localBase, void** pOut)
{
    char pFullExport[MAX_PATH] = { 0 };
    size_t len_out = strlen((char*)(localBase + FuncRVA));
    memcpy(pFullExport, (char*)(localBase + FuncRVA), len_out);

    char* pFuncName = strchr(pFullExport, '.');
    *(pFuncName++) = '\0';
    if (*pFuncName == '#')
        pFuncName = (char*)(LOWORD(atoi(++pFuncName)));

    HINSTANCE hForwardDll = _GetModuleHandleExA(hTargetProc, pFullExport);

    if (hForwardDll)
        return GetProcAddressEx(hTargetProc, hForwardDll, pFuncName, pOut);

    return false;
}

BYTE bShellCode[19];
extern void __stdcall SHELLCODE(void);

int main(int argc, char* argv[])
{
    if (argc != 2)
    {
        printf("Usage: %s <PID>\n", argv[0]);
        return 1;
    }

    char* dllPath = "C:\\Users\\meii\\Dekstop\\rgbypass\\Release\\dll.dll";
    void* pRtlLogStackBackTrace = NULL;
    void* pLoadLibraryExA = NULL;
    void* pDllPath;

    DWORD pid = atoi(argv[1]);
    memcpy(bShellCode, SHELLCODE, 19);

    HANDLE hProcess = OpenProcess(PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION, FALSE, pid);
    if (hProcess == NULL)
    {
        printf("Failed to open process.\n");
        return 1;
    }

	// ntdll!RtlLogStackBackTrace is a gigantic function i just chose at random
    if (!GetProcAddressEx(hProcess, _GetModuleHandleExA(hProcess, "ntdll.dll"), "RtlLogStackBackTrace", &pRtlLogStackBackTrace) || 
        !GetProcAddressEx(hProcess, _GetModuleHandleExA(hProcess, "kernel32.dll"), "LoadLibraryExA", &pLoadLibraryExA))
    {
        printf("Failed to find function(s).\n");

		CloseHandle(hProcess);
		return 1;
    }
    else {
		printf("ntdll!RtlLogStackBackTrace: %p\n", pRtlLogStackBackTrace);
		printf("kernel32!LoadLibraryExA: %p\n", pLoadLibraryExA);
    }

    pDllPath = VirtualAllocEx(hProcess, NULL, strlen(dllPath) + 1, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (pDllPath == NULL)
    {
		printf("Failed to allocate memory. Do I have PROCESS_VM_OPERATION?\n");

        return 1;
    }

    if (!WriteProcessMemory(hProcess, pDllPath, dllPath, strlen(dllPath) + 1, NULL))
    {
		printf("Failed to write memory. Do I have PROCESS_VM_WRITE?\n");

        return 1;
    }

	// con struct shell code
    memcpy(bShellCode + 6, &pDllPath, sizeof(pDllPath));
    memcpy(bShellCode + 11, &pLoadLibraryExA, sizeof(pLoadLibraryExA));

    int sizes[] = { 1, 2, 2, 5, 5, 2, 1 }, * p = sizes, off = 0;

    for (; p < sizes + sizeof(sizes) / sizeof(int); off += *p++) {
        for (int i = 0; i < *p; i++) printf("%02X ", bShellCode[off + i]);
        printf("\n");
    }

    if (!WriteProcessMemory(hProcess, pRtlLogStackBackTrace, bShellCode, sizeof(bShellCode), NULL))
    {
		printf("Failed to write memory. Do I have PROCESS_VM_WRITE?\n");

        return 1;
    }

    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)pRtlLogStackBackTrace, NULL, 0, NULL);
    if (hThread == NULL)
    {
		printf("Failed to create thread. Do I have PROCESS_CREATE_THREAD?\n");

        return 1;
    }

    WaitForSingleObject(hThread, INFINITE);

    printf("Success!\n");


    CloseHandle(hProcess);
    return 0;
}
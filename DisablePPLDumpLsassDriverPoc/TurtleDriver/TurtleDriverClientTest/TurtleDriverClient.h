#pragma once

//#include <ntifs.h>
//#include <ntddk.h>


#define IOCTL_TURTLEDRIVER_TESTER CTL_CODE(FILE_DEVICE_UNKNOWN,0x800,METHOD_NEITHER,FILE_ANY_ACCESS)
#define IOCTL_TURTLEDRIVER_CHANGE_PPL CTL_CODE(FILE_DEVICE_UNKNOWN,0x801,METHOD_NEITHER,FILE_ANY_ACCESS)


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
;

/*
UNICODE_STRING TurtleDriverName = RTL_CONSTANT_STRING(L"\\Device\\TurtleDriver");
UNICODE_STRING TurtleDeviceName = RTL_CONSTANT_STRING(L"\\Device\\TurtleDriver");
UNICODE_STRING TurtleDeviceSymLink = RTL_CONSTANT_STRING(L"\\??\\TurtleDriver");
*/
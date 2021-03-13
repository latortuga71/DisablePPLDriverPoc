#pragma once

#include <ntifs.h>
#include <ntddk.h>
#include "IOCTL.h"


UNICODE_STRING TurtleDeviceName = RTL_CONSTANT_STRING(L"\\Device\\TurtleDriver");
UNICODE_STRING TurtleDeviceSymLink = RTL_CONSTANT_STRING(L"\\??\\TurtleDriver");


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


NTSTATUS CompleteIrp(PIRP Irp, NTSTATUS status = STATUS_SUCCESS, ULONG_PTR info = 0) {
	Irp->IoStatus.Status = status;
	Irp->IoStatus.Information = info;
	IoCompleteRequest(Irp,0);
	return status;
}


NTSTATUS TurtleDriverChangeProcessProtection(SIZE_T bufferInSize, PVOID bufferIn, SIZE_T bufferOutSize, PVOID bufferOut) {
	NTSTATUS status = STATUS_SUCCESS;
	// check buffers
	if (bufferInSize != sizeof(ProcessData)) {
		KdPrint(("TURTLE DRIVER -> Buffer in size not size of process data struct\n"));
		return STATUS_FAIL_CHECK;
	}
	// set variables
	ProcessData* inProcStruct = (ProcessData*)bufferIn;
	//ProcessData* outProcStruct = (ProcessData*)bufferOut;
	PEPROCESS targetProcess = NULL;
	//PROCESS_SIGNATURE_PROTECTION* pSignatureProtection = NULL;
	//PULONG pFlags2 = NULL;
	// lookup pid
	status = PsLookupProcessByProcessId((HANDLE)inProcStruct->ProcessId, &targetProcess);
	PROCESS_SIGNATURE_PROTECTION* SigProtect = (PROCESS_SIGNATURE_PROTECTION*)(((ULONG_PTR)targetProcess) + 0x878); // <- this offset only works for specific version of windows
	SigProtect->SignatureLevel = inProcStruct->SigProtection.SignatureLevel; //0x3f;
	SigProtect->SectionSignatureLevel = inProcStruct->SigProtection.SectionSignatureLevel;//0x3f;
	SigProtect->Protection = inProcStruct->SigProtection.Protection;
	//SigProtect->Protection.Type = //2;
	//SigProtect->Protection.Audit = //0;
	//SigProtect->Protection.Signer = //6;
	if (!NT_SUCCESS(status)) {
		KdPrint(("TURTLE DRIVER -> Failed to lookup process by pid!\n"));
		return STATUS_FAIL_CHECK;
	}
	KdPrint(("TURTLE DRIVER -> Sucessfully looked up process by pid\n"));
	UNREFERENCED_PARAMETER(bufferOutSize);
	UNREFERENCED_PARAMETER(bufferOut);
	//UNREFERENCED_PARAMETER(bufferInSize);
	//UNREFERENCED_PARAMETER(bufferIn);
	//KdPrint(("TURTLE DRIVER -> Attempting to change process protection\n"));
	ObDereferenceObject(targetProcess);
	return status;
}



NTSTATUS TurtleDriverTester(SIZE_T bufferInSize,PVOID bufferIn,SIZE_T bufferOutSize,PVOID bufferOut) {
	UNREFERENCED_PARAMETER(bufferOutSize);
	UNREFERENCED_PARAMETER(bufferOut);
	NTSTATUS status = STATUS_SUCCESS;
	if (bufferInSize != sizeof(ProcessData)) {
		KdPrint(("TURTLE DRIVER -> Buffer in size not size of process data struct\n"));
		return STATUS_FAIL_CHECK;
	}
	// cast inbuffer to ProcessData
	ProcessData* inProcStruct = (ProcessData*)bufferIn;
	KdPrint(("TURTLE DRIVER -> Process ID Provided ByClient ::: %lu\n", inProcStruct->ProcessId));
	ProcessData* outProcStruct = (ProcessData*)bufferOut;
	// set output struct
	outProcStruct->ProcessId = inProcStruct->ProcessId;
	///
	KdPrint(("TURTLE DRIVER -> Process ID Sent back to client ::: %lu\n", outProcStruct->ProcessId));
	return status;
}

#include "TurtleDriver.h"

void UnloadTurtleDriver(_In_ PDRIVER_OBJECT DriverObject) {
	// undo DriverInit in reverse
	IoDeleteSymbolicLink(&TurtleDeviceSymLink);
	IoDeleteDevice(DriverObject->DeviceObject);
	KdPrint(("UNLOADED"));
}

_Use_decl_annotations_ NTSTATUS TurtleDriverCreateClose(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
	UNREFERENCED_PARAMETER(DeviceObject);
	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = 0;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}

_Use_decl_annotations_ NTSTATUS TurtleDriverDeviceControl(PDEVICE_OBJECT DeviceObject,  PIRP Irp) {
	UNREFERENCED_PARAMETER(DeviceObject);
	// GetIOStackLocation
	auto stack = IoGetCurrentIrpStackLocation(Irp);
	auto status = STATUS_SUCCESS;
	// Variables for use in switch statement
	PVOID BufferIn, BufferOut;
	size_t BufferInSize, BufferOutSize;
	// if stack got irp location
	if (stack) {
		BufferInSize = stack->Parameters.DeviceIoControl.InputBufferLength;
		BufferOutSize = stack->Parameters.DeviceIoControl.OutputBufferLength;
		BufferIn = stack->Parameters.DeviceIoControl.Type3InputBuffer;
		BufferOut = Irp->UserBuffer;
		// Switch statememt
		switch (stack->Parameters.DeviceIoControl.IoControlCode) {
		case IOCTL_TURTLEDRIVER_TESTER:
		{
			status = TurtleDriverTester(BufferInSize, BufferIn, BufferOutSize, BufferOut);
		}
		case IOCTL_TURTLEDRIVER_CHANGE_PPL:
		{
			status = TurtleDriverChangeProcessProtection(BufferInSize, BufferIn, BufferOutSize, BufferOut);
		}
		default:
			status = STATUS_INVALID_DEVICE_REQUEST;
			break;
		}
	}
	CompleteIrp(Irp, status);
	KdPrint(("TURTLE DRIVER -> COMPLETED IRP\n"));
	return STATUS_SUCCESS;
}
extern "C" NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath) {
	UNREFERENCED_PARAMETER(RegistryPath);
	NTSTATUS status = STATUS_SUCCESS;
	// Set Unload Routine
	DriverObject->DriverUnload = UnloadTurtleDriver;
	// Set Dispatch Routines
	DriverObject->MajorFunction[IRP_MJ_CREATE] = TurtleDriverCreateClose;
	DriverObject->MajorFunction[IRP_MJ_CLOSE] = TurtleDriverCreateClose;
	DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = TurtleDriverDeviceControl;
	// Create Device Object
	PDEVICE_OBJECT DeviceObject;
	status = IoCreateDevice(DriverObject,0,&TurtleDeviceName,FILE_DEVICE_UNKNOWN,0,FALSE,&DeviceObject);
	if (!NT_SUCCESS(status)) {
		KdPrint(("Failed to create device object (0x%08X)", status));
		return status;
	}
	// Create sym link to object
	status = IoCreateSymbolicLink(&TurtleDeviceSymLink, &TurtleDeviceName);
	if (!NT_SUCCESS(status)) {
		KdPrint(("Failed to create symLink to device (0x%08X)",status));
		IoDeleteDevice(DeviceObject);
		return status;
	}
	KdPrint(("LOADED"));
	return STATUS_SUCCESS;

}
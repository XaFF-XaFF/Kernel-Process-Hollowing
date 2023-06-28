#pragma once
#include <ntddk.h>

#define MAX_PATH 260
#define PS_INHERIT_HANDLES 4
#define ENCRYPTION_KEY "1234567890"

#define IMAGE_DIRECTORY_ENTRY_BASERELOC 5
#define THREAD_PREVIOUSMODE_OFFSET 0x232
#define TOKEN 0x4b8

typedef NTSTATUS(NTAPI* ZwCreateProcessExPtr)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, HANDLE, ULONG, HANDLE, HANDLE, HANDLE, BOOLEAN);

typedef NTSTATUS(NTAPI* ZwCreateProcessPtr)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, HANDLE, BOOLEAN, HANDLE, HANDLE, HANDLE);

typedef NTSTATUS(NTAPI* NtReadVirtualMemoryPtr)(HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T);

typedef NTSTATUS(NTAPI* NtWriteVirtualMemoryPtr)(HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T);

typedef DWORD(NTAPI* PTHREAD_START_ROUTINE)(
	PVOID lpThreadParameter);

typedef NTSTATUS(NTAPI* NtCreateThreadExPtr)(
	PHANDLE hThread,
	ACCESS_MASK DesiredAccess,
	PVOID ObjectAttributes,
	HANDLE ProcessHandle,
	PTHREAD_START_ROUTINE lpStartAddress,
	PVOID lpParameter,
	DWORD Flags,
	SIZE_T StackZeroBits,
	SIZE_T SizeOfStackCommit,
	SIZE_T SizeOfStackReserve,
	PVOID lpBytesBuffer);

extern "C"
NTSYSAPI NTSTATUS NTAPI ZwSetInformationProcess(
	__in HANDLE ProcessHandle,
	__in PROCESSINFOCLASS ProcessInformationClass,
	__in_bcount(ProcessInformationLength) PVOID ProcessInformation,
	__in ULONG ProcessInformationLength);

extern "C"
_Must_inspect_result_
NTSYSAPI NTSTATUS NTAPI ZwAdjustPrivilegesToken(
	_In_ HANDLE TokenHandle,
	_In_ BOOLEAN DisableAllPrivileges,
	_In_opt_ PTOKEN_PRIVILEGES NewState,
	_In_ ULONG BufferLength,
	_Out_writes_bytes_to_opt_(BufferLength, *ReturnLength) PTOKEN_PRIVILEGES PreviousState,
	_When_(PreviousState != NULL, _Out_) PULONG ReturnLength
);
typedef struct BASE_RELOCATION_BLOCK {
	DWORD PageAddress;
	DWORD BlockSize;
} BASE_RELOCATION_BLOCK, * PBASE_RELOCATION_BLOCK;

typedef struct BASE_RELOCATION_ENTRY {
	USHORT Offset : 12;
	USHORT Type : 4;
} BASE_RELOCATION_ENTRY, * PBASE_RELOCATION_ENTRY;


typedef NTSTATUS(NTAPI* NtCreateUserProcessPtr)(PHANDLE, PHANDLE, ACCESS_MASK, ACCESS_MASK, POBJECT_ATTRIBUTES, POBJECT_ATTRIBUTES, ULONG, ULONG, PRTL_USER_PROCESS_PARAMETERS, PVOID, PVOID);

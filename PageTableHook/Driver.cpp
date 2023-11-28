#include "Base.h"
#include "pageHook.h"

using fnNtCreateFile = decltype(&NtCreateFile);
fnNtCreateFile  g_OriNtCreateFile;

NTSTATUS NTAPI MyNtCreateFile(
	PHANDLE            FileHandle,
	ACCESS_MASK        DesiredAccess,
	POBJECT_ATTRIBUTES ObjectAttributes,
	PIO_STATUS_BLOCK   IoStatusBlock,
	PLARGE_INTEGER     AllocationSize,
	ULONG              FileAttributes,
	ULONG              ShareAccess,
	ULONG              CreateDisposition,
	ULONG              CreateOptions,
	PVOID              EaBuffer,
	ULONG              EaLength
) {
	DbgPrintEx(77, 0, "[+]create file\r\n");
	return g_OriNtCreateFile(FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, AllocationSize, FileAttributes, ShareAccess, CreateDisposition, CreateOptions, EaBuffer, EaLength);
}

void unload(PDRIVER_OBJECT pDriveObj) {
	PageTableHookManager::GetInstance()->clean();
	ExFreePoolWithTag(PageTableHookManager::GetInstance(), 'p');
}

EXTERN_C NTSTATUS DriverEntry(PDRIVER_OBJECT pDriverObject, UNICODE_STRING unicodeString)  {
	HANDLE pid = PageTableHookManager::GetInstance()->test();
	if (pid == 0) {
		return STATUS_UNSUCCESSFUL;
	}
	g_OriNtCreateFile = &NtCreateFile;
	PageTableHookManager::GetInstance()->pte_inline_hook(pid, (void**)&g_OriNtCreateFile, MyNtCreateFile);
	pDriverObject->DriverUnload = unload;
	return STATUS_SUCCESS;
}
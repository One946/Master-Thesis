#pragma once
#include "pin.H"

namespace W {
#define _WINDOWS_H_PATH_ C:/Program Files/Windows Kits/10/Include/10.0.17763.0/um
#include <Windows.h>
#include <ntstatus.h>
#include <subauth.h>
}
using namespace std;
//NLS FILES BEGIN
#define PTR_ADD_OFFSET(Pointer, Offset)   ((W::PVOID)((W::ULONG_PTR)(Pointer) + (W::ULONG_PTR)(Offset)))
#define PH_MODULE_TYPE_MAPPED_FILE 2
#define PH_MODULE_TYPE_MAPPED_IMAGE 5
typedef enum _MEMORY_INFORMATION_CLASS
{
	MemoryBasicInformation, // MEMORY_BASIC_INFORMATION
	MemoryWorkingSetInformation, // MEMORY_WORKING_SET_INFORMATION
	MemoryMappedFilenameInformation, // UNICODE_STRING
	MemoryRegionInformation, // MEMORY_REGION_INFORMATION
	MemoryWorkingSetExInformation, // MEMORY_WORKING_SET_EX_INFORMATION
	MemorySharedCommitInformation, // MEMORY_SHARED_COMMIT_INFORMATION
	MemoryImageInformation, // MEMORY_IMAGE_INFORMATION
	MemoryRegionInformationEx, // MEMORY_REGION_INFORMATION
	MemoryPrivilegedBasicInformation,
	MemoryEnclaveImageInformation, // MEMORY_ENCLAVE_IMAGE_INFORMATION // since REDSTONE3
	MemoryBasicInformationCapped, // 10
	MemoryPhysicalContiguityInformation, // MEMORY_PHYSICAL_CONTIGUITY_INFORMATION // since 20H1
	MaxMemoryInfoClass
} MEMORY_INFORMATION_CLASS;

//NtQueryVirtualMemory
typedef long (NTAPI* _NtQueryVirtualMemory)(
	W::HANDLE                   ProcessHandle,
	W::PVOID                    BaseAddress,
	MEMORY_INFORMATION_CLASS MemoryInformationClass,
	W::PVOID                    MemoryInformation,
	W::SIZE_T                   MemoryInformationLength,
	W::PSIZE_T                  ReturnLength
	);
// dynamically imported functions
W::PVOID GetLibraryProcAddress(W::PSTR LibraryName, W::PSTR ProcName);
int long PhGetProcessMappedFileName(_In_ W::HANDLE ProcessHandle, _In_ W::PVOID BaseAddress, _Out_ wchar_t *FileName);
VOID PhpEnumGenericMappedFilesAndImages(W::HANDLE ProcessHandle);

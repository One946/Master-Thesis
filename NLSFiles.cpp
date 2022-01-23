#include "pin.H"
#include "MappedFilesHeader.h"

/****************************MAPPED FILES******************************************/
// https://stackoverflow.com/questions/28859456/function-returning-function-is-not-allowed-in-typedef-foobar
 //since NTSTATUS is actually a typedef to LONG. The workaround was to replace the function return type from NTSTATUS to LONG(but ideally includes should be fixed so that NTSTATUS is resoved).
//*******************************************************************
//MApped Files
//******************************************************************* 

W::PVOID GetLibraryProcAddress(W::PSTR LibraryName, W::PSTR ProcName)
{
	return W::GetProcAddress(W::GetModuleHandleA(LibraryName), ProcName);
}
int long PhGetProcessMappedFileName(_In_ W::HANDLE ProcessHandle, _In_ W::PVOID BaseAddress, _Out_ wchar_t *FileName) {
	int long status;
	W::SIZE_T bufferSize;
	W::SIZE_T returnLength;
	W::PWSTR buffer; //W::PUNICODE_STRING

	returnLength = 0;
	bufferSize = 0x100;
	buffer = (W::PWSTR) malloc(bufferSize);

	status = NtQueryVirtualMemory(
		ProcessHandle,
		BaseAddress,
		MemoryMappedFilenameInformation,
		buffer,
		bufferSize,
		&returnLength
	);
	printf("status1 : %x ", status);

	if (status == 0x80000005 && returnLength > 0) // returnLength > 0 required for MemoryMappedFilename on Windows 7 SP1 (dmex)
	{
		free(buffer);
		bufferSize = returnLength;
		buffer = (W::PWSTR) malloc(bufferSize);

		status = NtQueryVirtualMemory(
			ProcessHandle,
			BaseAddress,
			MemoryMappedFilenameInformation,
			buffer,
			bufferSize,
			&returnLength
		);
	}

	printf("status2 : %x ", status);
	if (status != 0)
	{
		printf("status3 : %x \n", status);
		free(buffer);
		return status;
	}


	printf("status4 : %x \n", status);
	swprintf(FileName, 128, L"%ls", buffer);
	free(buffer);

	return status;
}

VOID PhpEnumGenericMappedFilesAndImages(W::HANDLE ProcessHandle) {
	W::BOOLEAN querySucceeded;
	W::PVOID baseAddress;
	W::MEMORY_BASIC_INFORMATION basicInfo;
	baseAddress = (W::PVOID)0;
	if ((NtQueryVirtualMemory(
		ProcessHandle,
		baseAddress,
		MemoryBasicInformation,
		&basicInfo,
		sizeof(W::MEMORY_BASIC_INFORMATION),
		NULL
	)))
	{
		return; // consider changing if check using error status=c0000098 or status!=0
	}
	querySucceeded = TRUE;
	while (querySucceeded)
	{
		W::PVOID allocationBase;
		W::SIZE_T allocationSize;
		W::ULONG type;
		wchar_t fileName[128];

		if (basicInfo.Type == MEM_MAPPED || basicInfo.Type == MEM_IMAGE)
		{
			if (basicInfo.Type == MEM_MAPPED)
				type = PH_MODULE_TYPE_MAPPED_FILE;
			else
				type = PH_MODULE_TYPE_MAPPED_IMAGE;
			// Find the total allocation size.
			allocationBase = basicInfo.AllocationBase;
			allocationSize = 0;
			do {
				baseAddress = PTR_ADD_OFFSET(baseAddress, basicInfo.RegionSize);
				allocationSize += basicInfo.RegionSize;
				if ((NtQueryVirtualMemory(ProcessHandle, baseAddress, MemoryBasicInformation, &basicInfo, sizeof(W::MEMORY_BASIC_INFORMATION), NULL)))
				{
					querySucceeded = FALSE;
					break;
				}
			} while (basicInfo.AllocationBase == allocationBase);

			if ((PhGetProcessMappedFileName(ProcessHandle, allocationBase, fileName)) != 0) {
				continue;
			}
			wprintf(L"Filename: %ls \n", fileName);
			char* type_s = (basicInfo.Type == MEM_MAPPED) ? "mapped" : "image";
			printf("Base, size, type, basicInfo.Type: %d %d %s %d \n\n", allocationBase, allocationSize, type_s, basicInfo.Type);
		}
		else {
			baseAddress = PTR_ADD_OFFSET(baseAddress, basicInfo.RegionSize);
			if ((NtQueryVirtualMemory(
				ProcessHandle,
				baseAddress,
				MemoryBasicInformation,
				&basicInfo,
				sizeof(W::MEMORY_BASIC_INFORMATION),
				NULL
			)))
			{
				querySucceeded = FALSE;
			}
		}
	}
}

/****************Correct Handle************************/
//	NtQueryVirtualMemory = (_NtQueryVirtualMemory)GetLibraryProcAddress("ntdll.dll", "NtQueryVirtualMemory");
//	W::HANDLE curProc = W::OpenProcess(PROCESS_ALL_ACCESS, FALSE, PIN_GetPid()); //W::GetCurrentProcess();
//	PhpEnumGenericMappedFilesAndImages(curProc);
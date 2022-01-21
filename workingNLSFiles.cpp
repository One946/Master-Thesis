#include "pin.H"
#include <iostream>
#include <fstream>
#include <stdlib.h>
#include <string>
//NLS FILES BEGIN
#define PTR_ADD_OFFSET(Pointer, Offset)   ((W::PVOID)((W::ULONG_PTR)(Pointer) + (W::ULONG_PTR)(Offset)))
#define PH_MODULE_TYPE_MAPPED_FILE 2
#define PH_MODULE_TYPE_MAPPED_IMAGE 5
//NLS FILES END

namespace W {
#define _WINDOWS_H_PATH_ C:/Program Files/Windows Kits/10/Include/10.0.17763.0/um
#include <Windows.h>
	//#include <ntdef.h>
#include <ntstatus.h>
#include <subauth.h>
}
using namespace std;
//*******************************************************************
//TYPEDEF
//*******************************************************************
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
typedef struct mem_regions_t {
	int id;
	int high;
	int low;
	string name;
	W::DWORD protection;
	W::DWORD  pagesType;
	bool unloaded;
}mem_regions;
typedef struct mem_map_t {
	VOID * address;
	char op;
	int id;
}mem_map;
typedef unsigned char MEM_MASK;
/****************************MAPPED FILES******************************************/

typedef long (NTAPI* _NtQueryVirtualMemory)(
	W::HANDLE                   ProcessHandle,
	W::PVOID                    BaseAddress,
	MEMORY_INFORMATION_CLASS MemoryInformationClass,
	W::PVOID                    MemoryInformation,
	W::SIZE_T                   MemoryInformationLength,
	W::PSIZE_T                  ReturnLength
);
// dynamically imported functions
_NtQueryVirtualMemory NtQueryVirtualMemory;

// https://stackoverflow.com/questions/28859456/function-returning-function-is-not-allowed-in-typedef-foobar
/****************************MAPPED FILES******************************************/
//*******************************************************************
//GLOBAL VARIABLES
//*******************************************************************
KNOB< string > KnobOutputFile(KNOB_MODE_WRITEONCE, "pintool", "o", "migatte2.out", "specify file name");
ofstream TraceFile;
int img_counter = 0;
mem_regions mem_array[100]; //array in which i store valuable informations about the images
int counter = 0; //counter for instructions
int unkId = 0; //index for unknown regions in memory
mem_map op_map[10000];

static map<std::string, int> fMap;
//*******************************************************************
//MApped Files
//******************************************************************* 
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
	if (status!=0)
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
		return;
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

			if ((PhGetProcessMappedFileName(ProcessHandle, allocationBase, fileName))!=0) {
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



W::PVOID GetLibraryProcAddress(W::PSTR LibraryName, W::PSTR ProcName)
{
	return W::GetProcAddress(W::GetModuleHandleA(LibraryName), ProcName);
}
/********************************************************************/
/**************************Instrumentations**************************/
/********************************************************************/

VOID parse_funcsyms(IMG img, VOID *v) {
	if (!IMG_Valid(img)) return;
	W::MEMORY_BASIC_INFORMATION memInfo;
	//building up an array in which i store valuable informations about the images
	mem_array[img_counter].id = IMG_Id(img) - 1;
	mem_array[img_counter].high = IMG_HighAddress(img);
	mem_array[img_counter].low = IMG_LowAddress(img);
	mem_array[img_counter].name = IMG_Name(img);
	W::VirtualQuery((W::LPCVOID)IMG_EntryAddress(img), &memInfo, sizeof(memInfo));
	mem_array[img_counter].protection = memInfo.Protect;
	mem_array[img_counter].pagesType = memInfo.Type;
	mem_array[img_counter].unloaded = 0;
	img_counter++;
}

VOID ImageUnload(IMG img, VOID* v) {
	int index = 0;
	for (int i = 0; i < img_counter; i++) {
		if (IMG_Id(img) - 1 == mem_array[i].id) {
			mem_array[i].unloaded = 1;
			index = i;
			TraceFile << mem_array[i].name << " \n";
		}
	}
}

VOID CreateFileWArg(CHAR * name, wchar_t * filename)
{
	TraceFile << name << "(" << filename << ")" << endl;
}
VOID CreateFileWafter(ADDRINT ret)
{
	TraceFile << "\tReturned handle: " << ret << endl;
}
VOID Fini(INT32 code, VOID* v)
{
	if (TraceFile.is_open())
	{
		TraceFile << "************************************* \n";
		for (int i = 0; i < img_counter; i++) {
			TraceFile << "img name: " << mem_array[i].name << " img ID: " << mem_array[i].id << " is: " << mem_array[i].unloaded << " \n";
			TraceFile << " img high " << mem_array[i].high << " img low " << mem_array[i].low << "\n";
		}
		TraceFile.close();
	}
}
/* ===================================================================== */
/* Print Help Message                                                    */
/* ===================================================================== */
INT32 Usage()
{
	PIN_ERROR("This tool prints a log of image load and unload events\n" + KNOB_BASE::StringKnobSummary() + "\n");
	return -1;
}
/* ===================================================================== */
/* Main                                                                  */
/* ===================================================================== */
int main(int argc, char* argv[]) {
	// Initialize symbol processing
	PIN_InitSymbols();
	// Initialize pin
	if (PIN_Init(argc, argv)) return Usage();
	TraceFile.open(KnobOutputFile.Value().c_str());
	//PIN_AddThreadStartFunction(OnThreadStart, NULL);
	// Load ntdll dynamically
	NtQueryVirtualMemory = (_NtQueryVirtualMemory)GetLibraryProcAddress("ntdll.dll", "NtQueryVirtualMemory");
//	printf("PID: %d \n", PIN_GetPid());
	//printf("PID: %d", CHILD_PROCESS_GetId(CHILD_PROCESS));
	W::HANDLE curProc = W::OpenProcess(PROCESS_ALL_ACCESS, FALSE, PIN_GetPid()); //W::GetCurrentProcess();
	//printf("handle1: %d \n", curProc);
	PhpEnumGenericMappedFilesAndImages(curProc);
	PIN_AddFiniFunction(Fini, 0);
	// Start the program, never returns
	PIN_StartProgram();
	return 0;
}
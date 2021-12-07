#include "pin.H"
#include <iostream>
#include <fstream>
#include <stdlib.h>
#include <string>
//mem array begin
#define MEM_READABLE			0x1
#define MEM_WRITEABLE			0x2
#define MEM_EXECUTABLE			0x4
#define MEM_ACCESSIBLE			0x8
#define MEM_IS_READABLE(x)		((x) & (MEM_READABLE | MEM_ACCESSIBLE))
#define MEM_IS_WRITEABLE(x)		((x) & (MEM_WRITEABLE | MEM_ACCESSIBLE))
#define MEM_IS_EXECUTABLE(x)	((x) & (MEM_EXECUTABLE| MEM_ACCESSIBLE))
#define MEM_GET_PAGE(addr)		((addr) >> OS_PAGE_OFFSET_BITS)
#define MAXADDR 0xffffffff
#define OS_PAGE_SIZE			4096
#define OS_PAGE_OFFSET_BITS		12
#define OS_NUM_PAGES			(1 << (32 - OS_PAGE_OFFSET_BITS))
#define OS_CLEAR_MASK			0xFFFFF000
#define OS_ALLOCATION_SIZE		65536
//mem array end*/
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
enum {
	VirtualQuery_INDEX = 0,
	VirtualQueryEx_INDEX,
	CoTaskMemAlloc_INDEX,
	GlobalAlloc_INDEX,
	HeapAlloc_INDEX,
	LocalAlloc_INDEX,
	malloc_INDEX,
	new_INDEX,
	VirtualAlloc_INDEX
};
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

typedef int long(NTAPI* _NtQueryVirtualMemory)(
	W::HANDLE                   ProcessHandle,
	W::PVOID                    BaseAddress,
	MEMORY_INFORMATION_CLASS MemoryInformationClass,
	W::PVOID                    MemoryInformation,
	W::SIZE_T                   MemoryInformationLength,
	W::PSIZE_T                  ReturnLength
	);
// dynamically imported functions
_NtQueryVirtualMemory NtQueryVirtualMemory;

/* https://stackoverflow.com/questions/28859456/function-returning-function-is-not-allowed-in-typedef-foobar
typedef int long(NTAPI* _NtQueryVirtualMemory)( //since NTSTATUS is actually a typedef to LONG. The workaround was to replace the function return type from NTSTATUS to LONG(but ideally includes should be fixed so that NTSTATUS is resoved).
	W::HANDLE                   ProcessHandle,
	W::PVOID                    BaseAddress,
	W::PVOID                    MemoryInformation,
	W::SIZE_T                   MemoryInformationLength,
	W::PSIZE_T                  ReturnLength
	);/*
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
// pointers for memory function results
int* p2BuffVQ;
int* p2BuffVQEx;
ADDRINT CTMAlloc;
ADDRINT GAlloc;
ADDRINT HAlloc;
ADDRINT LAlloc;
ADDRINT mAlloc;
ADDRINT VAlloc;

static map<std::string, int> fMap;
//*******************************************************************
//MApped Files
//******************************************************************* 
W::PVOID GetLibraryProcAddress(W::PSTR LibraryName, W::PSTR ProcName)
{
	return W::GetProcAddress(W::GetModuleHandleA(LibraryName), ProcName);
}

int long PhGetProcessMappedFileName( _In_ W::HANDLE ProcessHandle,  _In_ W::PVOID BaseAddress, _Out_ wchar_t *FileName){
	int long status;
	W::SIZE_T bufferSize;
	W::SIZE_T returnLength;
	void* buffer; //W::PUNICODE_STRING

	returnLength = 0;
	bufferSize = 0x100;
	buffer = malloc(bufferSize);

	status = NtQueryVirtualMemory(
		ProcessHandle,
		BaseAddress,
		MemoryMappedFilenameInformation,
		buffer,
		bufferSize,
		&returnLength
	);

	if (status == 0x80000005 && returnLength > 0) // returnLength > 0 required for MemoryMappedFilename on Windows 7 SP1 (dmex)
	{
		free(buffer);
		bufferSize = returnLength;
		buffer = malloc(bufferSize);

		status = NtQueryVirtualMemory(
			ProcessHandle,
			BaseAddress,
			MemoryMappedFilenameInformation,
			buffer,
			bufferSize,
			&returnLength
		);
	}

	if (!(status))
	{
		free(buffer);
		return status;
	}

	//swprintf(FileName, 64, L"%s", buffer->Buffer);
	free(buffer);

	return status;
}


VOID PhpEnumGenericMappedFilesAndImages(W::HANDLE ProcessHandle) {
	TraceFile << "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAIPULLUP \n";
	TraceFile << (void*)ProcessHandle << "\n";
	W::BOOLEAN querySucceeded;
	W::PVOID baseAddress;
	W::MEMORY_BASIC_INFORMATION basicInfo;

	baseAddress = (W::PVOID)0;
	//TraceFile << "++++++"<<(NtQueryVirtualMemory(ProcessHandle, baseAddress, MemoryBasicInformation, &basicInfo, sizeof(W::MEMORY_BASIC_INFORMATION), NULL)) << "\n";
	if ((NtQueryVirtualMemory(
		ProcessHandle,
		baseAddress,
		MemoryBasicInformation,
		&basicInfo,
		sizeof(W::MEMORY_BASIC_INFORMATION),
		NULL
	)))
	{
		//TraceFile << "i'm in the if 1 statement \n";
		return;
	}

	querySucceeded = TRUE;

	while (querySucceeded)
	{
		W::PVOID allocationBase;
		W::SIZE_T allocationSize;
		W::ULONG type;
		wchar_t fileName[64];
		W::BOOLEAN cont;

		if (basicInfo.Type == MEM_MAPPED || basicInfo.Type == MEM_IMAGE)
		{
			//TraceFile << "i'm in the if 2 statement \n";
			if (basicInfo.Type == MEM_MAPPED)
				type = PH_MODULE_TYPE_MAPPED_FILE;
			else
				type = PH_MODULE_TYPE_MAPPED_IMAGE;

			// Find the total allocation size.

			allocationBase = basicInfo.AllocationBase;
			allocationSize = 0;

			do
			{
				baseAddress = PTR_ADD_OFFSET(baseAddress, basicInfo.RegionSize);
				allocationSize += basicInfo.RegionSize;

				if ((NtQueryVirtualMemory(ProcessHandle, baseAddress, MemoryBasicInformation, &basicInfo, sizeof(W::MEMORY_BASIC_INFORMATION), NULL)))
				{
					//TraceFile << "i'm in the if 3 statement \n";
					querySucceeded = FALSE;
					break;
				}
			} while (basicInfo.AllocationBase == allocationBase);

			// Check if we have a duplicate base address.
			/*if (PhFindEntryHashtable(BaseAddressHashtable, &allocationBase))
			{
				continue;
			}*/

			if ((PhGetProcessMappedFileName( ProcessHandle, allocationBase, fileName)))
			{
				continue;
			}

			wprintf(L"Filename: %s\n", fileName);
			char* type_s = (basicInfo.Type == MEM_MAPPED) ? "mapped" : "image";
			printf("Base, size, type: %p %x %s\n", allocationBase, allocationSize, type_s);
		}
		else
		{
			//TraceFile << "i'm in the else statement";
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


/********************************************************************/
/****************************ValidateMemory**********************************/
/********************************************************************/
BOOL  validateRead(VOID * ip, VOID * addr) {
	bool found = 1; // to use if then call i have to return 1 if i want to execute thencall
	for (int i = 0; i < img_counter; i++) {
		if ((int)addr < mem_array[i].high && (int)addr >= mem_array[i].low) {
			found = 0; // to no use the then call i have to return 0
			return found;
		}
	}
	return found;
}

VOID  missRead(VOID* ip, VOID * addr) {
	int mem_reg = 0;
	W::MEMORY_BASIC_INFORMATION memInfo;
	W::VirtualQuery((W::LPCVOID)addr, &memInfo, sizeof(memInfo));
	if (img_counter < 100) {
		TraceFile << "OK I PULL UP 3 \n";
		mem_reg = (int)memInfo.BaseAddress + memInfo.RegionSize;
		mem_array[img_counter].protection = memInfo.Protect;
		mem_array[img_counter].id = img_counter;
		mem_array[img_counter].high = mem_reg - 1;
		mem_array[img_counter].low = (int)memInfo.BaseAddress;
		mem_array[img_counter].name = "Unknown";
		mem_array[img_counter].protection = memInfo.Protect;
		mem_array[img_counter].pagesType = memInfo.Type;
		mem_array[img_counter].unloaded = 0;
		img_counter++;
	}
}

VOID RecordMemR(VOID * addr) {
	int mem_reg = 0;
	W::MEMORY_BASIC_INFORMATION memInfo;
	bool done = FALSE;
	for (int i = 0; i < img_counter; i++) {
		if ((int)addr < mem_array[i].high && (int)addr >= mem_array[i].low) {
			op_map[counter].address = addr;
			op_map[counter].op = 'R';
			op_map[counter].id = counter;
			done = TRUE;
		}
	}
	if (!done) {
		W::VirtualQuery((W::LPCVOID)addr, &memInfo, sizeof(memInfo));
		if (img_counter < 100) {
			mem_reg = (int)memInfo.BaseAddress + memInfo.RegionSize;
			mem_array[img_counter].protection = memInfo.Protect;
			mem_array[img_counter].id = img_counter;
			mem_array[img_counter].high = mem_reg - 1;
			mem_array[img_counter].low = (int)memInfo.BaseAddress;
			mem_array[img_counter].name = "Unknown";
			mem_array[img_counter].protection = memInfo.Protect;
			mem_array[img_counter].pagesType = memInfo.Type;
			mem_array[img_counter].unloaded = 0;
			img_counter++;
		}
	}
}

//function to analyze memory accesses
VOID ValidateMemory(INS ins, VOID *v) {
	UINT32 mem_operands = INS_MemoryOperandCount(ins);
	for (UINT32 memOp = 0; memOp < mem_operands; memOp++)
	{
		if (INS_MemoryOperandIsRead(ins, memOp)) {
			INS_InsertIfCall(
				ins, IPOINT_BEFORE,
				(AFUNPTR)validateRead,
				IARG_INST_PTR,
				IARG_MEMORYOP_EA, memOp,
				IARG_END);
			INS_InsertThenCall(
				ins, IPOINT_BEFORE,
				(AFUNPTR)missRead,
				IARG_INST_PTR,
				IARG_MEMORYOP_EA, memOp,
				IARG_END
			);
		}
	}
}
/********************************************************************/
/****************************THREDS**********************************/
/********************************************************************/
VOID findStacks(CONTEXT *ctxt) {
	TraceFile << "in findStacks\n";
	int base;
	int max;
	int index;
	int todo = 1;
	// register stack region
	ADDRINT currentSP = PIN_GetContextReg(ctxt, REG_STACK_PTR);
	ADDRINT end = currentSP;
	W::MEMORY_BASIC_INFORMATION memInfo;
	W::VirtualQuery((W::LPCVOID)currentSP, &memInfo, sizeof(memInfo));
	base = (int)memInfo.BaseAddress;
	max = (int)memInfo.RegionSize + (int)memInfo.BaseAddress - 1;
	if (img_counter < 100) {// still not working, i have to figure out how to add regions once while checking the whole array
		for (int i = 0; i < img_counter; i++) {
			if ((int)currentSP < mem_array[i].high && (int)currentSP >= mem_array[i].low) {
				TraceFile << "checking todo";
				todo = 0;
				index = i;
				break;
			}
		}
		if (todo) {
			int mem_reg = (int)memInfo.BaseAddress + memInfo.RegionSize;
			mem_array[img_counter].protection = memInfo.Protect;
			mem_array[img_counter].id = img_counter;
			mem_array[img_counter].high = mem_reg - 1;
			mem_array[img_counter].low = (int)memInfo.BaseAddress;
			mem_array[img_counter].name = "StackRegion";
			mem_array[img_counter].protection = memInfo.Protect;
			mem_array[img_counter].pagesType = memInfo.Type;
			mem_array[img_counter].unloaded = 0;
			TraceFile << "added a stack region with id=" << mem_array[img_counter].id << "\n";
			TraceFile << "base =" << base << " mem_array base=" << mem_array[index].low << "\n";
			img_counter++;
		}
	}
}
VOID OnThreadStart(THREADID tid, CONTEXT *ctxt, INT32, VOID *) {
	TraceFile << "in thread start \n";
	findStacks(ctxt);
}
/********************************************************************/
/************************Validate Virtual Query**********************/
/********************************************************************/
VOID ArgVQEx(char *name, ADDRINT arg0, ADDRINT arg1, ADDRINT arg2, ADDRINT arg3) {
	int* lpbuffer = (int*)arg2;
	p2BuffVQEx = lpbuffer;
}
//function to parse virtual query arguments
VOID ArgVQ(char *name, ADDRINT arg0, ADDRINT arg1, ADDRINT arg2) { //lpbuffer of type MEMORY_BASIC_INFORMATION
	int* lpbuffer = (int*)arg1;
	p2BuffVQ = lpbuffer;
}
//function to retrive VirtualQuery return value	
VOID VQAfter(ADDRINT ret, IMG img) {
	W::MEMORY_BASIC_INFORMATION* result = (W::MEMORY_BASIC_INFORMATION *)p2BuffVQ;
	TraceFile << "Return value of VirtualQuery: " << result->BaseAddress << " \n";
}
VOID VQExAfter(ADDRINT ret) {
	W::MEMORY_BASIC_INFORMATION* result = (W::MEMORY_BASIC_INFORMATION *)p2BuffVQEx;
	for (int i = 0; i < 50; i++) {
		if ((int)result->AllocationBase >= mem_array[i].low && (int)result->AllocationBase < mem_array[i].high) {
			/*TraceFile << "\n spotted an address contained in a module VIRTUALQUERYEX";
			TraceFile << "\nThe module is: " << mem_array[i].name;
			TraceFile << "\n max address of the pages belonging to the image is: " << mem_array[i].high;
			TraceFile << "\n base address of the pages belonging to the image is: " << mem_array[i].low;
			TraceFile << "\n the id of the image is: " << mem_array[i].id;*/
		}
	}
}

/********************************************************************/
/****************************HEAPS**********************************/
/********************************************************************/
VOID CTMAAfter(ADDRINT ret, IMG img) {
	CTMAlloc =  ret;
	int todo = 1;
	W::MEMORY_BASIC_INFORMATION memInfo;
	if (img_counter < 100) {
		for (int i = 0; i < img_counter; i++) {
			if ((int)ret < mem_array[i].high && (int)ret >= mem_array[i].low) {
				todo = 0;
				break;
			}
		}
		if (todo) {
			W::VirtualQuery((W::LPCVOID)ret, &memInfo, sizeof(memInfo));
			int mem_reg = (int)memInfo.BaseAddress + memInfo.RegionSize;
			mem_array[img_counter].protection = memInfo.Protect;
			mem_array[img_counter].id = img_counter;
			mem_array[img_counter].high = mem_reg - 1;
			mem_array[img_counter].low = (int)memInfo.BaseAddress;
			mem_array[img_counter].name = "CoTaskMemAllocResult";
			mem_array[img_counter].protection = memInfo.Protect;
			mem_array[img_counter].pagesType = memInfo.Type;
			mem_array[img_counter].unloaded = 0;
			img_counter++;
		}
	}
	TraceFile << "Return value of  CoTaskMemAlloc :" << CTMAlloc << " \n";
}
VOID GAfter(ADDRINT ret, IMG img) {
	GAlloc = ret;
	int todo = 1;
	W::MEMORY_BASIC_INFORMATION memInfo;
	if (img_counter < 100) {
		for (int i = 0; i < img_counter; i++) {
			if ((int)ret < mem_array[i].high && (int)ret >= mem_array[i].low) {
				todo = 0;
				break;
			}
		}
		if (todo) {
			W::VirtualQuery((W::LPCVOID)ret, &memInfo, sizeof(memInfo));
			int mem_reg = (int)memInfo.BaseAddress + memInfo.RegionSize;
			mem_array[img_counter].protection = memInfo.Protect;
			mem_array[img_counter].id = img_counter;
			mem_array[img_counter].high = mem_reg - 1;
			mem_array[img_counter].low = (int)memInfo.BaseAddress;
			mem_array[img_counter].name = "GlobalAllocResult";
			mem_array[img_counter].protection = memInfo.Protect;
			mem_array[img_counter].pagesType = memInfo.Type;
			mem_array[img_counter].unloaded = 0;
			img_counter++;
		}
	}
	TraceFile << "Return value of  GlobalAlloc :" << GAlloc << " \n";
}
VOID HAAfter(ADDRINT ret, IMG img) {
	HAlloc = ret;
	int todo = 1;
	W::MEMORY_BASIC_INFORMATION memInfo;
	if (img_counter < 100) {
		for (int i = 0; i < img_counter; i++) {
			if ((int)ret < mem_array[i].high && (int)ret >= mem_array[i].low) {
				todo = 0;
				break;
			}
		}
		if (todo) {
			W::VirtualQuery((W::LPCVOID)ret, &memInfo, sizeof(memInfo));
			int mem_reg = (int)memInfo.BaseAddress + memInfo.RegionSize;
			mem_array[img_counter].protection = memInfo.Protect;
			mem_array[img_counter].id = img_counter;
			mem_array[img_counter].high = mem_reg - 1;
			mem_array[img_counter].low = (int)memInfo.BaseAddress;
			mem_array[img_counter].name = "HeapAllocResult";
			mem_array[img_counter].protection = memInfo.Protect;
			mem_array[img_counter].pagesType = memInfo.Type;
			mem_array[img_counter].unloaded = 0;
			img_counter++;
		}
	}
	TraceFile << "Return value of  HeapAlloc :" << HAlloc << " \n";
}
VOID LAAfter(ADDRINT ret, IMG img) {
	LAlloc = ret;
	int todo = 1;
	W::MEMORY_BASIC_INFORMATION memInfo;
	if (img_counter < 100) {
		for (int i = 0; i < img_counter; i++) {
			if ((int)ret < mem_array[i].high && (int)ret >= mem_array[i].low) {
				todo = 0;
				break;
			}
		}
		if (todo) {
			W::VirtualQuery((W::LPCVOID)ret, &memInfo, sizeof(memInfo));
			int mem_reg = (int)memInfo.BaseAddress + memInfo.RegionSize;
			mem_array[img_counter].protection = memInfo.Protect;
			mem_array[img_counter].id = img_counter;
			mem_array[img_counter].high = mem_reg - 1;
			mem_array[img_counter].low = (int)memInfo.BaseAddress;
			mem_array[img_counter].name = "LocalAllocResult";
			mem_array[img_counter].protection = memInfo.Protect;
			mem_array[img_counter].pagesType = memInfo.Type;
			mem_array[img_counter].unloaded = 0;
			img_counter++;
		}
	}
	//TraceFile << "Return value of  LocalAlloc :" << LAlloc << " \n";
}
VOID MAAfter(ADDRINT ret, VOID*  rtn) {
	int todo = 1;
	W::MEMORY_BASIC_INFORMATION memInfo;
	mAlloc = ret;
	if (img_counter < 100) {
		for (int i = 0; i < img_counter; i++) {
			if ((int)ret < mem_array[i].high && (int)ret >= mem_array[i].low) {
				todo = 0;
				break;
			}
		}
		if (todo) {
		W::VirtualQuery((W::LPCVOID)ret, &memInfo, sizeof(memInfo));
		int mem_reg = (int)memInfo.BaseAddress + memInfo.RegionSize;
		mem_array[img_counter].protection = memInfo.Protect;
		mem_array[img_counter].id = img_counter;
		mem_array[img_counter].high = mem_reg - 1;
		mem_array[img_counter].low = (int)memInfo.BaseAddress;
		mem_array[img_counter].name = "MallocResult";
		mem_array[img_counter].protection = memInfo.Protect;
		mem_array[img_counter].pagesType = memInfo.Type;
		mem_array[img_counter].unloaded = 0;
		//TraceFile << "Base address: " << mem_array[img_counter].low << " High address: " << mem_array[img_counter].high << " \n";
		//TraceFile << "Return value of  malloc :" << mAlloc << " \n";
		//TraceFile << "Address of function: " << rtn << " \n";
		img_counter++;
		}
	}
}
VOID VAAfter(ADDRINT ret, IMG img) {
	VAlloc = ret;
	int todo = 1;
	W::MEMORY_BASIC_INFORMATION memInfo;
	if (img_counter < 100) {
		for (int i = 0; i < img_counter; i++) {
			if ((int)ret < mem_array[i].high && (int)ret >= mem_array[i].low) {
				todo = 0;
				break;
			}
		}
		if (todo) {
			W::VirtualQuery((W::LPCVOID)ret, &memInfo, sizeof(memInfo));
			int mem_reg = (int)memInfo.BaseAddress + memInfo.RegionSize;
			mem_array[img_counter].protection = memInfo.Protect;
			mem_array[img_counter].id = img_counter;
			mem_array[img_counter].high = mem_reg - 1;
			mem_array[img_counter].low = (int)memInfo.BaseAddress;
			mem_array[img_counter].name = "VirtualAlloc";
			mem_array[img_counter].protection = memInfo.Protect;
			mem_array[img_counter].pagesType = memInfo.Type;
			mem_array[img_counter].unloaded = 0;
			img_counter++;
		}
	}
	TraceFile << " return value of  VirtualAlloc :" << VAlloc << " \n";
}
VOID MemAlloc(IMG img, VOID *v) {
	//CoTaskMemAlloc  GlobalAlloc   HeapAlloc   LocalAlloc	malloc		new   VirtualAlloc
	//const char* names[] = { "VirtualQuery", "VirtualQueryEx", "CoTaskMemAlloc", "GlobalAlloc", "HeapAlloc","LocalAlloc", "malloc", "new", "VirtualAlloc" };
	fMap.insert(std::pair<std::string, int>("VirtualQuery", VirtualQuery_INDEX));
	fMap.insert(std::pair<std::string, int>("VirtualQueryEx", VirtualQueryEx_INDEX));
	fMap.insert(std::pair<std::string, int>("CoTaskMemAlloc", CoTaskMemAlloc_INDEX));
	fMap.insert(std::pair<std::string, int>("GlobalAlloc", GlobalAlloc_INDEX));
	fMap.insert(std::pair<std::string, int>("HeapAlloc", HeapAlloc_INDEX));
	fMap.insert(std::pair<std::string, int>("LocalAlloc", LocalAlloc_INDEX));
	fMap.insert(std::pair<std::string, int>("malloc", malloc_INDEX));
	fMap.insert(std::pair<std::string, int>("new", new_INDEX)); // wierd
	fMap.insert(std::pair<std::string, int>("VirtualAlloc", VirtualAlloc_INDEX));


	for (std::map<string, int>::iterator it = fMap.begin(),
		end = fMap.end(); it != end; ++it) {
		const char* func_name = it->first.c_str();
		RTN rtn = RTN_FindByName(img, func_name); // get pointer to the function
		if (rtn != RTN_Invalid()) {
			int index = it->second;
			switch (index) {
			case(VirtualQuery_INDEX):
				if (RTN_Valid(rtn)) {
					RTN_Open(rtn);
					//function to parse VirtualQuery arguments
					RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)ArgVQ,
						IARG_ADDRINT, "VirtualQuery",
						IARG_FUNCARG_ENTRYPOINT_VALUE, 0, IARG_FUNCARG_ENTRYPOINT_VALUE, 1, IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
						IARG_END);
					//function to retrive VirtualQuery return value	
					RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)VQAfter,
						IARG_FUNCRET_EXITPOINT_VALUE, IARG_END);
					RTN_Close(rtn);
				}
				break;
			case(VirtualQueryEx_INDEX):
				if (RTN_Valid(rtn)) {// does not work properly need to reconfigure for VQEx using function for VQ
					RTN_Open(rtn);
					//function to parse VirtualQueryEx arguments
					RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)ArgVQEx,
						IARG_ADDRINT, "VirtualQueryEx",
						IARG_FUNCARG_ENTRYPOINT_VALUE, 0, IARG_FUNCARG_ENTRYPOINT_VALUE, 1, IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
						IARG_END);
					//function to retrive VirtualQuery return value	
					RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)VQAfter,
						IARG_FUNCRET_EXITPOINT_VALUE, IARG_END);
					RTN_Close(rtn);
				}
				break;
			case(CoTaskMemAlloc_INDEX):
				if (RTN_Valid(rtn)) {
					RTN_Open(rtn);
					//function to retrive CoTaskMemAlloc  return value	
					RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)CTMAAfter,
						IARG_FUNCRET_EXITPOINT_VALUE, IARG_END);
					RTN_Close(rtn);
				}
				break;
			case(GlobalAlloc_INDEX):
				if (RTN_Valid(rtn)) {
					RTN_Open(rtn);
					//function to retrive GlobalAlloc  return value	
					RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)GAfter,
						IARG_FUNCRET_EXITPOINT_VALUE, IARG_END);
					RTN_Close(rtn);
				}
				break;
			case(HeapAlloc_INDEX):
				if (RTN_Valid(rtn)) {
					RTN_Open(rtn);
					//function to retrive HeapAlloc  return value	
					RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)HAAfter,
						IARG_FUNCRET_EXITPOINT_VALUE, IARG_END);
					RTN_Close(rtn);
				}
				break;
			case(LocalAlloc_INDEX):
				if (RTN_Valid(rtn)) {
					RTN_Open(rtn);
					//function to retrive LocalAlloc  return value	
					RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)LAAfter,
						IARG_FUNCRET_EXITPOINT_VALUE, IARG_END);
					RTN_Close(rtn);
				}
				break;
			case(malloc_INDEX):
				if (RTN_Valid(rtn)) {
					RTN_Open(rtn);
					//function to retrive malloc  return value	
					RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)MAAfter,
						IARG_FUNCRET_EXITPOINT_VALUE, IARG_PTR , rtn, IARG_END);
					RTN_Close(rtn);
				}
				break;
			//case(new_INDEX):
				//do stuff
				//break;
			case(VirtualAlloc_INDEX):
				if (RTN_Valid(rtn)) {
					RTN_Open(rtn);
					//function to retrive VirtualAlloc  return value	
					RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)VAAfter,
						IARG_FUNCRET_EXITPOINT_VALUE, IARG_END);
					RTN_Close(rtn);
				}
				break;

			}
		}
	}
}
/********************************************************************/
/**************************Instrumentations*******************/
/********************************************************************/
VOID parse_funcsyms(IMG img, VOID *v) {
	/*
	W::BOOL bResult;
	W::HANDLE hHeap;
	W::ULONG HeapInformation;
	hHeap = W::GetProcessHeap();
	bResult = W::HeapQueryInformation(hHeap,
		W::HeapCompatibilityInformation,
		&HeapInformation,
		sizeof(HeapInformation),
		NULL);
	if (bResult == FALSE) {
			TraceFile << "Failed to retrieve heap features with LastError" << W::GetLastError() << ". \n";
	}
	TraceFile<< "HeapCompatibilityInformation is: "<< HeapInformation << " \n";
	*/
	// Load ntdll dynamically
	NtQueryVirtualMemory = (_NtQueryVirtualMemory)GetLibraryProcAddress("ntdll.dll", "NtQueryVirtualMemory");
	W::HANDLE curProc = W::GetCurrentProcess();
	PhpEnumGenericMappedFilesAndImages(curProc);
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
	TraceFile << "img: " << mem_array[img_counter].name << " is loaded  \n";
	img_counter++;
	//instrumentVQ(img, 0);
	MemAlloc(img, 0);
}

VOID ImageUnload(IMG img, VOID* v) {
	int index = 0;
	TraceFile << "********************************************* \n";
	for (int i = 0; i < img_counter; i++) {
		TraceFile << "img name: " << mem_array[i].name << " img ID: " << mem_array[i].id << " \n";
	}
/*
	for (int i = 0; i < img_counter; i++) {
		if (IMG_Id(img)-1 == mem_array[i].id) {
			mem_array[i].unloaded = 1;
			index = i;
			TraceFile << "img name: " << mem_array[i].name << " img ID: " << mem_array[i].id << " \n";
		}
	}
	TraceFile << "img: " << mem_array[index].name << " is unloaded  \n";*/
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
	IMG_AddInstrumentFunction(parse_funcsyms, 0);
	IMG_AddUnloadFunction(ImageUnload, 0);
	// function to analyze memory access 
	//INS_AddInstrumentFunction(ValidateMemory, 0);
	// Register Fini to be called when the application exits
	PIN_AddFiniFunction(Fini, 0);
	// Start the program, never returns
	PIN_StartProgram();
	return 0;
}
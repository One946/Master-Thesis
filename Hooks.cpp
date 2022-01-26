#include "pin.H"
#include "HooksHeader.h"
#include "MemoryHeader.h"	
//#include "Memory.cpp"


namespace W {
#define _WINDOWS_H_PATH_ C:/Program Files/Windows Kits/10/Include/10.0.17763.0/um
#include <Windows.h>
	//#include <ntdef.h>
#include <ntstatus.h>
#include <subauth.h>
}
using namespace std;

//*******************************************************************
//GLOBAL VARIABLES
//*******************************************************************
extern int img_counter;
extern mem_regions mem_array[100]; //array in which i store valuable informations about the images
extern int counter; //counter for instructions
extern mem_map op_map;
/*SYSCALLS*/
unsigned int  NtAllocateVirtualMemory = 0x00000013;
unsigned int  NtFreeVirtualMemory = 0x00000084;
//unsigned int  NtAllocateVirtualMemoryEx = 0x00000084; NON ESISTE
unsigned int  NtMapViewOfSection = 0x000000a8;
unsigned int  NtUnmapViewOfSection = 0x00000181;
unsigned int  NtCreateSection = 0x00000054;
TLS_KEY tls_key;
//#define MAXSYSCALLS		
//CHAR* syscallIDs[MAXSYSCALLS] = { 0 };

#define MAXSYSCALLS	0x200
CHAR* syscallIDs[MAXSYSCALLS];

/*SYSCALLS*/

/********************************************************************/
/**************************Instrumentations**************************/
/********************************************************************/

//syscalls
VOID EnumSyscalls() {
	unsigned char *image = (unsigned char *)W::GetModuleHandle("ntdll");
	W::IMAGE_DOS_HEADER *dos_header = (W::IMAGE_DOS_HEADER *) image;
	W::IMAGE_NT_HEADERS *nt_headers = (W::IMAGE_NT_HEADERS *)(image + dos_header->e_lfanew);
	W::IMAGE_DATA_DIRECTORY *data_directory = &nt_headers->
		OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
	W::IMAGE_EXPORT_DIRECTORY *export_directory = (W::IMAGE_EXPORT_DIRECTORY *)(image + data_directory->VirtualAddress);
	// RVAs from image base
	W::DWORD *address_of_names = (W::DWORD*)(image + export_directory->AddressOfNames);
	W::DWORD *address_of_functions = (W::DWORD*)(image + export_directory->AddressOfFunctions);
	UINT16 *address_of_name_ordinals = (W::UINT16*)(image + export_directory->AddressOfNameOrdinals);
	// NumberOfNames can be 0: in that case the module will export by ordinal only 
	W::DWORD number_of_names = MIN(export_directory->NumberOfFunctions, export_directory->NumberOfNames);
	size_t ntcalls = 0, zwcalls = 0;

	for (W::DWORD i = 0; i < number_of_names; i++) {
		// AddressOfNameOrdinals contains the ordinals associated with the function names in AddressOfNames
		const char *name = (const char *)(image + address_of_names[i]);
		// AddressOfFunctions points to an array of RVAs of the functions/symbols in the module
		unsigned char *addr = image + address_of_functions[address_of_name_ordinals[i]];
		if (!memcmp(name, "Zw", 2) || !memcmp(name, "Nt", 2)) {
			if (addr[0] == 0xb8 && (addr[5] == 0xb9 || addr[5] == 0x33 || addr[5] == 0xba)) {
				ADDRINT syscall_number = *(UINT32*)(addr + 1);
				// by using a map for every Zw/Nt pair we will skip duplicates
				if (!syscallIDs[syscall_number] || !memcmp(name, "Nt", 2)) {
					syscallIDs[syscall_number] = strdup(name);
				}
			}
		}
	}

}

VOID HOOKS_NtProtectVirtualMemory_entry(CONTEXT *ctx, SYSCALL_STANDARD std){
	//TraceFile << "in HOOKS_NtProtectVirtualMemory_exit \n";
	ADDRINT baseAddress = PIN_GetSyscallArgument(ctx, std, 1); // 1 baseAddress 2 NumbOfBytes to be protected
	W::PULONG NumOfBytes = (W::PULONG)PIN_GetSyscallArgument(ctx, std, 2);
}

VOID HOOKS_NtFreeVirtualMemory_entry(CONTEXT *ctx, SYSCALL_STANDARD std) {
	//TraceFile << "in HOOKS_NtFreeVirtualMemory_exit \n";
	ADDRINT baseAddress = PIN_GetSyscallArgument(ctx, std, 1); // 1 baseAddress 2 RegSize to be freed
	W::PSIZE_T RegSize = (W::PSIZE_T)PIN_GetSyscallArgument(ctx, std, 2);
}
VOID HOOKS_NtCreateSection_entry(CONTEXT *ctx, SYSCALL_STANDARD std) {
	//TraceFile << "in HOOKS_NtCreateSection_exit \n";
}
VOID HOOKS_NtAllocateVirtualMemory_entry(CONTEXT *ctx, SYSCALL_STANDARD std){
	//TraceFile << "in HOOKS_NtAllocateVirtualMemory_exit \n";
	printf("in HOOKS_NtAllocateVirtualMemory_exit \n");
	ADDRINT baseAddress = PIN_GetSyscallArgument(ctx, std, 1); // 2 baseAddress 4 RegSize to be freed
	W::PSIZE_T RegSize = (W::PSIZE_T)PIN_GetSyscallArgument(ctx, std, 3);
	W::ULONG Protect = PIN_GetSyscallArgument(ctx, std, 5);
	printf("BaseAddress: %x, RegSize: %d \n", baseAddress, RegSize);
	if (img_counter < 100) {
		printf("img_counter: %d \n", img_counter);
		//mem_reg = (int)memInfo.BaseAddress + memInfo.RegionSize;
		mem_array[img_counter].protection = Protect;
		mem_array[img_counter].id = img_counter;
		mem_array[img_counter].high = baseAddress+(int)RegSize - 1;
		mem_array[img_counter].low = baseAddress;
		mem_array[img_counter].name = "NtAllocateVirtualMemory";
		mem_array[img_counter].unloaded = 0;
		img_counter++;
	}
}
VOID HOOKS_NtMapViewOfSection_entry(CONTEXT *ctx, SYSCALL_STANDARD std) {
	//TraceFile << "in HOOKS_NtMapViewOfSection_exit \n";
}
VOID HOOKS_NtUnmapViewOfSection_entry(CONTEXT *ctx, SYSCALL_STANDARD std) {
	//TraceFile << "in HOOKS_NtUnmapViewOfSection_exit \n";
}

VOID OnThreadStart(THREADID tid, CONTEXT *ctxt, INT32, VOID *) {
	pintool_tls* tdata = (pintool_tls*)calloc(1, sizeof(pintool_tls));
	tls_key = PIN_CreateThreadDataKey(NULL);
	if (PIN_SetThreadData(tls_key, tdata, tid) == FALSE) {
		PIN_ExitProcess(1);
	}
	findStacks(ctxt);

}

VOID HOOKS_SyscallEntry(THREADID thread_id, CONTEXT *ctx, SYSCALL_STANDARD std) {
	// get the syscall number
	ADDRINT syscall_number = PIN_GetSyscallNumber(ctx, std);
	pintool_tls *tdata = static_cast<pintool_tls*>(PIN_GetThreadData(tls_key, thread_id));
	syscall_t *sc = &tdata->sc;
	sc->syscall_number = syscall_number;

	if (syscall_number == NtAllocateVirtualMemory) { //NtAllocateVirtualMemory
		//TraceFile << "sc->syscall_number " << (void*)sc->syscall_number << "\n";
		HOOKS_NtAllocateVirtualMemory_entry(ctx, std);
	}
	if (syscall_number == NtFreeVirtualMemory) { //NtAllocateVirtualMemory
		//TraceFile << "sc->syscall_number " << (void*)sc->syscall_number << "\n";
		HOOKS_NtFreeVirtualMemory_entry(ctx, std);
	}
	if (syscall_number == NtMapViewOfSection) { //NtAllocateVirtualMemory
		//TraceFile << "sc->syscall_number " << (void*)sc->syscall_number << "\n";
		HOOKS_NtMapViewOfSection_entry(ctx, std);
	}
	if (syscall_number == NtUnmapViewOfSection) { //NtAllocateVirtualMemory
		//TraceFile << "sc->syscall_number " << (void*)sc->syscall_number << "\n";
		HOOKS_NtUnmapViewOfSection_entry(ctx, std);
	}
	if (syscall_number == NtCreateSection) { //NtAllocateVirtualMemory
		//TraceFile << "sc->syscall_number " << (void*)sc->syscall_number << "\n";
		HOOKS_NtCreateSection_entry(ctx, std);
	}
}


VOID HOOKS_SyscallExit(THREADID thread_id, CONTEXT *ctx, SYSCALL_STANDARD std) {
	pintool_tls *tdata = static_cast<pintool_tls*>(PIN_GetThreadData(tls_key, thread_id));
	syscall_t *sc = &tdata->sc;
			//TraceFile << "sc->syscall_number " << (void*)sc->syscall_number << "\n";

}

	//EnumSyscalls(); // parse ntdll for ordinals
	//PIN_AddSyscallEntryFunction(SyscallEntry, NULL);
	//PIN_AddThreadStartFunction(OnThreadStart, NULL);
	//PIN_AddSyscallExitFunction(SyscallExit, NULL);
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
extern mem_regions mem_array[100]; //array in which  informations about the images are stored
extern int counter; //counter for instructions
extern mem_map op_map;
extern TLS_KEY tls_key;

#define MAXSYSCALLS	0x200
CHAR* syscallIDs[MAXSYSCALLS];

int scCounter1 = 0; // counter used to identify order in syscall in entry
int scCounter2 = 0; // counter used to identify order in syscall in entry
sysmap memArrayEntry[1000]; // Entry array to store syscall informations
sysmap memArrayExit[1000]; // Exit array to store syscall informations
differences regUpdates[1000]; // structure to store memory changes, namely if a memory region is created or deleted

/********************************************************************/
/**************************Instrumentations**************************/
/********************************************************************/

// Helper method to print  information about the differences in memory regions before and after a syscall
VOID printRegions() {
	printf("different regions spotted! \n");
	for (int i = 0; i < scCounter2; i++) {
		printf("++++++++++++++++++++++++++++++++++++++++\n");
		printf("Syscall number:%x, i:%d \n", memArrayEntry[i].syscalNumb, i);
		if (regUpdates[i].newRegions) {
			for (int j = 0; j < regUpdates[i].newRegions; j++) {
				printf("New Regions! \n");
				printf("regUpdates[i].Added[j].RegionID:%d , regUpdates[i].Added[j].Size:%d \n", regUpdates[i].Added[j].RegionID, regUpdates[i].Added[j].Size);
				printf("regUpdates[i].Added[j].StartAddress:%x, regUpdates[i].Added[j].EndAddress:%x \n", regUpdates[i].Added[j].StartAddress, regUpdates[i].Added[j].EndAddress);
			}
		}
		if (regUpdates[i].deletedRegions) {
			for (int j = 0; j < regUpdates[i].deletedRegions; j++) {
				printf("Deleted Regions! \n");
				printf("regUpdates[i].Deleted[j].RegionID:%d , regUpdates[i].Deleted[j].Size:%d \n", regUpdates[i].Deleted[j].RegionID, regUpdates[i].Deleted[j].Size);
				printf("regUpdates[i].Deleted[j].StartAddress:%x, regUpdates[i].Deleted[j].EndAddress:%x \n", regUpdates[i].Deleted[j].StartAddress, regUpdates[i].Deleted[j].EndAddress);
			}
		}
		if (regUpdates[i].resizedRegions) {
			for (int j = 0; j < regUpdates[i].resizedRegions; j++) {
				printf("Resized Regions! \n");
				printf("regUpdates[i].Resized[j].RegionID:%d , regUpdates[i].Resized[j].Size:%d \n", regUpdates[i].Resized[j].RegionID, regUpdates[i].Resized[j].Size);
				printf("regUpdates[i].Resized[j].StartAddress:%x, regUpdates[i].Resized[j].EndAddress:%x \n", regUpdates[i].Resized[j].StartAddress, regUpdates[i].Resized[j].EndAddress);
			}
		}
	}
}

// Method to spot differences between memory regions before and after a syscall
VOID changed() {
	bool gt = 0; // variable to check if regions is greater in exit
	bool lt = 0; // variable to check if regions is lesser in exit
	bool eq = 0; // variable to check if regions is equal in exit
	ADDRINT delta1 = 0;
	ADDRINT delta2 = 0;
	bool found;
	int newIndex;  // index to count the different region and identify them
	int deletedIndex;
	int resizedIndex;
	fflush(stdout);

	for (int i = 0; i < scCounter1; i++) { //cicle on every syscall in the array
		gt = memArrayEntry[i].regionsSum < memArrayExit[i].regionsSum;
		lt = memArrayEntry[i].regionsSum > memArrayExit[i].regionsSum;
		eq = memArrayEntry[i].regionsSum == memArrayExit[i].regionsSum;
		resizedIndex = 0;

		if (gt) { //more region in exit than in entry
			newIndex = 0;
			for (int j = 0; j <= memArrayExit[i].regionsSum; j++) {
				found = 0;
				for (int k = 0; k <= memArrayEntry[i].regionsSum; k++) { // cycle on the memory map untill the end
					if (memArrayExit[i].Array[j].StartAddress == memArrayEntry[i].Array[k].StartAddress) {
						if (memArrayExit[i].Array[j].EndAddress != memArrayEntry[i].Array[k].EndAddress) {
							regUpdates[i].Resized[resizedIndex].StartAddress = memArrayExit[i].Array[j].StartAddress;
							regUpdates[i].Resized[resizedIndex].EndAddress = memArrayEntry[i].Array[k].EndAddress;
							regUpdates[i].Resized[resizedIndex].Size = memArrayEntry[i].Array[k].Size;
							regUpdates[i].Resized[resizedIndex].RegionID = memArrayEntry[i].Array[k].RegionID;
							resizedIndex++;

						}
						if (memArrayExit[i].Array[j].EndAddress == memArrayEntry[i].Array[k].EndAddress) {
							found = 1; // if i spot a known region, i break and keep looping on the exit array
							break;
						}
					}
				}
				if (!found) { // if i spot a new region i add it to the regionUpdates array;
					regUpdates[i].Added[newIndex].EndAddress = memArrayExit[i].Array[j].EndAddress;
					regUpdates[i].Added[newIndex].StartAddress = memArrayExit[i].Array[j].StartAddress;
					regUpdates[i].Added[newIndex].RegionID = memArrayExit[i].Array[j].RegionID;
					regUpdates[i].Added[newIndex].Size = memArrayExit[i].Array[j].Size;
					newIndex++;
				}
			}
			regUpdates[i].newRegions = newIndex;
		}
		if (lt) {		//Less region in exit than in entry
			deletedIndex = 0;
			for (int j = 0; j <= memArrayEntry[i].regionsSum; j++) {
				found = 0;
				for (int k = 0; k <= memArrayExit[i].regionsSum; k++) {// cycle on the memory map untill the end
					if (memArrayEntry[i].Array[j].StartAddress == memArrayExit[i].Array[k].StartAddress) {
						if (memArrayEntry[i].Array[j].EndAddress != memArrayExit[i].Array[k].EndAddress) {
							regUpdates[i].Resized[resizedIndex].StartAddress = memArrayEntry[i].Array[j].StartAddress;
							regUpdates[i].Resized[resizedIndex].EndAddress = memArrayExit[i].Array[k].EndAddress;
							regUpdates[i].Resized[resizedIndex].Size = memArrayExit[i].Array[k].Size;
							regUpdates[i].Resized[resizedIndex].RegionID = memArrayExit[i].Array[k].RegionID;
							resizedIndex++;
						}
						if (memArrayEntry[i].Array[j].EndAddress == memArrayExit[i].Array[k].EndAddress) {
							found = 1; // if i spot a known region, i break and keep looping on the entry array
							break;
						}
					}
				}
				if (!found) { //if a regions has been removed i put it in the memory update array
					regUpdates[i].Deleted[deletedIndex].EndAddress = memArrayExit[i].Array[j].EndAddress;
					regUpdates[i].Deleted[deletedIndex].StartAddress = memArrayExit[i].Array[j].StartAddress;
					regUpdates[i].Deleted[deletedIndex].RegionID = memArrayExit[i].Array[j].RegionID;
					regUpdates[i].Deleted[deletedIndex].Size = memArrayExit[i].Array[j].Size;
					deletedIndex++;
				}
			}
			regUpdates[i].deletedRegions = deletedIndex;
		}

		if (eq) {
			for (int j = 0; j < memArrayEntry[i].regionsSum; j++) {
				found = 0;
				for (int k = 0; k <= memArrayExit[i].regionsSum; k++) {
					if (memArrayEntry[i].Array[j].StartAddress == memArrayExit[i].Array[k].StartAddress) {
						if (memArrayEntry[i].Array[j].EndAddress != memArrayExit[i].Array[k].EndAddress) {
							regUpdates[i].Resized[resizedIndex].StartAddress = memArrayEntry[i].Array[j].StartAddress;
							regUpdates[i].Resized[resizedIndex].EndAddress = memArrayExit[i].Array[k].EndAddress;
							regUpdates[i].Resized[resizedIndex].Size = memArrayExit[i].Array[k].Size;
							regUpdates[i].Resized[resizedIndex].RegionID = memArrayExit[i].Array[k].RegionID;
							resizedIndex++;
						}
						if (memArrayEntry[i].Array[j].EndAddress == memArrayExit[i].Array[k].EndAddress) {
							found = 1; // if i spot a known region, i break and keep looping on the entry array
							break;
						}
					}
				}
			}
		}
		regUpdates[i].resizedRegions = resizedIndex;
	}
}

// function to enumerate memory regions before a syscall is executed
VOID funcEntry() {
	W::MEMORY_BASIC_INFORMATION mbi;
	W::SIZE_T numBytes;
	W::DWORD MyAddress = 0;
	//sok variables
	W::PVOID maxAddr = 0;
	ADDRINT end = 0x7ffe0000; // address to query to -> 0x7ffe0000->KUSERDATA or 0x7fff0000->BLACK MAGIC
	int regions = 0;
	ADDRINT regionend = 0;
	W::SIZE_T size = 0;
	fflush(stdout);

	//cycle on the whole memroy, untill the end address
	while (numBytes = W::VirtualQuery((W::LPCVOID)MyAddress, &mbi, sizeof(mbi))) {
		if ((maxAddr && maxAddr >= mbi.BaseAddress) || end <= (ADDRINT)mbi.BaseAddress) break;
		maxAddr = mbi.BaseAddress;
		if (mbi.State != MEM_FREE) { //&& mbi.Type != MEM_PRIVATE) {

			// if memory is used store information about that memory in an array
			regionend = (ADDRINT)mbi.BaseAddress + mbi.RegionSize - 1;
			memArrayEntry[scCounter1].Array[regions].EndAddress = regionend;
			memArrayEntry[scCounter1].Array[regions].StartAddress = (ADDRINT)mbi.BaseAddress;
			memArrayEntry[scCounter1].Array[regions].RegionID = regions;
			memArrayEntry[scCounter1].Array[regions].Size = mbi.RegionSize;
			regions++;
		}
		size += mbi.RegionSize;
		MyAddress += mbi.RegionSize;
	}
	memArrayEntry[scCounter1].regionsSum = regions - 1;
	memArrayEntry[scCounter1].syscallID = scCounter1;
	scCounter1++;
}

// function to enumerate memory regions after a syscall is executed
VOID funcExit() {
	W::MEMORY_BASIC_INFORMATION mbi;
	W::SIZE_T numBytes;
	W::DWORD MyAddress = 0;
	//sok variables
	W::PVOID maxAddr = 0;
	ADDRINT end = 0x7ffe0000; // address to query to -> 0x7ffe0000->KUSERDATA or 0x7fff0000->BLACK MAGIC
	int regions = 0;
	ADDRINT regionend = 0;
	W::SIZE_T size = 0;
	fflush(stdout);

	//cycle on the whole memroy, untill the end address
	while (numBytes = W::VirtualQuery((W::LPCVOID)MyAddress, &mbi, sizeof(mbi))) {
		if ((maxAddr && maxAddr >= mbi.BaseAddress) || end <= (ADDRINT)mbi.BaseAddress) break;
		maxAddr = mbi.BaseAddress;
		if (mbi.State != MEM_FREE) { // && mbi.Type != MEM_PRIVATE) {
			// if memory is used store information about that memory in an array
			regionend = (ADDRINT)mbi.BaseAddress + mbi.RegionSize - 1;
			memArrayExit[scCounter2].Array[regions].EndAddress = regionend;
			memArrayExit[scCounter2].Array[regions].StartAddress = (ADDRINT)mbi.BaseAddress;
			memArrayExit[scCounter2].Array[regions].RegionID = regions;
			memArrayExit[scCounter2].Array[regions].Size = mbi.RegionSize;
			regions++;
		}
		size += mbi.RegionSize;
		MyAddress += mbi.RegionSize;
	}
	memArrayExit[scCounter2].regionsSum = regions - 1;
	memArrayExit[scCounter2].syscallID = scCounter2;
	scCounter2++;
}

//enumerate syscalls' ordinals
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

VOID HOOKS_NtProtectVirtualMemory_entry(CONTEXT *ctx, SYSCALL_STANDARD std) {
	printf("in HOOKS_NtProtectVirtualMemory_exit \n");
	ADDRINT baseAddress = PIN_GetSyscallArgument(ctx, std, 1); // 1 baseAddress 2 NumbOfBytes to be protected
	W::PULONG NumOfBytes = (W::PULONG)PIN_GetSyscallArgument(ctx, std, 2);
}
VOID HOOKS_NtFreeVirtualMemory_entry(CONTEXT *ctx, SYSCALL_STANDARD std) {
	printf("in HOOKS_NtFreeVirtualMemory_entry \n");
	ADDRINT baseAddress = PIN_GetSyscallArgument(ctx, std, 1); // 1 baseAddress 2 RegSize to be freed
	W::PSIZE_T RegSize = (W::PSIZE_T)PIN_GetSyscallArgument(ctx, std, 2);
}
VOID HOOKS_NtCreateSection_entry(CONTEXT *ctx, SYSCALL_STANDARD std) {
	printf("in HOOKS_NtCreateSection_exit \n");
}
VOID HOOKS_NtAllocateVirtualMemory_entry(CONTEXT *ctx, SYSCALL_STANDARD std) {
	//TraceFile << "in HOOKS_NtAllocateVirtualMemory_exit \n";
	printf("in HOOKS_NtAllocateVirtualMemory_entry \n");
	ADDRINT baseAddress = PIN_GetSyscallArgument(ctx, std, 1); // 2 baseAddress 4 RegSize to be freed
	W::PSIZE_T RegSize = (W::PSIZE_T)PIN_GetSyscallArgument(ctx, std, 3);
	W::ULONG Protect = PIN_GetSyscallArgument(ctx, std, 5);
	printf("BaseAddress: %x, RegSize: %d \n", baseAddress, RegSize);
	if (img_counter < 100) {
		printf("img_counter: %d \n", img_counter);
		//mem_reg = (int)memInfo.BaseAddress + memInfo.RegionSize;
		mem_array[img_counter].protection = Protect;
		mem_array[img_counter].id = img_counter;
		mem_array[img_counter].high = baseAddress + (int)RegSize - 1;
		mem_array[img_counter].low = baseAddress;
		mem_array[img_counter].name = "NtAllocateVirtualMemory";
		mem_array[img_counter].unloaded = 0;
		img_counter++;
	}
}
VOID HOOKS_NtMapViewOfSection_entry(CONTEXT *ctx, SYSCALL_STANDARD std) {
	printf("in HOOKS_NtMapViewOfSection_exit \n");
}
VOID HOOKS_NtUnmapViewOfSection_entry(CONTEXT *ctx, SYSCALL_STANDARD std) {
	printf("in HOOKS_NtUnmapViewOfSection_exit \n");
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
//	pintool_tls *tdata = static_cast<pintool_tls*>(PIN_GetThreadData(tls_key, thread_id));
//	syscall_t *sc = &tdata->sc;
//	sc->syscall_number = syscall_number;
	if (syscall_number > 0x200) {
		printf("****************Syscall number: %x ****************\n", syscall_number);
	}
	if (syscall_number < 0x200) {
		printf("****************Syscall name: %s ****************\n", syscallIDs[syscall_number]);
	}
//	memArrayEntry[scCounter1].syscalNumb = syscall_number;
//	funcEntry();

}


VOID HOOKS_SyscallExit(THREADID thread_id, CONTEXT *ctx, SYSCALL_STANDARD std) {
	funcExit();
	changed();
}

//EnumSyscalls(); // parse ntdll for ordinals
//PIN_AddSyscallEntryFunction(SyscallEntry, NULL);
//PIN_AddThreadStartFunction(OnThreadStart, NULL);
//PIN_AddSyscallExitFunction(SyscallExit, NULL);	
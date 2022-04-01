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
sysmap memArrayEntry; // Entry array to store syscall informations
sysmap memArrayExit; // Exit array to store syscall informations
differences regUpdates; // structure to store memory changes, namely if a memory region is created or deleted
ADDRINT arg1,arg2,arg3;
/********************************************************************/
/**************************Instrumentations**************************/
/********************************************************************/

VOID fillArg(CONTEXT *ctx, SYSCALL_STANDARD std, ADDRINT syscall_number) {

	switch (syscall_number){
	case(0x00d7)://ntallocatevirtualmemory
		arg1 = PIN_GetSyscallArgument(ctx, std, 1);
	case(0x0013)://ntprotectvirtualmemory
		arg1 = PIN_GetSyscallArgument(ctx, std, 1);
	case(0x0032)://ntclose
		arg1 = PIN_GetSyscallArgument(ctx, std, 0);
	case(0x0040):// ntcreateevent
		arg1 = PIN_GetSyscallArgument(ctx, std, 0);
	case(0x004a): // ntcreatemutant
		arg1 = PIN_GetSyscallArgument(ctx, std, 0);
	case(0x0054):// ntcreatesection
		arg1 = PIN_GetSyscallArgument(ctx, std, 0);
	case(0x0083)://ntfreevirtualmemory
		arg1 = PIN_GetSyscallArgument(ctx, std, 1);
	case(0x00a8):// ntmapviewofsection
		arg1 = PIN_GetSyscallArgument(ctx, std, 2); // also 5 6
		arg2 = PIN_GetSyscallArgument(ctx, std, 5); // also 5 6
		arg3 = PIN_GetSyscallArgument(ctx, std, 6); // also 5 6
	case(0x00b3):// ntopenfile
		arg1 = PIN_GetSyscallArgument(ctx, std, 0);
	case(0x00b6):// ntopenkey
		arg1 = PIN_GetSyscallArgument(ctx, std, 0);
	case(0x00b7):// ntopenkeyEx
		arg1 = PIN_GetSyscallArgument(ctx, std, 0);
	case(0x00bf): // ntopenprocesstoken
		arg1 = PIN_GetSyscallArgument(ctx, std, 2);
	case(0x00c0): // ntopenprocesstokenex
		arg1 = PIN_GetSyscallArgument(ctx, std, 3);
	case(0x00c2): // ntopensection
		arg1 = PIN_GetSyscallArgument(ctx, std, 0);
	case(0x00d9): // ntqueryattributesfile
		arg1 = PIN_GetSyscallArgument(ctx, std, 1);
	case(0x00ea): // ntqueryinformationprocess
		arg1 = PIN_GetSyscallArgument(ctx, std, 2);
	case(0x00ed): // ntqueryinformationtoken
		arg1 = PIN_GetSyscallArgument(ctx, std, 2);
	case(0x00fb): // ntqueryperformancecounter
		arg1 = PIN_GetSyscallArgument(ctx, std, 0);
	case(0x00fe): // ntquerysection
		arg1 = PIN_GetSyscallArgument(ctx, std, 2);
	case(0x0105): // ntquerysysteminformation
		arg1 = PIN_GetSyscallArgument(ctx, std, 1);
	case(0x010a): // ntqueryvaluekey
		arg1 = PIN_GetSyscallArgument(ctx, std, 3);
	case(0x010c): // ntqueryvolumeinformationfile
		arg1 = PIN_GetSyscallArgument(ctx, std, 2);
	case(0x012b): // ntrequestwaitreplyport
		arg1 = PIN_GetSyscallArgument(ctx, std, 2);
	case(0x0177): // nttracecontrol
		arg1 = PIN_GetSyscallArgument(ctx, std, 3);
	default:
		break;
	}
	/*
	if (syscall_number == 0x00d7) {//ntallocatevirtualmemory
		arg = PIN_GetSyscallArgument(ctx, std, 1);
	}
	if (syscall_number == 0x0013) {//ntprotectvirtualmemory
		arg = PIN_GetSyscallArgument(ctx, std, 1);
	}
	if (syscall_number == 0x0032) { //ntclose
		arg = PIN_GetSyscallArgument(ctx, std, 0);
	}
	if (syscall_number == 0x0040) { // ntcreateevent
		arg = PIN_GetSyscallArgument(ctx, std, 0);
	}
	if (syscall_number == 0x004a) { // ntcreatemutant
		arg = PIN_GetSyscallArgument(ctx, std, 0);
	}
	if (syscall_number == 0x0054) { // ntcreatesection
		arg = PIN_GetSyscallArgument(ctx, std, 0);
	}
	if (syscall_number == 0x0083) { //ntfreevirtualmemory
		arg = PIN_GetSyscallArgument(ctx, std, 1);
	}
	if (syscall_number == 0x00a8) { // ntmapviewofsection
		arg = PIN_GetSyscallArgument(ctx, std, 2); // also 5 6
	}
	if (syscall_number == 0x00b3) { // ntopenfile
		arg = PIN_GetSyscallArgument(ctx, std, 0);
	}
	if (syscall_number == 0x00b6) { // ntopenkey
		arg = PIN_GetSyscallArgument(ctx, std, 0);
	}
	if (syscall_number == 0x00b7) { // ntopenkeyEx
		arg = PIN_GetSyscallArgument(ctx, std, 0);
	}
	if (syscall_number == 0x00bf) { // ntopenprocesstoken
		arg = PIN_GetSyscallArgument(ctx, std, 2);
	}
	if (syscall_number == 0x00c0) { // ntopenprocesstokenex
		arg = PIN_GetSyscallArgument(ctx, std, 3);
	}
	if (syscall_number == 0x00c2) { // ntopensection
		arg = PIN_GetSyscallArgument(ctx, std, 0);
	}
	if (syscall_number == 0x00d9) { // ntqueryattributesfile
		arg = PIN_GetSyscallArgument(ctx, std, 1);
	}
	if (syscall_number == 0x00ea) { // ntqueryinformationprocess
		arg = PIN_GetSyscallArgument(ctx, std, 2);
	}
	if (syscall_number == 0x00ed) { // ntqueryinformationtoken
		arg = PIN_GetSyscallArgument(ctx, std, 2);
	}
	if (syscall_number == 0x00fb) { // ntqueryperformancecounter
		arg = PIN_GetSyscallArgument(ctx, std, 0);
	}
	if (syscall_number == 0x00fe) { // ntquerysection
		arg = PIN_GetSyscallArgument(ctx, std, 2);
	}
	if (syscall_number == 0x0105) { // ntquerysysteminformation
		arg = PIN_GetSyscallArgument(ctx, std, 1);
	}
	if (syscall_number == 0x010a) { // ntqueryvaluekey
		arg = PIN_GetSyscallArgument(ctx, std, 3);
	}
	if (syscall_number == 0x010c) { // ntqueryvolumeinformationfile
		arg = PIN_GetSyscallArgument(ctx, std, 2);
	}
	if (syscall_number == 0x012b) { // ntrequestwaitreplyport
		arg = PIN_GetSyscallArgument(ctx, std, 2);
	}
	if (syscall_number == 0x0177) { // nttracecontrol
		arg = PIN_GetSyscallArgument(ctx, std, 3);
	}*/
}

// Helper method to print  information about the differences in memory regions before and after a syscall
VOID printRegions() {
	if (regUpdates.newRegions) {
		printf("new regions spotted! \n");
		printf("++++++++++++++++++++++++++++++++++++++++\n");
		printf("Syscall number:%x \n", memArrayEntry.syscalNumb);
		for (int j = 0; j < regUpdates.newRegions; j++) {
			printf("New Regions! \n");
			printf("regUpdates[i].Added[j].RegionID:%d , regUpdates[i].Added[j].Size:%d \n", regUpdates.Added[j].RegionID, regUpdates.Added[j].Size);
			printf("regUpdates[i].Added[j].StartAddress:%x, regUpdates[i].Added[j].EndAddress:%x \n", regUpdates.Added[j].StartAddress, regUpdates.Added[j].EndAddress);
			if (arg1 <= regUpdates.Added[j].EndAddress && arg1 >= regUpdates.Added[j].StartAddress) {
				printf(" %%%%%%%%% Ret addres: %x, StartAddress: %x , EndAddress: %x \n", arg1, regUpdates.Added[j].StartAddress, regUpdates.Added[j].EndAddress);
			}
		}
	}
	if (regUpdates.deletedRegions) {
		printf("deleted regions spotted! \n");
		printf("++++++++++++++++++++++++++++++++++++++++\n");
		printf("Syscall number:%x \n", memArrayEntry.syscalNumb);
		for (int j = 0; j < regUpdates.deletedRegions; j++) {
			printf("Deleted Regions! \n");
			printf("regUpdates[i].Deleted[j].RegionID:%d , regUpdates[i].Deleted[j].Size:%d \n", regUpdates.Deleted[j].RegionID, regUpdates.Deleted[j].Size);
			printf("regUpdates[i].Deleted[j].StartAddress:%x, regUpdates[i].Deleted[j].EndAddress:%x \n", regUpdates.Deleted[j].StartAddress, regUpdates.Deleted[j].EndAddress);
			if (arg1 <= regUpdates.Deleted[j].EndAddress && arg1 >= regUpdates.Deleted[j].StartAddress) {
				printf(" %%%%%%%%% Ret addres: %x, StartAddress: %x , EndAddress: %x \n", arg1, regUpdates.Deleted[j].StartAddress, regUpdates.Deleted[j].EndAddress);
			}
		}
	}
	if (regUpdates.resizedRegions) {
		printf("resized regions spotted! \n");
		printf("++++++++++++++++++++++++++++++++++++++++\n");
		printf("Syscall number:%x \n", memArrayEntry.syscalNumb);
		for (int j = 0; j < regUpdates.resizedRegions; j++) {
			printf("Resized Regions! \n");
			printf("regUpdates[i].Resized[j].RegionID:%d , regUpdates[i].Resized[j].Size:%d \n", regUpdates.Resized[j].RegionID, regUpdates.Resized[j].Size);
			printf("regUpdates[i].Resized[j].StartAddress:%x, regUpdates[i].Resized[j].EndAddress:%x \n", regUpdates.Resized[j].StartAddress, regUpdates.Resized[j].EndAddress);
			if (arg1 <= regUpdates.Resized[j].EndAddress && arg1 >= regUpdates.Resized[j].StartAddress) {
				printf(" %%%%%%%%% Ret addres: %x, StartAddress: %x , EndAddress: %x \n", arg1, regUpdates.Resized[j].StartAddress, regUpdates.Resized[j].EndAddress);
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

		gt = memArrayEntry.regionsSum < memArrayExit.regionsSum;
		lt = memArrayEntry.regionsSum > memArrayExit.regionsSum;
		eq = memArrayEntry.regionsSum == memArrayExit.regionsSum;
		resizedIndex = 0;

		if (gt) { //more region in exit than in entry
			newIndex = 0;
			for (int j = 0; j <= memArrayExit.regionsSum; j++) {
				found = 0;
				for (int k = 0; k <= memArrayEntry.regionsSum; k++) { // cycle on the memory map untill the end
					if (memArrayExit.Array[j].StartAddress == memArrayEntry.Array[k].StartAddress) {
						if (memArrayExit.Array[j].EndAddress != memArrayEntry.Array[k].EndAddress) {
							regUpdates.Resized[resizedIndex].StartAddress = memArrayExit.Array[j].StartAddress;
							regUpdates.Resized[resizedIndex].EndAddress = memArrayEntry.Array[k].EndAddress;
							regUpdates.Resized[resizedIndex].Size = memArrayEntry.Array[k].Size;
							regUpdates.Resized[resizedIndex].RegionID = memArrayEntry.Array[k].RegionID;
							resizedIndex++;

						}
						if (memArrayExit.Array[j].EndAddress == memArrayEntry.Array[k].EndAddress) {
							found = 1; // if i spot a known region, i break and keep looping on the exit array
							break;
						}
					}
				}
				if (!found) { // if i spot a new region i add it to the regionUpdates array;
					if (arg1 <= memArrayExit.Array[j].EndAddress && arg1 >= memArrayExit.Array[j].StartAddress) {
						printf(" %%%%%%%%% Ret addres: %x, StartAddress: %x , EndAddress: %x \n", arg1, memArrayExit.Array[j].StartAddress, memArrayExit.Array[j].EndAddress);
					}
					if (memArrayEntry.syscalNumb == 0x00a8) {
						if (arg2 <= memArrayExit.Array[j].EndAddress && arg2 >= memArrayExit.Array[j].StartAddress) {
							printf(" %%%%%%%%% Ret addres: %x, StartAddress: %x , EndAddress: %x \n", arg2, memArrayExit.Array[j].StartAddress, memArrayExit.Array[j].EndAddress);
						}
						if (arg3 <= memArrayExit.Array[j].EndAddress && arg3 >= memArrayExit.Array[j].StartAddress) {
							printf(" %%%%%%%%% Ret addres: %x, StartAddress: %x , EndAddress: %x \n", arg3, memArrayExit.Array[j].StartAddress, memArrayExit.Array[j].EndAddress);
						}
					}
					regUpdates.Added[newIndex].EndAddress = memArrayExit.Array[j].EndAddress;
					regUpdates.Added[newIndex].StartAddress = memArrayExit.Array[j].StartAddress;
					regUpdates.Added[newIndex].RegionID = memArrayExit.Array[j].RegionID;
					regUpdates.Added[newIndex].Size = memArrayExit.Array[j].Size;
					newIndex++;
	

				}
			}
			regUpdates.newRegions = newIndex;
		}
		if (lt) {		//Less region in exit than in entry
			deletedIndex = 0;
			for (int j = 0; j <= memArrayEntry.regionsSum; j++) {
				found = 0;
				for (int k = 0; k <= memArrayExit.regionsSum; k++) {// cycle on the memory map untill the end
					if (memArrayEntry.Array[j].StartAddress == memArrayExit.Array[k].StartAddress) {
						if (memArrayEntry.Array[j].EndAddress != memArrayExit.Array[k].EndAddress) {
							regUpdates.Resized[resizedIndex].StartAddress = memArrayEntry.Array[j].StartAddress;
							regUpdates.Resized[resizedIndex].EndAddress = memArrayExit.Array[k].EndAddress;
							regUpdates.Resized[resizedIndex].Size = memArrayExit.Array[k].Size;
							regUpdates.Resized[resizedIndex].RegionID = memArrayExit.Array[k].RegionID;
							resizedIndex++;
						}
						if (memArrayEntry.Array[j].EndAddress == memArrayExit.Array[k].EndAddress) {
							found = 1; // if i spot a known region, i break and keep looping on the entry array
							break;
						}
					}
				}
				if (!found) { //if a regions has been removed i put it in the memory update array
					regUpdates.Deleted[deletedIndex].EndAddress = memArrayExit.Array[j].EndAddress;
					regUpdates.Deleted[deletedIndex].StartAddress = memArrayExit.Array[j].StartAddress;
					regUpdates.Deleted[deletedIndex].RegionID = memArrayExit.Array[j].RegionID;
					regUpdates.Deleted[deletedIndex].Size = memArrayExit.Array[j].Size;
					deletedIndex++;
				}
			}
			regUpdates.deletedRegions = deletedIndex;
		}

		if (eq) {
			for (int j = 0; j < memArrayEntry.regionsSum; j++) {
				found = 0;
				for (int k = 0; k <= memArrayExit.regionsSum; k++) {
					if (memArrayEntry.Array[j].StartAddress == memArrayExit.Array[k].StartAddress) {
						if (memArrayEntry.Array[j].EndAddress != memArrayExit.Array[k].EndAddress) {
							regUpdates.Resized[resizedIndex].StartAddress = memArrayEntry.Array[j].StartAddress;
							regUpdates.Resized[resizedIndex].EndAddress = memArrayExit.Array[k].EndAddress;
							regUpdates.Resized[resizedIndex].Size = memArrayExit.Array[k].Size;
							regUpdates.Resized[resizedIndex].RegionID = memArrayExit.Array[k].RegionID;
							resizedIndex++;
						}
						if (memArrayEntry.Array[j].EndAddress == memArrayExit.Array[k].EndAddress) {
							found = 1; // if i spot a known region, i break and keep looping on the entry array
							break;
						}
					}
				}
			}
		}
		regUpdates.resizedRegions = resizedIndex;

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
			memArrayEntry.Array[regions].EndAddress = regionend;
			memArrayEntry.Array[regions].StartAddress = (ADDRINT)mbi.BaseAddress;
			memArrayEntry.Array[regions].RegionID = regions;
			memArrayEntry.Array[regions].Size = mbi.RegionSize;
			regions++;
		}
		size += mbi.RegionSize;
		MyAddress += mbi.RegionSize;
	}
	memArrayEntry.regionsSum = regions - 1;
	memArrayEntry.syscallID = scCounter1;
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
			memArrayExit.Array[regions].EndAddress = regionend;
			memArrayExit.Array[regions].StartAddress = (ADDRINT)mbi.BaseAddress;
			memArrayExit.Array[regions].RegionID = regions;
			memArrayExit.Array[regions].Size = mbi.RegionSize;
			regions++;
		}
		size += mbi.RegionSize;
		MyAddress += mbi.RegionSize;
	}
	memArrayExit.regionsSum = regions - 1;
	memArrayExit.syscallID = scCounter2;
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
	if (syscall_number > 0x200) {
		printf("****************Syscall number: %x ****************\n", syscall_number);
		if (syscall_number == 0x10e6) {
			return;
		}
	}
	if (syscall_number < 0x200) {
		printf("****************Syscall name: %s ****************\n", syscallIDs[syscall_number]);
	}
	memArrayEntry.syscalNumb = syscall_number;
	fillArg(ctx, std, syscall_number);
	printf("ENTRY arg1: %x \n", arg1);
	printf("ENTRY arg2: %x \n", arg2);
	printf("ENTRY arg3: %x \n", arg3);
	funcEntry();
}


VOID HOOKS_SyscallExit(THREADID thread_id, CONTEXT *ctx, SYSCALL_STANDARD std, ADDRINT scNumber) {
	funcExit();
	changed();
	
	printf("regUpdates.newRegions: %d \n", regUpdates.newRegions);
	printf("EXIT arg1: %x \n", arg1);
	printf("EXIT arg2: %x \n", arg2);
	printf("EXIT arg3: %x \n", arg3);
	/*
	for (int i = 0; i < regUpdates.newRegions; i++) {
		printf("StartAddress: %x, EndAddress : %x \n", regUpdates.Added[i].StartAddress, regUpdates.Added[i].EndAddress);
		if (arg >= regUpdates.Added[i].StartAddress && arg <= regUpdates.Added[i].EndAddress) {
			printf("&&&&&&&&& PROTECT Ret addres: %x, StartAddress: %x , EndAddress: %x \n", arg, regUpdates.Added[i].StartAddress, regUpdates.Added[i].EndAddress);
		}
	}*/
	
	// printRegions();
	
}

//EnumSyscalls(); // parse ntdll for ordinals
//PIN_AddSyscallEntryFunction(SyscallEntry, NULL);
//PIN_AddThreadStartFunction(OnThreadStart, NULL);
//PIN_AddSyscallExitFunction(SyscallExit, NULL);	
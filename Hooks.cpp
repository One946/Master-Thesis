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
unsigned int  NtFreeVirtualMemory = 0x00000083;
//unsigned int  NtAllocateVirtualMemoryEx = 0x00000084; NON ESISTE
unsigned int  NtMapViewOfSection = 0x000000a8;
unsigned int  NtUnmapViewOfSection = 0x00000181;
unsigned int  NtCreateSection = 0x00000054;
unsigned int NtOpenProcessTokenEx = 0x000000bf;
unsigned int NtQueryInformationTransaction = 0x000000ed;
unsigned int NtOpenKeyEx = 0x000000b6;
unsigned int NtQueryValueKey = 0x0000010a;
unsigned int NtClose = 0x00000032;
unsigned int NtOpenKNtOpenRegistryTransactioney = 0x000000c0;
unsigned int NtPssCaptureVaSpaceBulk = 0x00000d7;
unsigned int NtOpenSemaphore = 0x000000c2;
unsigned int NtQuerySection = 0x000000fe;
unsigned int NtQueryAttributesFile = 0x000000d9;
unsigned int NtOpenFile = 0x000000b3;
unsigned int NtSetInformationResourceManager = 0x0000014d;
unsigned int NtQueryInformationProcess = 0x000000ea;
unsigned int NtQueryPerformanceCounter = 0x000000fb;
unsigned int NtWriteFile = 0x0000018c; 
unsigned int NtTerminateProcess = 0x00000172;
unsigned int NtQueryVirtualMemory = 0x0000010b;

unsigned int NtRequestWaitReplyPort = 0x0000012b;
unsigned int NtQueryVolumeInformationFile = 0x0000010c;
extern TLS_KEY tls_key;

int scCounter1 = 0;
int scCounter2 = 0;
int diffIndex = 0;


#define MAXSYSCALLS	0x200
CHAR* syscallIDs[MAXSYSCALLS];

//sysmap memRangArray1[500];
//sysmap memRangArray2[500];
/*SYSCALLS*/
MemoryRange pippo1[100];
MemoryRange pippo2[100];
RegionsOfInterest pippo3;

sysmap prova1;
sysmap prova2;

/********************************************************************/
/**************************Instrumentations**************************/
/********************************************************************/
BOOL changed(sysmap* array1, sysmap* array2) {
	bool DifSize = 0; // variable to check if regions number changed
	DifSize = array1->regionsSum != array2->regionsSum;
	if(DifSize){
		printf("different sizes");
		return true;
	}
}

VOID funcEntry() { 
	W::MEMORY_BASIC_INFORMATION mbi;
	W::SIZE_T numBytes;
	W::DWORD MyAddress = 0;
	//sok variables
	W::PVOID maxAddr = 0;
	ADDRINT end = 0x7ffe0000; //0x7ffe0000->KUSERDATA 0x7fff0000->BLACK MAGIC
	int regions = 0;
	ADDRINT regionend = 0;
	W::SIZE_T size = 0;

	while (numBytes = W::VirtualQuery((W::LPCVOID)MyAddress, &mbi, sizeof(mbi))) {
		//numBytes = W::VirtualQuery((W::LPCVOID)MyAddress, &mbi, sizeof(mbi));
		//printf("number of bytes from VQ: %d \n", numBytes);
		if ((maxAddr && maxAddr >= mbi.BaseAddress) || end <= (ADDRINT)mbi.BaseAddress) break;
		maxAddr = mbi.BaseAddress;
		if (mbi.State != MEM_FREE && mbi.Type != MEM_PRIVATE) {
			regionend = (ADDRINT)mbi.BaseAddress + mbi.RegionSize - 1;
			//printf("ENTRY-CHECK StartAddress: %x , EndAddress: %x \n", memRangArray1[scCounter1].Array[regions].StartAddress, memRangArray1[scCounter1].Array[regions].EndAddress);
			//printf("\t scCounter1: %d \n", scCounter1);
			pippo1[regions].EndAddress = regionend;
			pippo1[regions].StartAddress = (ADDRINT)mbi.BaseAddress;
			pippo1[regions].RegionID = regions;
			pippo1[regions].Size = mbi.RegionSize;
			regions++;
		}
		size += mbi.RegionSize;
		MyAddress += mbi.RegionSize;
	}
	printf("EXIT regions count: %d \n", regions);

}
//function to retrive VirtualQuery return value	
VOID funcExit() {
	W::MEMORY_BASIC_INFORMATION mbi;
	W::SIZE_T numBytes;
	W::DWORD MyAddress = 0;
	//sok variables
	W::PVOID maxAddr = 0;
	ADDRINT end = 0x7ffe0000; //0x7ffe0000->KUSERDATA 0x7fff0000->BLACK MAGIC
	int regions = 0;
	ADDRINT regionend = 0;
	W::SIZE_T size = 0;

	while (numBytes = W::VirtualQuery((W::LPCVOID)MyAddress, &mbi, sizeof(mbi))) {
		//numBytes = W::VirtualQuery((W::LPCVOID)MyAddress, &mbi, sizeof(mbi));
		//printf("number of bytes from VQ: %d \n", numBytes);
		if ((maxAddr && maxAddr >= mbi.BaseAddress) || end <= (ADDRINT)mbi.BaseAddress) break;
		maxAddr = mbi.BaseAddress;
		if (mbi.State != MEM_FREE && mbi.Type != MEM_PRIVATE) {
			regionend = (ADDRINT)mbi.BaseAddress + mbi.RegionSize - 1;
			//printf("ENTRY-CHECK StartAddress: %x , EndAddress: %x \n", memRangArray1[scCounter1].Array[regions].StartAddress, memRangArray1[scCounter1].Array[regions].EndAddress);
			//printf("\t scCounter1: %d \n", scCounter1);			pippo1[regions].EndAddress = regionend;
			pippo2[regions].EndAddress = regionend;
			pippo2[regions].StartAddress = (ADDRINT)mbi.BaseAddress;
			pippo2[regions].RegionID = regions;
			pippo2[regions].Size = mbi.RegionSize;
			regions++;
		}
		size += mbi.RegionSize;
		MyAddress += mbi.RegionSize;
	}
	printf("EXIT regions count: %d \n", regions);
}
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
VOID HOOKS_NtAllocateVirtualMemory_entry(CONTEXT *ctx, SYSCALL_STANDARD std){
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
		mem_array[img_counter].high = baseAddress+(int)RegSize - 1;
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
	pintool_tls *tdata = static_cast<pintool_tls*>(PIN_GetThreadData(tls_key, thread_id));
	syscall_t *sc = &tdata->sc;
	sc->syscall_number = syscall_number;
	printf("****************Syscall number: %x ****************\n", syscall_number);
	funcEntry();
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
	if (syscall_number == NtOpenProcessTokenEx) { //NtAllocateVirtualMemory
		//TraceFile << "sc->syscall_number " << (void*)sc->syscall_number << "\n";
		//HOOKS_NtAllocateVirtualMemory_entry(ctx, std);
		printf("NtOpenProcessTokenEx \n");
	}
	if (syscall_number == NtQueryInformationTransaction) { //NtAllocateVirtualMemory
		//TraceFile << "sc->syscall_number " << (void*)sc->syscall_number << "\n";
		//HOOKS_NtAllocateVirtualMemory_entry(ctx, std);
		printf("NtQueryInformationTransaction \n");
	}
	if (syscall_number == NtOpenKeyEx) { //NtAllocateVirtualMemory
		//TraceFile << "sc->syscall_number " << (void*)sc->syscall_number << "\n";
		//HOOKS_NtAllocateVirtualMemory_entry(ctx, std);
		printf("NtOpenKeyEx	 \n");
	}if (syscall_number == NtQueryValueKey) { //NtAllocateVirtualMemory
		//TraceFile << "sc->syscall_number " << (void*)sc->syscall_number << "\n";
		//HOOKS_NtAllocateVirtualMemory_entry(ctx, std);
		printf("NtQueryVirtualMemory \n");
	}if (syscall_number == NtClose) { //NtAllocateVirtualMemory
		//TraceFile << "sc->syscall_number " << (void*)sc->syscall_number << "\n";
		//HOOKS_NtAllocateVirtualMemory_entry(ctx, std);
		printf("NtClose \n");
	}if (syscall_number == NtOpenKNtOpenRegistryTransactioney) { //NtAllocateVirtualMemory
		//TraceFile << "sc->syscall_number " << (void*)sc->syscall_number << "\n";
		//HOOKS_NtAllocateVirtualMemory_entry(ctx, std);
		printf("NtOpenKNtOpenRegistryTransactioney \n");
	}if (syscall_number == NtPssCaptureVaSpaceBulk) { //NtAllocateVirtualMemory
		//TraceFile << "sc->syscall_number " << (void*)sc->syscall_number << "\n";
		//HOOKS_NtAllocateVirtualMemory_entry(ctx, std);
		printf("NtPssCaptureVaSpaceBulk \n");
	}if (syscall_number == NtOpenSemaphore) { //NtAllocateVirtualMemory
		//TraceFile << "sc->syscall_number " << (void*)sc->syscall_number << "\n";
		//HOOKS_NtAllocateVirtualMemory_entry(ctx, std);
		printf("NtOpenSemaphore \n");
	}if (syscall_number == NtQuerySection) { //NtAllocateVirtualMemory
		//TraceFile << "sc->syscall_number " << (void*)sc->syscall_number << "\n";
		//HOOKS_NtAllocateVirtualMemory_entry(ctx, std);
		printf("NtQuerySection \n");
	}if (syscall_number == NtQueryAttributesFile) { //NtAllocateVirtualMemory
		//TraceFile << "sc->syscall_number " << (void*)sc->syscall_number << "\n";
		//HOOKS_NtAllocateVirtualMemory_entry(ctx, std);
		printf("NtQueryAttributesFile \n");
	}if (syscall_number == NtOpenFile) { //NtAllocateVirtualMemory
		//TraceFile << "sc->syscall_number " << (void*)sc->syscall_number << "\n";
		//HOOKS_NtAllocateVirtualMemory_entry(ctx, std);
		printf("NtOpenFile \n");
	}if (syscall_number == NtSetInformationResourceManager) { //NtAllocateVirtualMemory
		//TraceFile << "sc->syscall_number " << (void*)sc->syscall_number << "\n";
		//HOOKS_NtAllocateVirtualMemory_entry(ctx, std);
		printf("NtSetInformationResourceManager \n");
	}if (syscall_number == NtQueryInformationProcess) { //NtAllocateVirtualMemory
		//TraceFile << "sc->syscall_number " << (void*)sc->syscall_number << "\n";
		//HOOKS_NtAllocateVirtualMemory_entry(ctx, std);
		printf("NtQueryInformationProcess \n");
	}if (syscall_number == NtQueryPerformanceCounter) { //NtAllocateVirtualMemory
		//TraceFile << "sc->syscall_number " << (void*)sc->syscall_number << "\n";
		//HOOKS_NtAllocateVirtualMemory_entry(ctx, std);
		printf("NtQueryPerformanceCounter \n");
	}if (syscall_number == NtWriteFile) { //NtAllocateVirtualMemory
		//TraceFile << "sc->syscall_number " << (void*)sc->syscall_number << "\n";
		//HOOKS_NtAllocateVirtualMemory_entry(ctx, std);
		printf("NtWriteFile \n");
	}if (syscall_number == NtTerminateProcess) { //NtAllocateVirtualMemory
		//TraceFile << "sc->syscall_number " << (void*)sc->syscall_number << "\n";
		//HOOKS_NtAllocateVirtualMemory_entry(ctx, std);
		printf("NtTerminateProcess \n");
	}if (syscall_number == NtQueryVirtualMemory) { //NtAllocateVirtualMemory
		//TraceFile << "sc->syscall_number " << (void*)sc->syscall_number << "\n";
		//HOOKS_NtAllocateVirtualMemory_entry(ctx, std);
		printf("NtQueryVirtualMemory \n");
	}if (syscall_number == NtRequestWaitReplyPort) { //NtAllocateVirtualMemory
		//TraceFile << "sc->syscall_number " << (void*)sc->syscall_number << "\n";
		//HOOKS_NtAllocateVirtualMemory_entry(ctx, std);
		printf("NtRequestWaitReplyPort \n");
	}if (syscall_number == NtQueryVolumeInformationFile) { //NtAllocateVirtualMemory
		//TraceFile << "sc->syscall_number " << (void*)sc->syscall_number << "\n";
		//HOOKS_NtAllocateVirtualMemory_entry(ctx, std);
		printf("NtQueryVolumeInformationFile \n");
	}
}


VOID HOOKS_SyscallExit(THREADID thread_id, CONTEXT *ctx, SYSCALL_STANDARD std) {
	pintool_tls *tdata = static_cast<pintool_tls*>(PIN_GetThreadData(tls_key, thread_id));
	syscall_t *sc = &tdata->sc;
	funcExit();
	ADDRINT delta1 = 0;
	ADDRINT delta2 = 0;

	prova1.regionsSum = 8;
	prova2.regionsSum = 99;

	bool pippo = changed(&prova1, &prova2);


	for (int i = 0; i < 83; i++) {
		delta1 = pippo1[i].StartAddress - pippo2[i].StartAddress;
		delta2 = pippo1[i].EndAddress - pippo2[i].EndAddress;

		if(delta1!=0 || delta2!=0){
		printf("******************************** \n");
		printf("ENTRY Start address: %x, End Address: %x \n", pippo1[i].StartAddress, pippo1[i].EndAddress);
		printf("EXIT Start address: %x, End Address: %x \n", pippo2[i].StartAddress, pippo2[i].EndAddress);
		printf(" \t\t\t\t delta1: %d, delta2: %d \n", delta1, delta2);
		printf("ENTRY size: %d, regionID: %d \n", pippo1[i].Size, pippo1[i].RegionID);
		printf("EXIT size: %d, regionID: %d \n", pippo2[i].Size, pippo2[i].RegionID);
	

		pippo3.array1[diffIndex].EndAddress = pippo1[i].EndAddress;
		pippo3.array1[diffIndex].StartAddress = pippo1[i].StartAddress;
		pippo3.array1[diffIndex].Size = pippo1[i].Size;
		pippo3.array1[diffIndex].RegionID = pippo1[i].RegionID;

		pippo3.array2[diffIndex].EndAddress = pippo2[i].EndAddress;
		pippo3.array2[diffIndex].StartAddress = pippo2[i].StartAddress;
		pippo3.array2[diffIndex].Size = pippo2[i].Size;
		pippo3.array2[diffIndex].RegionID = pippo2[i].RegionID;

		printf("ENTRY pippo3.array1[diffIndex].StartAddress: %x, pippo3.array1[diffIndex].EndAddress: %x \n", pippo3.array1[diffIndex].StartAddress, pippo3.array1[diffIndex].EndAddress);
		printf("EXIT pippo3.array2[diffIndex].StartAddress: %x, pippo3.array2[diffIndex].EndAddress: %x \n", pippo3.array2[diffIndex].StartAddress, pippo3.array2[diffIndex].EndAddress);
		printf("******************************** \n");
		//printf(" \t\t\t\t delta1: %d, delta2: %d \n", delta1, delta2);
		//printf("ENTRY size: %d, regionID: %d \n", pippo1[i].Size, pippo1[i].RegionID);
		//printf("EXIT size: %d, regionID: %d \n", pippo2[i].Size, pippo2[i].RegionID);


		diffIndex++;

		}
	}
			//TraceFile << "sc->syscall_number " << (void*)sc->syscall_number << "\n";

}

	//EnumSyscalls(); // parse ntdll for ordinals
	//PIN_AddSyscallEntryFunction(SyscallEntry, NULL);
	//PIN_AddThreadStartFunction(OnThreadStart, NULL);
	//PIN_AddSyscallExitFunction(SyscallExit, NULL);
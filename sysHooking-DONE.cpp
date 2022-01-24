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
	VirtualAlloc_INDEX,
	HeapReAlloc_INDEX,
	realloc_INDEX,
	HeapFree_INDEX,
	CreateFileMappingW_INDEX,
	CreateFileMappingA_INDEX,
	CreateFileA_INDEX
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
//syscall structure
typedef struct _syscall_t {
	ADDRINT syscall_number;
	union {
		ADDRINT args[16];
		struct {
			ADDRINT arg0, arg1, arg2, arg3;
			ADDRINT arg4, arg5, arg6, arg7;
			ADDRINT arg8, arg9, arg10, arg11;
		};
	};
} syscall_t;
typedef void(*syscall_hook)(syscall_t *sc, CONTEXT *ctx, SYSCALL_STANDARD std);
typedef struct {
	syscall_t sc;
} pintool_tls;

//*******************************************************************
//GLOBAL VARIABLES
//*******************************************************************
KNOB< string > KnobOutputFile(KNOB_MODE_WRITEONCE, "pintool", "o", "migatte2.out", "specify file name");
ofstream TraceFile;
int img_counter = 0;
mem_regions mem_array[100]; //array in which i store valuable informations about the images
mem_map op_map[10000];
static map<std::string, int> fMap;
/*SYSCALLS*/
unsigned int  NtAllocateVirtualMemory = 0x00000013;
unsigned int  NtFreeVirtualMemory = 0x00000084;
//unsigned int  NtAllocateVirtualMemoryEx = 0x00000084; NON ESISTE
unsigned int  NtMapViewOfSection = 0x000000a8;
unsigned int  NtUnmapViewOfSection = 0x00000181;
unsigned int  NtCreateSection = 0x00000054;
TLS_KEY tls_key;
#define MAXSYSCALLS		0x200
CHAR* syscallIDs[MAXSYSCALLS] = { 0 };

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

VOID HOOKS_NtProtectVirtualMemory_exit(CONTEXT *ctx, SYSCALL_STANDARD std){
	TraceFile << "in HOOKS_NtProtectVirtualMemory_exit \n";
}
VOID HOOKS_NtUnmapViewOfSection_exit(CONTEXT *ctx, SYSCALL_STANDARD std) {
	TraceFile << "in HOOKS_NtUnmapViewOfSection_exit \n";
}
VOID HOOKS_NtFreeVirtualMemory_exit(CONTEXT *ctx, SYSCALL_STANDARD std) {
	TraceFile << "in HOOKS_NtFreeVirtualMemory_exit \n";
}
VOID HOOKS_NtCreateSection_exit(CONTEXT *ctx, SYSCALL_STANDARD std) {
	TraceFile << "in HOOKS_NtCreateSection_exit \n";
}
VOID HOOKS_NtAllocateVirtualMemory_exit(CONTEXT *ctx, SYSCALL_STANDARD std){
	TraceFile << "in HOOKS_NtAllocateVirtualMemory_exit \n";
}
VOID HOOKS_NtMapViewOfSection_exit(CONTEXT *ctx, SYSCALL_STANDARD std) {
	TraceFile << "in HOOKS_NtMapViewOfSection_exit \n";
}


VOID OnThreadStart(THREADID tid, CONTEXT *ctxt, INT32, VOID *) {
	pintool_tls* tdata = (pintool_tls*)calloc(1, sizeof(pintool_tls));
	tls_key = PIN_CreateThreadDataKey(NULL);
	if (PIN_SetThreadData(tls_key, tdata, tid) == FALSE) {
		//LOG_AR("PIN_SetThreadData failed");
		PIN_ExitProcess(1);
	}
}

VOID HOOKS_SyscallEntry(THREADID thread_id, CONTEXT *ctx, SYSCALL_STANDARD std) {
	// get the syscall number
	ADDRINT syscall_number = PIN_GetSyscallNumber(ctx, std);
	pintool_tls *tdata = static_cast<pintool_tls*>(PIN_GetThreadData(tls_key, thread_id));
	syscall_t *sc = &tdata->sc;
	sc->syscall_number = syscall_number;

	if (syscall_number == NtAllocateVirtualMemory) { //NtAllocateVirtualMemory
		//TraceFile << "sc->syscall_number " << (void*)sc->syscall_number << "\n";
		HOOKS_NtAllocateVirtualMemory_exit(ctx, std);
	}
	if (syscall_number == NtFreeVirtualMemory) { //NtAllocateVirtualMemory
		//TraceFile << "sc->syscall_number " << (void*)sc->syscall_number << "\n";
		HOOKS_NtFreeVirtualMemory_exit(ctx, std);
	}
	if (syscall_number == NtMapViewOfSection) { //NtAllocateVirtualMemory
		//TraceFile << "sc->syscall_number " << (void*)sc->syscall_number << "\n";
		HOOKS_NtMapViewOfSection_exit(ctx, std);
	}
	if (syscall_number == NtUnmapViewOfSection) { //NtAllocateVirtualMemory
		//TraceFile << "sc->syscall_number " << (void*)sc->syscall_number << "\n";
		HOOKS_NtUnmapViewOfSection_exit(ctx, std);
	}
	if (syscall_number == NtCreateSection) { //NtAllocateVirtualMemory
		//TraceFile << "sc->syscall_number " << (void*)sc->syscall_number << "\n";
		HOOKS_NtCreateSection_exit(ctx, std);
	}
}


VOID HOOKS_SyscallExit(THREADID thread_id, CONTEXT *ctx, SYSCALL_STANDARD std) {
	//TLS_KEY tls_key;
	pintool_tls *tdata = static_cast<pintool_tls*>(PIN_GetThreadData(tls_key, thread_id));
	syscall_t *sc = &tdata->sc;
			//TraceFile << "sc->syscall_number " << (void*)sc->syscall_number << "\n";

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
VOID SyscallEntry(THREADID thread_id, CONTEXT *ctx, SYSCALL_STANDARD std, void *v) {
		HOOKS_SyscallEntry(thread_id, ctx, std);
}VOID SyscallExit(THREADID thread_id, CONTEXT *ctx, SYSCALL_STANDARD std, void *v) {
		HOOKS_SyscallExit(thread_id, ctx, std);
}

int main(int argc, char* argv[]) {
	// Initialize symbol processing
	PIN_InitSymbols();
	// Initialize pin
	if (PIN_Init(argc, argv)) return Usage();
	TraceFile.open(KnobOutputFile.Value().c_str());
	EnumSyscalls(); // parse ntdll for ordinals
	PIN_AddSyscallEntryFunction(SyscallEntry, NULL);
	PIN_AddThreadStartFunction(OnThreadStart, NULL);
	PIN_AddSyscallExitFunction(SyscallExit, NULL);
	// Register Fini to be called when the application exits
	PIN_AddFiniFunction(Fini, 0);
	// Start the program, never returns
	PIN_StartProgram();
	return 0;
}
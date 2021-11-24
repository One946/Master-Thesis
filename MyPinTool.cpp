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
}
using namespace std;
//*******************************************************************
//TYPEDEF
//*******************************************************************
typedef struct mem_regions_t {
	int id;
	int high;
	int low;
	string name;
}mem_regions;
typedef struct mem_map_t {
	VOID * address;
	char op;
	int id;
}mem_map;
typedef unsigned char MEM_MASK;
typedef struct sez {
	ADDRINT start;
	ADDRINT end;
} struct_section;
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

// https://stackoverflow.com/questions/28859456/function-returning-function-is-not-allowed-in-typedef-foobar
typedef int long(NTAPI* _NtQueryVirtualMemory)( //since NTSTATUS is actually a typedef to LONG. The workaround was to replace the function return type from NTSTATUS to LONG(but ideally includes should be fixed so that NTSTATUS is resoved).
	W::HANDLE                   ProcessHandle,
	W::PVOID                    BaseAddress,
	MEMORY_INFORMATION_CLASS MemoryInformationClass,
	W::PVOID                    MemoryInformation,
	W::SIZE_T                   MemoryInformationLength,
	W::PSIZE_T                  ReturnLength
	);
//*******************************************************************
//GLOBAL VARIABLES
//*******************************************************************
KNOB< string > KnobOutputFile(KNOB_MODE_WRITEONCE, "pintool", "o", "migatte2.out", "specify file name");
ofstream TraceFile;
MEM_MASK pages[OS_NUM_PAGES]; // 4GB address space
vector<struct_section> dllTextRanges;
int img_counter = 0;
mem_regions mem_array[100]; //array in which i store valuable informations about the images
int counter = 0; //counter for instructions

char* whitelistedDLLs[] = { "gdi32.dll",
							"msctf.dll",
							"comctl32.dll",
							"windowscodecs.dll",
							"kernelbase.dll",
							"msvcrt.dll" };
//*******************************************************************
//FUNCTIONS
//******************************************************************* 
_NtQueryVirtualMemory NtQueryVirtualMemory;

VOID PhpEnumGenericMappedFilesAndImages(W::HANDLE ProcessHandle) {
	W::BOOLEAN querySucceeded;
	W::PVOID baseAddress;
	W::MEMORY_BASIC_INFORMATION basicInfo;
	baseAddress = (W::PVOID)0;
	if (!(NtQueryVirtualMemory(
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
		wchar_t fileName[64];
		W::BOOLEAN cont;
		if (basicInfo.Type == MEM_MAPPED || basicInfo.Type == MEM_IMAGE)
		{
			if (basicInfo.Type == MEM_MAPPED)
				type = PH_MODULE_TYPE_MAPPED_FILE;
			else
				type = PH_MODULE_TYPE_MAPPED_IMAGE;
			allocationBase = basicInfo.AllocationBase;
			allocationSize = 0;
			do
			{
				baseAddress = PTR_ADD_OFFSET(baseAddress, basicInfo.RegionSize);
				allocationSize += basicInfo.RegionSize;

				if (!(NtQueryVirtualMemory(
					ProcessHandle,
					baseAddress,
					MemoryBasicInformation,
					&basicInfo,
					sizeof(W::MEMORY_BASIC_INFORMATION),
					NULL
				)))
				{
					querySucceeded = FALSE;
					break;
				}
			} while (basicInfo.AllocationBase == allocationBase);
			/*if (!(PhGetProcessMappedFileName(
				ProcessHandle,
				allocationBase,
				&fileName
			)))
			{
				continue;
			}*/
			//wprintf(L"Filename: %s\n", fileName);
			cout << "Before TraceFile";
			TraceFile << fileName<< "\n";
			char* type_s = (basicInfo.Type == MEM_MAPPED) ? "mapped" : "image";
			//printf("Base, size, type: %p %x %s\n", allocationBase, allocationSize, type_s);
		}
		else
		{
			baseAddress = PTR_ADD_OFFSET(baseAddress, basicInfo.RegionSize);
			if (!(NtQueryVirtualMemory(
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
inline MEM_MASK getRWX(SEC section) {
	// ASSUMPTION: Pin does not load sections with PAGE_GUARD enabled
	// bit 0: R, bit 1: W, bit 2: X
	return MEM_ACCESSIBLE |
		(SEC_IsReadable(section) ? 1 : 0) | // ternary to suppress warning
		((SEC_IsWriteable(section) ? 1 : 0) << 1) |
		((SEC_IsExecutable(section) ? 1 : 0) << 2);
}

int MEMORY_AuxRegisterArea(ADDRINT start, ADDRINT size, MEM_MASK mask) {
	UINT32 pageIdxStart = MEM_GET_PAGE(start);
	UINT32 pageIdxEnd = MEM_GET_PAGE(start + size - 1);
	if (size == 0) pageIdxEnd = pageIdxStart;
	int ret = 0;
	MEM_MASK lastMask = -1;
	do {
		MEM_MASK m = pages[pageIdxStart];
		if (m) {
			if (m != mask) {
				if (lastMask != m) {
					//cout << "COFFEE " << hex << start << " " << hex << pageIdxStart << " " << hex << (ADDRINT)m << " " << hex << (ADDRINT)mask << endl;
					lastMask = m;
				}
				ret |= 0x1;
			}
			ret |= 0x2; // 0x1 for wrong, 0x2 for found
		}
		pages[pageIdxStart] = mask;
	} while (pageIdxStart++ != pageIdxEnd);
	return ret;
}

ADDRINT PIN_FAST_ANALYSIS_CALL validateRead(ADDRINT addr) {
	return !MEM_IS_READABLE(pages[MEM_GET_PAGE(addr)]);
}

ADDRINT validateReadAux(ADDRINT val, ADDRINT eip, THREADID tid, CONTEXT *ctx) {
	MEM_MASK mask = pages[MEM_GET_PAGE(val)];

	if (mask == 0) { // region not in the map/no permissions
		EXCEPTION_INFO exc;
		// 0xc0000005 is Windows code for memory access violation
		PIN_InitWindowsExceptionInfo(&exc, 0xc0000005, eip);
		//PIN_SetContextReg(ctx, REG_INST_PTR, PIN_GetContextReg(ctx, REG_INST_PTR) + 0x1); // add 0x1 to get the right address
		PIN_RaiseException(ctx, tid, &exc);
	}
	else if (!(mask & MEM_ACCESSIBLE)) { // region is not accessible
		// Pin doesn't handle guarded pages correctly only when
		// fetching code, but data read/write accesses are fine
		//LOG_AR("(IM)POSSIBLE PAGE GUARD BUG IN PIN");
	}
	else if (!(mask & MEM_READABLE)) { // region is not readable
		EXCEPTION_INFO exc;
		PIN_InitWindowsExceptionInfo(&exc, 0xc0000005, val);
		//PIN_SetContextReg(ctx, REG_INST_PTR, PIN_GetContextReg(ctx, REG_INST_PTR) + 0x1); // add 0x1 to get the right address
		PIN_RaiseException(ctx, tid, &exc);
	}
	return val;
}
MEM_MASK MEMORY_WinToPinCast(UINT32 permissions) {
	// https://docs.microsoft.com/en-us/windows/desktop/memory/memory-protection-constants

	// CFI stuff not available in VS2010
#ifndef PAGE_TARGETS_INVALID
#define PAGE_TARGETS_INVALID	0x40000000
#endif
#ifndef PAGE_TARGETS_NO_UPDATE
#define PAGE_TARGETS_NO_UPDATE	0x40000000
#endif

// standard modifiers
// PAGE_GUARD 0x100 => needs special handling
// PAGE_NOCACHE 0x200
// PAGE_WRITECOMBINE 0x400
	MEM_MASK mask;
	UINT32 clearMask = ~(PAGE_NOCACHE | PAGE_WRITECOMBINE |
		PAGE_TARGETS_INVALID | PAGE_TARGETS_NO_UPDATE);

	switch (permissions & clearMask) {
	case PAGE_EXECUTE:
		mask = MEM_EXECUTABLE | MEM_READABLE; break;
	case PAGE_EXECUTE_READ:
		mask = MEM_EXECUTABLE | MEM_READABLE; break;
	case PAGE_EXECUTE_READWRITE:
	case PAGE_EXECUTE_WRITECOPY:
		mask = MEM_EXECUTABLE | MEM_READABLE | MEM_WRITEABLE; break;
	case PAGE_READONLY:
		mask = MEM_READABLE; break;
	case PAGE_READWRITE:
	case PAGE_WRITECOPY:
		mask = MEM_READABLE | MEM_WRITEABLE; break;
	default:
		mask = 0; // PAGE_NOACCESS
	}
	if (mask && !(permissions & PAGE_GUARD)) {
		mask |= MEM_ACCESSIBLE;
	}
	return mask;
}
bool MEMORY_AddMappedMemory(ADDRINT start, ADDRINT end, ADDRINT eip) {
	W::MEMORY_BASIC_INFORMATION mem;
	W::SIZE_T numBytes;
	ADDRINT address = start;
	W::PVOID maxAddr = 0;
	int count = 0;
	bool changed = FALSE;
	while (1) {
		numBytes = W::VirtualQuery((W::LPCVOID)address, &mem, sizeof(mem));
		// workaround for not getting stuck on the last valid block
		if ((maxAddr && maxAddr >= mem.BaseAddress) || end <= (ADDRINT)mem.BaseAddress) break;
		maxAddr = mem.BaseAddress;
		ADDRINT startAddr = (ADDRINT)mem.BaseAddress;
		ADDRINT size = mem.RegionSize;
		MEM_MASK mask = MEMORY_WinToPinCast(mem.Protect);
		bool insideDll = FALSE;
		if (eip != NULL) {
			for (std::vector<struct_section>::iterator it = dllTextRanges.begin(); it != dllTextRanges.end(); ++it) {
				if (it->start <= eip && eip < it->end) {
					insideDll = TRUE;
				}
			}
		}
		if (mem.State != MEM_FREE && (mem.Type != MEM_PRIVATE || insideDll)) {
			++count;
			if (mask != 0) {
				int ret = MEMORY_AuxRegisterArea(startAddr, size, mask);
				if (!ret || ret & 0x1) changed = true;
			}
		}
		address += mem.RegionSize;
	}
	return changed;
}
void MEMORY_RegisterArea(ADDRINT start, ADDRINT size, MEM_MASK mask) {
	UINT32 pageIdxStart = MEM_GET_PAGE(start);
	UINT32 pageIdxEnd = MEM_GET_PAGE(start + size - 1);
	if (size == 0) pageIdxEnd = pageIdxStart;
	do {
		pages[pageIdxStart] = mask;
	} while (pageIdxStart++ != pageIdxEnd);
}
VOID RecordMemR(VOID * ip, VOID * addr) {
	int mem_reg = 0;
	W::DWORD protection = 0;
	counter++;
	W::MEMORY_BASIC_INFORMATION memInfo;
	bool done = FALSE;
	//for(IMG img = APP_ImgHead(); IMG_Valid(img); img = IMG_Next(img)){
	for (int i = 0; i < img_counter; i++) {
		//if (counter < 10000 && (int)addr < IMG_HighAddress(img) && (int)addr >=IMG_LowAddress(img)){
		if (counter < 10000 && (int)addr < mem_array[i].high && (int)addr >= mem_array[i].low) {
			done = TRUE;
			//TraceFile << op_map[counter].id << ") " << op_map[counter].op << " happened in img: " << mem_array[i].name << "\n";
		}
	}
	if (!done) {
		W::VirtualQuery((W::LPCVOID)addr, &memInfo, sizeof(memInfo));
		mem_reg = (int)memInfo.BaseAddress + memInfo.RegionSize;
		protection = memInfo.Protect;
		mem_array[img_counter].id = 0;
		mem_array[img_counter].high = mem_reg;
		mem_array[img_counter].low = (int)memInfo.BaseAddress;
		mem_array[img_counter].name = "Unknown";
	}
}
//function to record a write if falls within known mem_region
VOID RecordMemW(VOID * ip, VOID * addr) {
	int mem_reg = 0;
	counter++;
	W::MEMORY_BASIC_INFORMATION memInfo;
	bool done = FALSE;
	for (int i = 0; i < img_counter; i++) {
		if (counter < 10000 && (int)addr < mem_array[i].high && (int)addr >= mem_array[i].low) {
			done = TRUE;
		}
	}
	if (!done) {
		W::VirtualQuery((W::LPCVOID)addr, &memInfo, sizeof(memInfo));
		mem_reg = (int)memInfo.BaseAddress + memInfo.RegionSize;
		mem_array[img_counter].id = 0;
		mem_array[img_counter].high = mem_reg;
		mem_array[img_counter].low = (int)memInfo.BaseAddress;
		mem_array[img_counter].name = "Unknown";
		W::HANDLE curProc = W::GetCurrentProcess();
		PhpEnumGenericMappedFilesAndImages(curProc);
	}
}
static void MEMORY_InstrumentINS(INS ins,VOID* ip) {
	UINT32 numMemOps = INS_MemoryOperandCount(ins);
	for (UINT32 opIdx = 0; opIdx < numMemOps; opIdx++) {
		if (INS_MemoryOperandIsRead(ins, opIdx)) {
			INS_InsertCall(
				ins, IPOINT_BEFORE, (AFUNPTR)RecordMemR,
				IARG_INST_PTR,
				IARG_MEMORYOP_EA, opIdx,
				IARG_END);
		}
		/*if (INS_MemoryOperandIsWritten(ins, opIdx)) {
			INS_InsertCall(
				ins, IPOINT_BEFORE, (AFUNPTR)RecordMemW,
				IARG_INST_PTR,
				IARG_MEMORYOP_EA, opIdx,
				IARG_END);
		}*/
	}
}

static void image(IMG img, VOID* ip) {
	// with _paranoidKnob ESP is seen as a general-purpose register
	ADDRINT imgStart = IMG_LowAddress(img);
	ADDRINT imgEnd = IMG_HighAddress(img);
	UINT32 numReg = IMG_NumRegions(img);
	for (size_t i = 0; i < numReg; i++) {
		ADDRINT hAddr = IMG_RegionHighAddress(img, i);
		ADDRINT lAddr = IMG_RegionLowAddress(img, i);
		MEMORY_AddMappedMemory(lAddr, hAddr, NULL);
	}

	bool whiteListed = false;
	const char* imgName = IMG_Name(img).c_str();
	char tmp[MAX_PATH];
	for (size_t i = 0; imgName[i]; ++i) { // strlen :-)
		tmp[i] = tolower(imgName[i]);
	}
	string imgNameStr(tmp);
	for (size_t i = 0; i < sizeof(whitelistedDLLs) / sizeof(char*); ++i) {
		if (imgNameStr.find(whitelistedDLLs[i]) != string::npos) {
			whiteListed = true;
			break;
		}
	}
	for (SEC section = IMG_SecHead(img); SEC_Valid(section); section = SEC_Next(section)) {
		ADDRINT secStart = SEC_Address(section);
		ADDRINT secSize = SEC_Size(section);

		// DLLs have only .text as executable section (I guess?)
		if (whiteListed && SEC_Name(section).compare(".text") == 0) {
			struct_section sec;
			sec.start = secStart;
			sec.end = secStart + secSize;
			dllTextRanges.push_back(sec);
		}
		MEM_MASK rwx = getRWX(section);
		// memory hook
		MEMORY_RegisterArea(secStart, secSize, rwx);
	}

}

VOID parse_funcsyms(IMG img, VOID *v) {
	if (!IMG_Valid(img)) return;
	mem_array[img_counter].id = IMG_Id(img);
	mem_array[img_counter].high = IMG_HighAddress(img);
	mem_array[img_counter].low = IMG_LowAddress(img);
	mem_array[img_counter].name = IMG_Name(img);
	img_counter++;
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
	// Parse function names
	IMG_AddInstrumentFunction(parse_funcsyms, 0);
	// function to analyze memory access 
	INS_AddInstrumentFunction(MEMORY_InstrumentINS, 0);
	// Register Fini to be called when the application exits
	PIN_AddFiniFunction(Fini, 0);
	// Start the program, never returns
	PIN_StartProgram();
	return 0;
}
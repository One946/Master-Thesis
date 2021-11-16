#include "pin.H"
#include <iostream>
#include <fstream>
#include <stdlib.h>
#include <string>
/*mem array begin
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
namespace W {
#define _WINDOWS_H_PATH_ C:/Program Files/Windows Kits/10/Include/10.0.17763.0/um
#include <Windows.h>
}
using namespace std;

//*******************************************************************
//TYPE DEF
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
}mem_map;
typedef struct _MEMORY_BASIC_INFORMATION {
	void*  BaseAddress;
	void*  AllocationBase;
	int  AllocationProtect;
	int   PartitionId;
	size_t RegionSize;
	int State;
	int  Protect;
	int  Type;
} MEMORY_BASIC_INFORMATION, *PMEMORY_BASIC_INFORMATION;

//*******************************************************************
//GLOBAL VARIABLES
//*******************************************************************
KNOB< string > KnobOutputFile(KNOB_MODE_WRITEONCE, "pintool", "o", "migatte2.out", "specify file name");
ofstream TraceFile;
int* p2BuffVQ;
int* p2BuffVQEx;
int img_counter = 0;
mem_regions mem_array[100]; //array in which i store valuable informations about the images
mem_map op_map[1000];
int counter = 0;
//*******************************************************************
//FUNCTION DEFINITIONS
//*******************************************************************
//function to record a write if falls within known mem_region
VOID RecordMemR(VOID * ip, VOID * addr){
	counter++;
	if (counter < 100) {
		op_map[counter].address = addr;
		op_map[counter].op = 'R';
		TraceFile<< op_map[counter].op << " "<< op_map[counter].address << "\n";
	}
}
//function to record a write if falls within known mem_region
VOID RecordMemW(VOID * ip, VOID * addr){
	counter++;
	if (counter<100){
	op_map[counter].address = addr;
	op_map[counter].op = 'W';
	TraceFile << op_map[counter].op << " " << op_map[counter].address << "\n";
	}
}
//function to analyze memory accesses
VOID ValidateMemory(INS ins, VOID *v) {
	UINT32 mem_operands = INS_MemoryOperandCount(ins);
	for (UINT32 memOp = 0; memOp < mem_operands; memOp++)
	{
		if (INS_IsMemoryRead(ins)) {
			//op_map[counter].address = ins;
			//op_map[memOp].op = 0;
			INS_InsertCall(
				ins, IPOINT_BEFORE, (AFUNPTR)RecordMemR,
				IARG_INST_PTR,
				IARG_MEMORYOP_EA, memOp,
				IARG_END);
		}
		if (INS_IsMemoryRead(ins)) {
			//op_map[counter].address = memOp;
			//op_map[memOp].op = 1;
			INS_InsertCall(
				ins, IPOINT_BEFORE, (AFUNPTR)RecordMemW,
				IARG_INST_PTR,
				IARG_MEMORYOP_EA, memOp,
				IARG_END);
		}
	}
}
//function to parse VirtualQueryEx arguments
VOID ArgVQEx(char *name, ADDRINT arg0, ADDRINT arg1, ADDRINT arg2, ADDRINT arg3) { 
	//TraceFile << name << " ProcesHandle: (" << arg0 << ")" << " lpAddress: (" << arg1 << ")" << " lpBuffer: (" << arg2 << ")" << " dwLength: (" << arg3 << ")" << endl;
	int* lpbuffer = (int*)arg2;
	p2BuffVQEx = lpbuffer;
}
//function to parse virtual query arguments
VOID ArgVQ(char *name, ADDRINT arg0, ADDRINT arg1, ADDRINT arg2) { //lpbuffer of type MEMORY_BASIC_INFORMATION
	int* lpbuffer =(int*) arg1;
	p2BuffVQ = lpbuffer;
	//TraceFile << name << " lpAddress: (" << arg0 << ")" << " lpBuffer: (" << arg1 << ")" << " dwLength: (" << arg2 << ")" << endl;
}
//function to retrive VirtualQuery return value	
VOID VQAfter(ADDRINT ret, IMG img){
MEMORY_BASIC_INFORMATION* result = (MEMORY_BASIC_INFORMATION *) p2BuffVQ;
	for (int i = 0; i < 50; i++) {
		if((int)result->AllocationBase >= mem_array[i].low && (int) result->AllocationBase < mem_array[i].high){
			TraceFile << "\n spotted an address contained in a module";
			TraceFile << "\nThe module is: " << mem_array[i].name;
			TraceFile << "\n max address of the pages belonging to the image is: " << mem_array[i].high;
			TraceFile << "\n base address of the pages belonging to the image is: " << mem_array[i].low;
			TraceFile << "\n the id of the image is: " << mem_array[i].id;
			}
	}
}
VOID VQExAfter(ADDRINT ret) {
	MEMORY_BASIC_INFORMATION* result = (MEMORY_BASIC_INFORMATION *)p2BuffVQEx;
	for (int i = 0; i < 50; i++) {
		if((int)result->AllocationBase >= mem_array[i].low && (int) result->AllocationBase < mem_array[i].high){
			TraceFile << "\n spotted an address contained in a module VIRTUALQUERYEX";
			TraceFile << "\nThe module is: " << mem_array[i].name;
			TraceFile << "\n max address of the pages belonging to the image is: " << mem_array[i].high;
			TraceFile << "\n base address of the pages belonging to the image is: " << mem_array[i].low;
			TraceFile << "\n the id of the image is: " << mem_array[i].id;
			}
	}
}
//function to format information about VirtualQuery
VOID* alertprint(IMG img, RTN rtn) {
	TraceFile << "This file loads Image " << IMG_Name(img) << " which contains: \n";
	TraceFile << "\t" << RTN_Name(rtn) << " at address: " << RTN_Address(rtn) << "\n";
	TraceFile << "\t" << "the routine is associated with the following SYM " << SYM_Name(RTN_Sym(rtn)) << "\n";
	return 0;
}
VOID instrumentVQ(IMG img, VOID *v) {
	const char* name1 = "VirtualQuery";
	const char* name2 = "VirtualQueryEx";
	RTN rtn1 = RTN_FindByName(img, name1);
	RTN rtn2 = RTN_FindByName(img, name2);
	if (RTN_Valid(rtn1)) {
		RTN_Open(rtn1);
		//function to format information about VirtualQuery
		/*RTN_InsertCall(rtn1, IPOINT_AFTER, (AFUNPTR)alertprint(img, rtn1),
			IARG_FUNCRET_EXITPOINT_VALUE,
			IARG_END);*/
			//function to parse VirtualQuery arguments
		RTN_InsertCall(rtn1, IPOINT_BEFORE, (AFUNPTR)ArgVQ,
			IARG_ADDRINT, "VirtualQuery",
			IARG_FUNCARG_ENTRYPOINT_VALUE, 0, IARG_FUNCARG_ENTRYPOINT_VALUE, 1, IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
			IARG_END);
		//function to retrive VirtualQuery return value	
		RTN_InsertCall(rtn1, IPOINT_AFTER, (AFUNPTR)VQAfter,
			IARG_FUNCRET_EXITPOINT_VALUE, IARG_END);
		RTN_Close(rtn1);
	}
	if (RTN_Valid(rtn2)) {// does not work properly need to reconfigure for VQEx using function for VQ
		RTN_Open(rtn2);
		//function to format information about VirtualQuery
		/*RTN_InsertCall(rtn2, IPOINT_AFTER, (AFUNPTR)alertprint(img, rtn2),
			IARG_FUNCRET_EXITPOINT_VALUE,
			IARG_END);*/
			//function to parse VirtualQueryEx arguments
		RTN_InsertCall(rtn2, IPOINT_BEFORE, (AFUNPTR)ArgVQEx,
			IARG_ADDRINT, "VirtualQueryEx",
			IARG_FUNCARG_ENTRYPOINT_VALUE, 0, IARG_FUNCARG_ENTRYPOINT_VALUE, 1, IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
			IARG_END);
		//function to retrive VirtualQuery return value	
		RTN_InsertCall(rtn2, IPOINT_AFTER, (AFUNPTR)VQAfter,
			IARG_FUNCRET_EXITPOINT_VALUE, IARG_END);
		RTN_Close(rtn2);
	}
}
VOID parse_funcsyms(IMG img, VOID *v) {
	if (!IMG_Valid(img)) return;
	//building up an array in which i store valuable informations about the images
	mem_array[img_counter].id = IMG_Id(img);
	mem_array[img_counter].high = IMG_HighAddress(img);
	mem_array[img_counter].low = IMG_LowAddress(img);
	mem_array[img_counter].name = IMG_Name(img);
	img_counter++;
	instrumentVQ(img, 0);
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
int main(int argc, char* argv[]){
	// Initialize symbol processing
	PIN_InitSymbols();
	// Initialize pin
	if (PIN_Init(argc, argv)) return Usage();
	TraceFile.open(KnobOutputFile.Value().c_str());
	// Parse function names
	IMG_AddInstrumentFunction(parse_funcsyms, 0);
	// function to analyze memory access 
	INS_AddInstrumentFunction(ValidateMemory, 0);
	// Register Fini to be called when the application exits
	PIN_AddFiniFunction(Fini, 0);
	// Start the program, never returns
	PIN_StartProgram();
	return 0;
}
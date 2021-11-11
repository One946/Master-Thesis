#include "pin.H"
#include <iostream>
#include <fstream>
#include <stdlib.h>
#include <string>

namespace W {
#define _WINDOWS_H_PATH_ C:/Program Files/Windows Kits/10/Include/10.0.17763.0/um
#include <Windows.h>
}

using namespace std;

typedef struct mem_regions_t {
	int id;
	int high;
	int low;
	string name;
}mem_regions;

typedef struct mem_map_t {
	int address;
	bool op; //  1 for write 0 for read
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

KNOB< string > KnobOutputFile(KNOB_MODE_WRITEONCE, "pintool", "o", "migatte2.out", "specify file name");
ofstream TraceFile;
int* p2BuffVQ;
int* p2BuffVQEx;
int img_counter = 0;
mem_regions mem_array[50]; //array in which i store valuable informations about the images
mem_map op_map;

//function to record a write if falls within known mem_region
VOID RecordMemR(VOID * ip, VOID * addr){
	for (int i = 0; i < 50; i++) {
		if ((int)addr >= mem_array[i].low && (int)addr < mem_array[i].high) {
			TraceFile << "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++";
			TraceFile << "\n spotted an address contained in a known memory region belonging to a module";
			TraceFile << "\n The module is: " << mem_array[i].name <<" and the sample tried to access this addres with a ReadOP";
			TraceFile << "\n max address of the pages belonging to the image is: " << mem_array[i].high;
			TraceFile << "\n the address of interest is: " << (int)addr;
			TraceFile << "\n base address of the pages belonging to the image is: " << mem_array[i].low;
		}
	}
}
//function to record a write if falls within known mem_region
VOID RecordMemW(VOID * ip, VOID * addr){
	for (int i = 0; i < 50; i++) {
		if((int)addr >= mem_array[i].low && (int)addr < mem_array[i].high){
			TraceFile << "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++";
			TraceFile << "\n spotted an address contained in a known memory region belonging to a module";
			TraceFile << "\nThe module is: " << mem_array[i].name<< " and the sample tried to access this addres with a WriteOP";
			TraceFile << "\n max address of the pages belonging to the image is: " << mem_array[i].high;
			TraceFile << "\n the address of interest is: " << (int)addr;
			TraceFile << "\n base address of the pages belonging to the image is: " << mem_array[i].low;
		}
	}
}

//function to analyze memory accesses
VOID ValidateMemory(INS ins, VOID *v) {
	UINT32 mem_operands = INS_MemoryOperandCount(ins);
	for (UINT32 memOp = 0; memOp < mem_operands; memOp++){
		if (INS_MemoryOperandIsRead(ins, memOp))
		{
			INS_InsertCall(
				ins, IPOINT_BEFORE, (AFUNPTR)RecordMemR,
				IARG_INST_PTR,
				IARG_MEMORYOP_EA, memOp,
				IARG_END);
		}
		if (INS_MemoryOperandIsWritten(ins, memOp))
		{
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
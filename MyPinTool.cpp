#include "pin.H"
#include <iostream>
#include <fstream>
#include <stdlib.h>
#include <string>

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

using std::endl;
using std::ofstream;
using std::string;
KNOB< string > KnobOutputFile(KNOB_MODE_WRITEONCE, "pintool", "o", "migatte2.out", "specify file name");
ofstream TraceFile;
std::string s1 = "VirtualQueryEx";
std::string s2 = "VirtualQuery";
int* prova;

//function to parse VirtualQueryEx arguments
VOID ArgVQEx(char *name, ADDRINT arg0, ADDRINT arg1, ADDRINT arg2, ADDRINT arg3) { 
	TraceFile << name << " ProcesHandle: (" << arg0 << ")" << " lpAddress: (" << arg1 << ")" << " lpBuffer: (" << arg2 << ")" << " dwLength: (" << arg3 << ")" << endl;
}
//function to parse virtual query arguments
VOID ArgVQ(char *name, ADDRINT arg0, ADDRINT arg1, ADDRINT arg2) { //lpbuffer of type MEMORY_BASIC_INFORMATION
	int* lpbuffer =(int*) arg1;
	prova = lpbuffer;
	TraceFile << name << " lpAddress: (" << arg0 << ")" << " lpBuffer: (" << arg1 << ")" << " dwLength: (" << arg2 << ")" << endl;
}
//function to retrive VirtualQuery return value	
VOID VQAfter(ADDRINT ret){
MEMORY_BASIC_INFORMATION* result = (MEMORY_BASIC_INFORMATION *) prova;
	TraceFile << "  returns " << ret << endl;
	TraceFile << "base address of the pages " << result->BaseAddress;
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
	if (RTN_Valid(rtn2)) {
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
	for (SEC sec = IMG_SecHead(img); SEC_Valid(sec); sec = SEC_Next(sec)) {
		for (RTN rtn = SEC_RtnHead(sec); RTN_Valid(rtn); rtn = RTN_Next(rtn)) {
		std:string name = RTN_Name(rtn);
			if (!name.compare(s1) || !name.compare(s2)) {
				TraceFile << "Image " << IMG_Name(img) << " contains: \n";
				TraceFile << "\t Rtn name: " << name << "\n";
			}
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

VOID ImageUnload(IMG img, VOID* v) { TraceFile << "Unloading " << IMG_Name(img) << endl; }
// This function is called when the application exits
// It closes the output file.
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
int main(int argc, char* argv[])
{
	// Initialize symbol processing
	PIN_InitSymbols();
	// Initialize pin
	if (PIN_Init(argc, argv)) return Usage();
	TraceFile.open(KnobOutputFile.Value().c_str());
	// Parse function names
	IMG_AddInstrumentFunction(instrumentVQ, 0);
	// Register Fini to be called when the application exits
	PIN_AddFiniFunction(Fini, 0);
	// Start the program, never returns
	PIN_StartProgram();
	return 0;
}
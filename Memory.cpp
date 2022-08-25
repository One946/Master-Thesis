#include "pin.H"
#include "MemoryHeader.h"
#include "itree.h"
#include <iostream>

namespace W {
#define _WINDOWS_H_PATH_ C:/Program Files/Windows Kits/10/Include/10.0.17763.0/um
#include <Windows.h>
#include <ntstatus.h>
#include <subauth.h>
}
using namespace std;

//index for memory function
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

//*******************************************************************
//GLOBAL VARIABLES
//*******************************************************************
// tree to store dlls addresses
itreenode_t* itree = NULL;
//KNOB< string > KnobOutputFile(KNOB_MODE_WRITEONCE, "pintool", "o", "migatte2.out", "specify file name");
//ofstream TraceFile;
int img_counter = 0;
mem_regions mem_array[100]; //array in which i store valuable informations about the images
int counter = 0; //counter for instructions
mem_map op_map[10000];

// pointers for function results
int* p2BuffVQ;
int* p2BuffVQEx;
ADDRINT CTMAlloc;
ADDRINT GAlloc;
ADDRINT HAlloc;
ADDRINT LAlloc;
ADDRINT mAlloc;
ADDRINT VAlloc;
static map<std::string, int> fMap;
/********************************************************************/
/****************************ValidateMemory**************************/
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
		//TraceFile << "OK I PULL UP 3 \n";
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
	//TraceFile << "in findStacks\n";
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
				//TraceFile << "checking todo";
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
			//TraceFile << "added a stack region with id=" << mem_array[img_counter].id << "\n";
			//TraceFile << "base =" << base << " mem_array base=" << mem_array[index].low << "\n";
			img_counter++;
		}
	}
}
/*
VOID OnThreadStart(THREADID tid, CONTEXT *ctxt, INT32, VOID *) {
	//TraceFile << "in thread start \n";
	findStacks(ctxt);
}
*/

/********************************************************************/
/************************Validate Virtual Query**********************/
/********************************************************************/
//function to parse virtual query arguments
VOID ArgVQ(char *name, ADDRINT arg0, ADDRINT arg1, ADDRINT arg2) { //lpbuffer of type MEMORY_BASIC_INFORMATION
	int* lpbuffer = (int*)arg1;
	p2BuffVQ = lpbuffer;
}
//function to retrive VirtualQuery return value	
VOID VQAfter(ADDRINT ret, IMG img) {
	W::MEMORY_BASIC_INFORMATION* result = (W::MEMORY_BASIC_INFORMATION *)p2BuffVQ;
	//TraceFile << "Return value of VirtualQuery: " << (int)result->BaseAddress << " \n";
}
VOID ArgVQEx(char *name, ADDRINT arg0, ADDRINT arg1, ADDRINT arg2, ADDRINT arg3) {
	int* lpbuffer = (int*)arg2;
	p2BuffVQEx = lpbuffer;
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
VOID CTMAAfter(ADDRINT ret) {
	CTMAlloc = ret;
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
	//TraceFile << "Return value of  CoTaskMemAlloc :" << CTMAlloc << " \n";
	printf("Return value of  CoTaskMemAlloc : %x \n", CTMAlloc);
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
	//TraceFile << "Return value of  GlobalAlloc :" << GAlloc << " \n";
	printf("Return value of  GAlloc : %x \n", GAlloc);
}

VOID HAAfter(ADDRINT ret) {
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
	//TraceFile << "Return value of  HeapAlloc :" << HAlloc << " \n";
	printf("Return value of  HeapAlloc : %x \n", HAlloc);

}

VOID LAAfter(ADDRINT ret) {
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
	printf("Return value of  LAlloc : %x \n", LAlloc);

}

VOID MAAfter(ADDRINT ret) {// still have to implement the unload of dynamic memory
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
			mem_array[img_counter].name = "Malloc Result";
			mem_array[img_counter].protection = memInfo.Protect;
			mem_array[img_counter].pagesType = memInfo.Type;
			mem_array[img_counter].unloaded = 0;
			//TraceFile << "Return value of  malloc :" << (int)ret << " \n";
			//TraceFile << "mem_array[img_counter].low " << mem_array[img_counter].low << " mem_array[img_counter].high " << mem_array[img_counter].high;
			img_counter++;
		}
		printf("Return value of  malloc : %x \n", ret);
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
	//TraceFile << " return value of  VirtualAlloc :" << VAlloc << " \n";
	printf("Return value of  VirtualAlloc : %x \n", VAlloc);

}

VOID hFree(W::HANDLE hHeap, W::DWORD dwFlags, W::LPVOID lpMem) {
	//TraceFile << "HeapFree " << (int)lpMem << " \n";
	W::MEMORY_BASIC_INFORMATION memInfo;
	int todo = 0;
	int index = 0;
	//W::MEMORY_BASIC_INFORMATION memInfo;
	//W::VirtualQuery((W::LPCVOID)lpMem, &memInfo, sizeof(memInfo));
	if (img_counter < 100) {
		//W::VirtualQuery((W::LPCVOID)hHeap, &memInfo, sizeof(memInfo));
		for (int i = 0; i < img_counter; i++) {
			if ((int)hHeap - 1 <= mem_array[i].high && (int)hHeap >= mem_array[i].low) {
				//TraceFile << "first if	\n";
				todo = 1;
				index = i;
				break;
			}
		}
		if (todo) {
			//TraceFile << "Second if \n";
			mem_array[index].name = "hFree";
			mem_array[index].unloaded = 1;
		}
	}
	//TraceFile << "HeapFree \n";
}

VOID hReAllocB(ADDRINT hHeap, ADDRINT dwFlags, ADDRINT lpMem, ADDRINT dwBytes) {
	//TraceFile << "Before heapReAlloc " << (int)hHeap << " \n";
	int seen = 0;
	int index;

	if (img_counter < 100) {
		for (int i = 0; i < img_counter; i++) {
			if ((int)hHeap < mem_array[i].high && (int)hHeap >= mem_array[i].low) {
				seen = 1;
				index = i;
				//salva indice ed id ed aggiorna quello vecchio.
				//se non è contenuto nel mio array, devo solo aggiungere la nuova regione
				break;
			}
		}
		if (seen) {// aggiorna vecchio, inserisci nuovo
			mem_array[index].unloaded = 1;
			mem_array[index].name.append(" hReAlloc");
		}
	}
}

VOID hReAllocA(ADDRINT ret) {
	//TraceFile << "After heapReAlloc: " << (int)ret << " \n";
	int todo = 1;
	W::MEMORY_BASIC_INFORMATION memInfo;
	if (img_counter < 100) {
		for (int i = 0; i < img_counter; i++) {
			if ((int)ret < mem_array[i].high && (int)ret >= mem_array[i].low) {
				todo = 0;
				//salva indice ed id ed aggiorna quello vecchio.
				//se non è contenuto nel mio array, devo solo aggiungere la nuova regione
				break;
			}
		}
		if (todo) {// aggiorna vecchio, inserisci nuovo
			W::VirtualQuery((W::LPCVOID)ret, &memInfo, sizeof(memInfo));
			int mem_reg = (int)memInfo.BaseAddress + memInfo.RegionSize;
			mem_array[img_counter].protection = memInfo.Protect;
			mem_array[img_counter].id = img_counter;
			mem_array[img_counter].high = mem_reg - 1;
			mem_array[img_counter].low = (int)memInfo.BaseAddress;
			mem_array[img_counter].name = " hReAlloc";
			mem_array[img_counter].protection = memInfo.Protect;
			mem_array[img_counter].pagesType = memInfo.Type;
			mem_array[img_counter].unloaded = 0;
			img_counter++;
		}
	}
}

VOID CFMappingW(W::HANDLE hFile, W::LPSECURITY_ATTRIBUTES lpFileMappingAttributes,
	W::DWORD flProtect, W::DWORD dwMaximumSizeHigh, W::DWORD dwMaximumSizeLow, W::LPCWSTR lpName) {
	int todo = 1;
	W::MEMORY_BASIC_INFORMATION memInfo;
	//W::VirtualQuery((W::LPCVOID)lpMem, &memInfo, sizeof(memInfo));
	if (img_counter < 100) {
		//W::VirtualQuery((W::LPCVOID)hHeap, &memInfo, sizeof(memInfo));
		for (int i = 0; i < img_counter; i++) {
			if ((int)hFile - 1 <= mem_array[i].high && (int)hFile >= mem_array[i].low) {
				//TraceFile << "first if	\n";
				todo = 0;
				break;
			}
		}
		if (todo) {
			W::VirtualQuery((W::LPCVOID)hFile, &memInfo, sizeof(memInfo));
			int mem_reg = (int)memInfo.BaseAddress + memInfo.RegionSize;
			mem_array[img_counter].protection = memInfo.Protect;
			mem_array[img_counter].id = img_counter;
			mem_array[img_counter].high = mem_reg - 1;
			mem_array[img_counter].low = (int)memInfo.BaseAddress;
			mem_array[img_counter].name = "CFMappingW";
			mem_array[img_counter].protection = memInfo.Protect;
			mem_array[img_counter].pagesType = memInfo.Type;
			mem_array[img_counter].unloaded = 0;
			img_counter++;
		}
	}
	//TraceFile << "CFMappingW \n";
}

VOID CFMappingA(W::HANDLE hFile, W::LPSECURITY_ATTRIBUTES lpFileMappingAttributes,
	W::DWORD flProtect, W::DWORD dwMaximumSizeHigh, W::DWORD dwMaximumSizeLow, W::LPCSTR lpName) {
	//TraceFile << "HANDLE TO FILE: " << hFile << " \n";
	int todo = 1;
	W::MEMORY_BASIC_INFORMATION memInfo;
	//W::VirtualQuery((W::LPCVOID)lpMem, &memInfo, sizeof(memInfo));
	if (img_counter < 100) {
		//W::VirtualQuery((W::LPCVOID)hHeap, &memInfo, sizeof(memInfo));
		for (int i = 0; i < img_counter; i++) {
			if ((int)hFile - 1 <= mem_array[i].high && (int)hFile >= mem_array[i].low) {
				//TraceFile << "first if	\n";
				todo = 0;
				break;
			}
		}
		if (todo) {
			W::VirtualQuery((W::LPCVOID)hFile, &memInfo, sizeof(memInfo));
			int mem_reg = (int)memInfo.BaseAddress + memInfo.RegionSize;
			mem_array[img_counter].protection = memInfo.Protect;
			mem_array[img_counter].id = img_counter;
			mem_array[img_counter].high = mem_reg - 1;
			mem_array[img_counter].low = (int)memInfo.BaseAddress;
			mem_array[img_counter].name = "CFMappingA";
			mem_array[img_counter].protection = memInfo.Protect;
			mem_array[img_counter].pagesType = memInfo.Type;
			mem_array[img_counter].unloaded = 0;
			img_counter++;
		}
	}
	//TraceFile << "CFMappingA \n";
}

VOID CFMappingAAfter(W::HANDLE ret) {
	//TraceFile << "HANDLE TO FILE: " << ret << " \n";
}

VOID MemAlloc(IMG img, VOID *v) {
	fMap.insert(std::pair<std::string, int>("VirtualQuery", VirtualQuery_INDEX));
	fMap.insert(std::pair<std::string, int>("VirtualQueryEx", VirtualQueryEx_INDEX));
	fMap.insert(std::pair<std::string, int>("CoTaskMemAlloc", CoTaskMemAlloc_INDEX));
	fMap.insert(std::pair<std::string, int>("GlobalAlloc", GlobalAlloc_INDEX));
	fMap.insert(std::pair<std::string, int>("HeapAlloc", HeapAlloc_INDEX));
	fMap.insert(std::pair<std::string, int>("LocalAlloc", LocalAlloc_INDEX));
	fMap.insert(std::pair<std::string, int>("malloc", malloc_INDEX));
	fMap.insert(std::pair<std::string, int>("new", new_INDEX)); // wierd
	fMap.insert(std::pair<std::string, int>("VirtualAlloc", VirtualAlloc_INDEX));
	fMap.insert(std::pair<std::string, int>("HeapReAlloc", HeapReAlloc_INDEX));
	fMap.insert(std::pair<std::string, int>("realloc", realloc_INDEX));
	fMap.insert(std::pair<std::string, int>("HeapFree", HeapFree_INDEX));
	fMap.insert(std::pair<std::string, int>("CreateFileMappingW", CreateFileMappingW_INDEX));
	fMap.insert(std::pair<std::string, int>("CreateFileMappingA", CreateFileMappingA_INDEX));
	fMap.insert(std::pair<std::string, int>("CreateFileA", CreateFileA_INDEX));

	for (std::map<string, int>::iterator it = fMap.begin(),
		end = fMap.end(); it != end; ++it) {
		const char* func_name = it->first.c_str();
		RTN rtn = RTN_FindByName(img, func_name); // get pointer to the function
		if (rtn != RTN_Invalid()) {
			int index = it->second;
			switch (index) {
			case(VirtualQuery_INDEX):
				if (RTN_Valid(rtn)) {
					//TraceFile << func_name << " \n";
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
					//TraceFile << func_name << " \n";
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
					//TraceFile << func_name << " \n";
					RTN_Open(rtn);
					//function to retrive CoTaskMemAlloc  return value	
					RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)CTMAAfter,
						IARG_FUNCRET_EXITPOINT_VALUE, IARG_END);
					RTN_Close(rtn);
				}
				break;
			case(GlobalAlloc_INDEX):
				if (RTN_Valid(rtn)) {
					//TraceFile << func_name << " \n";
					RTN_Open(rtn);
					//function to retrive GlobalAlloc  return value	
					RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)GAfter,
						IARG_FUNCRET_EXITPOINT_VALUE, IARG_END);
					RTN_Close(rtn);
				}
				break;
			case(HeapAlloc_INDEX):
				if (RTN_Valid(rtn)) {
					//TraceFile << func_name << " \n";
					RTN_Open(rtn);
					//function to retrive HeapAlloc  return value	
					RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)HAAfter,
						IARG_FUNCRET_EXITPOINT_VALUE, IARG_END);
					RTN_Close(rtn);
				}
				break;
			case(LocalAlloc_INDEX):
				if (RTN_Valid(rtn)) {
					//TraceFile << func_name << " \n";
					RTN_Open(rtn);
					//function to retrive LocalAlloc  return value	
					RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)LAAfter,
						IARG_FUNCRET_EXITPOINT_VALUE, IARG_END);
					RTN_Close(rtn);
				}
				break;
			case(malloc_INDEX):
				if (RTN_Valid(rtn)) {
					//TraceFile << func_name << " \n";
					RTN_Open(rtn);
					//function to retrive malloc  return value	
					RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)MAAfter,
						IARG_FUNCRET_EXITPOINT_VALUE, IARG_PTR, rtn, IARG_END);
					RTN_Close(rtn);
				}
				break;
				//case(new_INDEX):
					//TraceFile << func_name << " \n";
					//do stuff
					//break;
			case(VirtualAlloc_INDEX):
				if (RTN_Valid(rtn)) {
					//TraceFile << func_name << " \n";
					RTN_Open(rtn);
					//function to retrive VirtualAlloc  return value	
					RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)VAAfter,
						IARG_FUNCRET_EXITPOINT_VALUE, IARG_END);
					RTN_Close(rtn);
				}
				break;
			case(HeapReAlloc_INDEX):
				if (RTN_Valid(rtn)) {
					//TraceFile << func_name << " \n";
					RTN_Open(rtn);
					//function to unload reallocated heaps
					RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)hReAllocB,
						IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
						IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
						IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
						IARG_FUNCARG_ENTRYPOINT_VALUE, 3,
						IARG_END);
					//function to store information about reallocated heaps
					RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)hReAllocA,
						IARG_FUNCRET_EXITPOINT_VALUE, IARG_END);
					RTN_Close(rtn);
				}
				break;
			case(realloc_INDEX):
				if (RTN_Valid(rtn)) {
					//TraceFile << func_name << " \n";
					RTN_Open(rtn);
					//function to unload reallocated heaps
					RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)hReAllocB,
						IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
						IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
						IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
						IARG_FUNCARG_ENTRYPOINT_VALUE, 3,
						IARG_END);
					//function to store information about reallocated heaps
					RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)hReAllocA,
						IARG_FUNCRET_EXITPOINT_VALUE, IARG_END);
					RTN_Close(rtn);
				}
				break;
			case(HeapFree_INDEX):
				if (RTN_Valid(rtn)) {
					//TraceFile << func_name << " \n";
					RTN_Open(rtn);
					//function to retrive VirtualAlloc  return value	
					RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)hFree,
						IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
						IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
						IARG_FUNCARG_ENTRYPOINT_VALUE, 2, IARG_END);
					RTN_Close(rtn);
				}
				break;
			case(CreateFileMappingW_INDEX):
				if (RTN_Valid(rtn)) {
					//TraceFile << func_name << " \n";
					RTN_Open(rtn);
					//function to retrive VirtualAlloc  return value	
					RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)CFMappingW,
						IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
						IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
						IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
						IARG_FUNCARG_ENTRYPOINT_VALUE, 3,
						IARG_FUNCARG_ENTRYPOINT_VALUE, 4,
						IARG_FUNCARG_ENTRYPOINT_VALUE, 5,
						IARG_END);
					RTN_Close(rtn);
				}
				break;
			case(CreateFileMappingA_INDEX):
				if (RTN_Valid(rtn)) {
					//TraceFile << func_name << " \n";
					RTN_Open(rtn);
					//function to retrive VirtualAlloc  return value	
					RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)CFMappingA,
						IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
						IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
						IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
						IARG_FUNCARG_ENTRYPOINT_VALUE, 3,
						IARG_FUNCARG_ENTRYPOINT_VALUE, 4,
						IARG_FUNCARG_ENTRYPOINT_VALUE, 5,
						IARG_END);
					RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)CFMappingAAfter,
						IARG_FUNCRET_EXITPOINT_VALUE, IARG_END);
					RTN_Close(rtn);
				}
				break;
			}
		}
	}
}
/********************************************************************/
/**************************Instrumentations**************************/
/********************************************************************/
VOID parse_funcsyms(IMG img, VOID *v) {
	if (!IMG_Valid(img)) return;
	if (IMG_IsMainExecutable(img)) return; // we only want to track Windows DLLs
	//insert in itre
	const char* imgName = IMG_Name(img).c_str();
	char* data = strdup(imgName);

	PIN_LockClient();
	int verify = (itree == NULL);
	if (itree == NULL) {
		itree = itree_init(IMG_LowAddress(img), IMG_HighAddress(img), (void*)data);
		bool isnull = (itree == NULL);
		if (isnull) { // if tree is still null
			printf("Fail to init tree at dll: %s \n", data);
		}
		else {
			printf("Good init  for Dll %s \n", data);
			printf("IMG_LowAddress, :%x, IMG_HighAddress: %x \n", IMG_LowAddress(img), IMG_HighAddress(img));

		}
	}
	else {
		bool success = itree_insert(itree, IMG_LowAddress(img), IMG_HighAddress(img), (void*)data);
		if (!success) {
			printf("Duplicate range insartion for Dll %s \n", data);
		}
		else {
			printf("Good range insartion for Dll %s \n", data);
			printf("IMG_LowAddress, :%x, IMG_HighAddress: %x \n", IMG_LowAddress(img), IMG_HighAddress(img));

		}
	}
	PIN_UnlockClient();
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
	img_counter++;
	cout << IMG_Name(img) << " is beeing loaded \n";
}

VOID ImageUnload(IMG img, VOID* v) {
	ADDRINT imgStart = IMG_LowAddress(img);
	ADDRINT imgEnd = IMG_HighAddress(img);
	cout << IMG_Name(img) << " \n";
	itreenode_t *node = itree_search(itree, imgStart);
	bool verify = (node != NULL);
	printf("is node to be unload found: %d \n", verify);
	
	if (verify) {
		cout << "IMG_Name: " << IMG_Name(img) << " \n";
		
		if (imgStart == node->start_addr && imgEnd == node->end_addr) {
			
			printf("Unloading DLL %s \n", node->data);
			itree = itree_delete(itree, imgStart, imgEnd);
		}
		else {
			printf("Abnormal unload: desired");
		}
	}
	int index = 0;
	for (int i = 0; i < img_counter; i++) {
		if (IMG_Id(img) - 1 == mem_array[i].id) {
			mem_array[i].unloaded = 1;
			index = i;
		}
	}
}

VOID exitFunc() {
	for (int i = 0; i < img_counter; i++) {
		cout << "img name: " << mem_array[i].name << " img ID: " << mem_array[i].id << " is: " << mem_array[i].unloaded << " \n";
		cout << " img high " << (void*) mem_array[i].high << " img low " << (void*)mem_array[i].low << "\n";
	}
}

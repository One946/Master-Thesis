#pragma once
#include "pin.H"

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

//functons headers

//Read Ops function
BOOL  validateRead(VOID * ip, VOID * addr);
VOID  missRead(VOID* ip, VOID * addr);
VOID RecordMemR(VOID * addr);
VOID ValidateMemory(INS ins, VOID *v);

//threads functions
VOID findStacks(CONTEXT *ctxt);
VOID OnThreadStart(THREADID tid, CONTEXT *ctxt, INT32, VOID *);

//VirtualQuery functions

VOID ArgVQEx(char *name, ADDRINT arg0, ADDRINT arg1, ADDRINT arg2, ADDRINT arg3);
VOID ArgVQ(char *name, ADDRINT arg0, ADDRINT arg1, ADDRINT arg2);
VOID VQAfter(ADDRINT ret, IMG img);
VOID VQExAfter(ADDRINT ret);

// Heap Functions
VOID CTMAAfter(ADDRINT ret);
VOID GAfter(ADDRINT ret, IMG img);
VOID HAAfter(ADDRINT ret);
VOID LAAfter(ADDRINT ret);
VOID MAAfter(ADDRINT ret);
VOID VAAfter(ADDRINT ret, IMG img);
VOID hFree(W::HANDLE hHeap, W::DWORD dwFlags, W::LPVOID lpMem);
VOID hReAllocB(ADDRINT hHeap, ADDRINT dwFlags, ADDRINT lpMem, ADDRINT dwBytes);
VOID hReAllocA(ADDRINT ret);
VOID CFMappingW(W::HANDLE hFile, W::LPSECURITY_ATTRIBUTES lpFileMappingAttributes,
				W::DWORD flProtect, W::DWORD dwMaximumSizeHigh, W::DWORD dwMaximumSizeLow, W::LPCWSTR lpName);
VOID CFMappingA(W::HANDLE hFile, W::LPSECURITY_ATTRIBUTES lpFileMappingAttributes,
				W::DWORD flProtect, W::DWORD dwMaximumSizeHigh, W::DWORD dwMaximumSizeLow, W::LPCSTR lpName);
VOID CFMappingAAfter(W::HANDLE ret);
VOID MemAlloc(IMG img, VOID *v);

//instrumentation functions
VOID parse_funcsyms(IMG img, VOID *v);
VOID ImageUnload(IMG img, VOID* v);
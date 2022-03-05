#pragma once
#include "pin.H"

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

//delta
typedef struct {
	ADDRINT StartAddress;
	ADDRINT EndAddress;
	int RegionID;
	W::SIZE_T Size;
}MemoryRange;

typedef struct {
	unsigned int syscallID;
	MemoryRange Array[1000]; //array of memory regions
	int regionsSum; // index for looping on array
}sysmap;

typedef struct {
	MemoryRange* Entry; //array of memory regions in entry
	MemoryRange* Exit; //array of memory regions in exity
	int entryRID; // ID of region in Entry
	int exitRID; // ID of region in Exit
	int regIndex; //index of the array at which the region has been found, in most of the cases is same of the ID
	int syscallIndex; //Index of the array of syscals at which differences has been found
	int syscallID; //Id of the syscall of interest

}differences;

/*Function headers */
VOID printRegions();
VOID changed();
VOID EnumSyscalls();
VOID HOOKS_NtProtectVirtualMemory_entry(CONTEXT *ctx, SYSCALL_STANDARD std);
VOID HOOKS_NtFreeVirtualMemory_entry(CONTEXT *ctx, SYSCALL_STANDARD std);
VOID HOOKS_NtCreateSection_entry(CONTEXT *ctx, SYSCALL_STANDARD std);
VOID HOOKS_NtAllocateVirtualMemory_entry(CONTEXT *ctx, SYSCALL_STANDARD std);
VOID HOOKS_NtMapViewOfSection_entry(CONTEXT *ctx, SYSCALL_STANDARD std);
VOID HOOKS_NtUnmapViewOfSection_entry(CONTEXT *ctx, SYSCALL_STANDARD std);
VOID OnThreadStart(THREADID tid, CONTEXT *ctxt, INT32, VOID *);
VOID HOOKS_SyscallEntry(THREADID thread_id, CONTEXT *ctx, SYSCALL_STANDARD std);
VOID HOOKS_SyscallExit(THREADID thread_id, CONTEXT *ctx, SYSCALL_STANDARD std);
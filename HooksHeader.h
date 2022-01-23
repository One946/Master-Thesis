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

/*Function headers */
VOID EnumSyscalls();
VOID HOOKS_NtProtectVirtualMemory_exit(CONTEXT *ctx, SYSCALL_STANDARD std);
VOID HOOKS_NtFreeVirtualMemory_exit(CONTEXT *ctx, SYSCALL_STANDARD std);
VOID HOOKS_NtCreateSection_exit(CONTEXT *ctx, SYSCALL_STANDARD std);
VOID HOOKS_NtAllocateVirtualMemory_exit(CONTEXT *ctx, SYSCALL_STANDARD std);
VOID HOOKS_NtMapViewOfSection_exit(CONTEXT *ctx, SYSCALL_STANDARD std);
VOID HOOKS_NtUnmapViewOfSection_exit(CONTEXT *ctx, SYSCALL_STANDARD std);
VOID OnThreadStart(THREADID tid, CONTEXT *ctxt, INT32, VOID *);
VOID HOOKS_SyscallEntry(THREADID thread_id, CONTEXT *ctx, SYSCALL_STANDARD std);
VOID HOOKS_SyscallExit(THREADID thread_id, CONTEXT *ctx, SYSCALL_STANDARD std);
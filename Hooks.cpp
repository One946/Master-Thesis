#include "pin.H"
#include "HooksHeader.h"
#include "MemoryHeader.h"
#include "itree.h"

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
extern mem_regions mem_array[100]; //array in which  informations about the images are stored
extern int counter; //counter for instructions
extern mem_map op_map;
extern TLS_KEY tls_key;
extern itreenode_t* itree;
#define MAXSYSCALLS	0x200
CHAR* syscallIDs[MAXSYSCALLS];

differences regUpdates; // structure to store memory changes, namely if a memory region is created or deleted
ADDRINT arg1, arg2, arg3;
ADDRINT *AVMarg, *FVMarg, *PVMarg, *MVSarg, *UVSarg; //variables to save value of arguments of AllocateVirtualMemory, FreeVirtualMemory, PrtectVirtualMemory, MapViewOfSection, UnMapViewOfSection
/********************************************************************/
/**************************Instrumentations**************************/
/********************************************************************/

VOID fillArg(CONTEXT *ctx, SYSCALL_STANDARD std, ADDRINT syscall_number) {

	switch (syscall_number) {
	case(0x00d7)://NtProtectVirtualMemory
		PVMarg = (ADDRINT *)PIN_GetSyscallArgument(ctx, std, 1);
		arg1 = (ADDRINT)*PVMarg;
		break;
	case(0x0013)://NtAllocateVirtualMemory
		AVMarg = (ADDRINT *)PIN_GetSyscallArgument(ctx, std, 1);
		arg1 = (ADDRINT)*AVMarg;
		//printf("AVMarg:%x, *AVMarg:%x, arg1:%x \n", AVMarg, *AVMarg, arg1);
		break;
		/*case(0x0032)://ntclose
			arg1 = (ADDRINT *)PIN_GetSyscallArgument(ctx, std, 0);
		case(0x0040):// ntcreateevent
			arg1 = PIN_GetSyscallArgument(ctx, std, 0);
		case(0x004a): // ntcreatemutant
			arg1 = PIN_GetSyscallArgument(ctx, std, 0);*/
			//case(0x0054):// ntcreatesection
			//	arg1 = PIN_GetSyscallArgument(ctx, std, 0);
	case(0x0083)://ntfreevirtualmemory
		FVMarg = (ADDRINT *)PIN_GetSyscallArgument(ctx, std, 1);
		arg1 = (ADDRINT)*FVMarg;

		printf("FVMarg:%x, *FVMarg:%x, arg1:%x \n", FVMarg, *FVMarg, arg1);
		break;
	case(0x00a8):// ntmapviewofsection
		MVSarg = (ADDRINT *)PIN_GetSyscallArgument(ctx, std, 2); // also 5 6
		arg1 = (ADDRINT)*MVSarg;
		//	arg2 = PIN_GetSyscallArgument(ctx, std, 5); // also 5 6
		//	arg3 = PIN_GetSyscallArgument(ctx, std, 6); // also 5 6
		printf("MVSarg:%x, *MVSarg:%x, arg1:%x \n", MVSarg, *MVSarg, arg1);
		break;
	case(0x0181)://NtUnmapViewOfSection
		UVSarg = (ADDRINT *)PIN_GetSyscallArgument(ctx, std, 2); // also 5 6
		arg1 = (ADDRINT)*UVSarg;
		//	arg2 = PIN_GetSyscallArgument(ctx, std, 5); // also 5 6
		//	arg3 = PIN_GetSyscallArgument(ctx, std, 6); // also 5 6
		printf("UVSarg:%x, *UVSarg:%x, arg1:%x \n", UVSarg, *UVSarg, arg1);

		break;
		/*case(0x00b3):// ntopenfile
			arg1 = PIN_GetSyscallArgument(ctx, std, 0);
		case(0x00b6):// ntopenkey
			arg1 = PIN_GetSyscallArgument(ctx, std, 0);
		case(0x00b7):// ntopenkeyEx
			arg1 = PIN_GetSyscallArgument(ctx, std, 0);
		case(0x00bf): // ntopenprocesstoken
			arg1 = PIN_GetSyscallArgument(ctx, std, 2);
		case(0x00c0): // ntopenprocesstokenex
			arg1 = PIN_GetSyscallArgument(ctx, std, 3);
		case(0x00c2): // ntopensection
			arg1 = PIN_GetSyscallArgument(ctx, std, 0);
		case(0x00d9): // ntqueryattributesfile
			arg1 = PIN_GetSyscallArgument(ctx, std, 1);
		case(0x00ea): // ntqueryinformationprocess
			arg1 = PIN_GetSyscallArgument(ctx, std, 2);
		case(0x00ed): // ntqueryinformationtoken
			arg1 = PIN_GetSyscallArgument(ctx, std, 2);
		case(0x00fb): // ntqueryperformancecounter
			arg1 = PIN_GetSyscallArgument(ctx, std, 0);
		case(0x00fe): // ntquerysection
			arg1 = PIN_GetSyscallArgument(ctx, std, 2);
		case(0x0105): // ntquerysysteminformation
			arg1 = PIN_GetSyscallArgument(ctx, std, 1);
		case(0x010a): // ntqueryvaluekey
			arg1 = PIN_GetSyscallArgument(ctx, std, 3);
		case(0x010c): // ntqueryvolumeinformationfile
			arg1 = PIN_GetSyscallArgument(ctx, std, 2);
		case(0x012b): // ntrequestwaitreplyport
			arg1 = PIN_GetSyscallArgument(ctx, std, 2);
		case(0x0177): // nttracecontrol
			arg1 = PIN_GetSyscallArgument(ctx, std, 3);*/
	default:
		break;
	}
}

// Helper method to print  information about the differences in memory regions before and after a syscall
VOID printRegions() {
	/*
	if (regUpdates.newRegions) {
		printf("new regions spotted! \n");
		printf("++++++++++++++++++++++++++++++++++++++++\n");
		printf("Syscall number:%x \n", memArrayEntry.syscalNumb);
		for (int j = 0; j < regUpdates.newRegions; j++) {
			printf("New Regions! \n");
			printf("regUpdates[i].Added[j].RegionID:%d , regUpdates[i].Added[j].Size:%d \n", regUpdates.Added[j].RegionID, regUpdates.Added[j].Size);
			printf("regUpdates[i].Added[j].StartAddress:%x, regUpdates[i].Added[j].EndAddress:%x \n", regUpdates.Added[j].StartAddress, regUpdates.Added[j].EndAddress);
			if (arg1 <= regUpdates.Added[j].EndAddress && arg1 >= regUpdates.Added[j].StartAddress) {
				printf(" %%%%%%%%% Ret addres: %x, StartAddress: %x , EndAddress: %x \n", arg1, regUpdates.Added[j].StartAddress, regUpdates.Added[j].EndAddress);
			}
		}
	}
	if (regUpdates.deletedRegions) {
		printf("deleted regions spotted! \n");
		printf("++++++++++++++++++++++++++++++++++++++++\n");
		printf("Syscall number:%x \n", memArrayEntry.syscalNumb);
		for (int j = 0; j < regUpdates.deletedRegions; j++) {
			printf("Deleted Regions! \n");
			printf("regUpdates[i].Deleted[j].RegionID:%d , regUpdates[i].Deleted[j].Size:%d \n", regUpdates.Deleted[j].RegionID, regUpdates.Deleted[j].Size);
			printf("regUpdates[i].Deleted[j].StartAddress:%x, regUpdates[i].Deleted[j].EndAddress:%x \n", regUpdates.Deleted[j].StartAddress, regUpdates.Deleted[j].EndAddress);
			if (arg1 <= regUpdates.Deleted[j].EndAddress && arg1 >= regUpdates.Deleted[j].StartAddress) {
				printf(" %%%%%%%%% Ret addres: %x, StartAddress: %x , EndAddress: %x \n", arg1, regUpdates.Deleted[j].StartAddress, regUpdates.Deleted[j].EndAddress);
			}
		}
	}
	if (regUpdates.resizedRegions) {
		printf("resized regions spotted! \n");
		printf("++++++++++++++++++++++++++++++++++++++++\n");
		printf("Syscall number:%x \n", memArrayEntry.syscalNumb);
		for (int j = 0; j < regUpdates.resizedRegions; j++) {
			printf("Resized Regions! \n");
			printf("regUpdates[i].Resized[j].RegionID:%d , regUpdates[i].Resized[j].Size:%d \n", regUpdates.Resized[j].RegionID, regUpdates.Resized[j].Size);
			printf("regUpdates[i].Resized[j].StartAddress:%x, regUpdates[i].Resized[j].EndAddress:%x \n", regUpdates.Resized[j].StartAddress, regUpdates.Resized[j].EndAddress);
			if (arg1 <= regUpdates.Resized[j].EndAddress && arg1 >= regUpdates.Resized[j].StartAddress) {
				printf(" %%%%%%%%% Ret addres: %x, StartAddress: %x , EndAddress: %x \n", arg1, regUpdates.Resized[j].StartAddress, regUpdates.Resized[j].EndAddress);
			}
		}
	}
*/
}

// Method to spot differences between memory regions before and after a syscall
VOID changed(pintool_tls* tdata) {
	bool gt = 0; // variable to check if regions is greater in exit
	bool lt = 0; // variable to check if regions is lesser in exit
	bool eq = 0; // variable to check if regions is equal in exit
	ADDRINT delta1 = 0;
	ADDRINT delta2 = 0;
	bool found;
	int newIndex;  // index to count the different region and identify them
	int deletedIndex;
	int resizedIndex;
	fflush(stdout);

	gt = tdata->memArrayEntry.regionsSum < tdata->memArrayExit.regionsSum;
	lt = tdata->memArrayEntry.regionsSum > tdata->memArrayExit.regionsSum;
	eq = tdata->memArrayEntry.regionsSum == tdata->memArrayExit.regionsSum;
	resizedIndex = 0;
	if (gt) { //more region in exit than in entry
		printf("more region in exit than in entry \n");
		printf("tdata->memArrayEntry.regionsSum: %d \n", tdata->memArrayEntry.regionsSum);
		printf("tdata->memArrayExit.regionsSum: %d \n", tdata->memArrayExit.regionsSum);
		newIndex = 0;
		for (int j = 0; j <= tdata->memArrayExit.regionsSum; j++) {
			found = 0;
			for (int k = 0; k <= tdata->memArrayEntry.regionsSum; k++) { // cycle on the memory map untill the end

				if (tdata->memArrayExit.Array[j].StartAddress == tdata->memArrayEntry.Array[k].StartAddress) {
					if (tdata->memArrayExit.Array[j].EndAddress != tdata->memArrayEntry.Array[k].EndAddress) {
						regUpdates.Resized[resizedIndex].StartAddress = tdata->memArrayExit.Array[j].StartAddress;
						regUpdates.Resized[resizedIndex].OldEndAddress = tdata->memArrayEntry.Array[k].EndAddress;
						regUpdates.Resized[resizedIndex].EndAddress = tdata->memArrayExit.Array[k].EndAddress;
						regUpdates.Resized[resizedIndex].Size = tdata->memArrayExit.Array[k].Size;
						regUpdates.Resized[resizedIndex].RegionID = tdata->memArrayExit.Array[k].RegionID;

						printf("regUpdates.Resized[resizedIndex].StartAddress: %x \n", regUpdates.Resized[resizedIndex].StartAddress);
						printf("regUpdates.Resized[resizedIndex].EndAddress: %x \n", regUpdates.Resized[resizedIndex].EndAddress);
						printf("regUpdates.Resized[resizedIndex].OldEndAddress: %x \n", regUpdates.Resized[resizedIndex].OldEndAddress);
						printf("regUpdates.Resized[resizedIndex].RegionID: %d \n", regUpdates.Resized[resizedIndex].RegionID);
						printf("regUpdates.Resized[resizedIndex].Size: %d \n\n", regUpdates.Resized[resizedIndex].Size);
						resizedIndex++;
						found = 1;

						if (tdata->sc.syscall_number == 0x00d7 || tdata->sc.syscall_number == 0x0013 || tdata->sc.syscall_number == 0x0083 || tdata->sc.syscall_number == 0x00a8 || tdata->sc.syscall_number == 0x0181) {
							if (arg1 <= tdata->memArrayExit.Array[j].EndAddress && arg1 >= tdata->memArrayExit.Array[j].StartAddress) {
								printf("arg1: %x, StartAddress: %x , EndAddress: %x \n", arg1, tdata->memArrayExit.Array[j].StartAddress, tdata->memArrayExit.Array[j].EndAddress);
							}// add other ifs for following arguments
						}
					}
					if (tdata->memArrayExit.Array[j].EndAddress == tdata->memArrayEntry.Array[k].EndAddress) {
						found = 1; // if i spot a known region, i break and keep looping on the exit array
						break;
					}
				}
			}
			if (!found) { // if i spot a new region i add it to the regionUpdates array;
				printf("j:%d \n", j);
				regUpdates.Added[newIndex].EndAddress = tdata->memArrayExit.Array[j].EndAddress;
				regUpdates.Added[newIndex].StartAddress = tdata->memArrayExit.Array[j].StartAddress;
				regUpdates.Added[newIndex].RegionID = tdata->memArrayExit.Array[j].RegionID;
				regUpdates.Added[newIndex].Size = tdata->memArrayExit.Array[j].Size;

				printf("\nregUpdates.Added[newIndex].StartAddress: %x \n", regUpdates.Added[newIndex].StartAddress);
				printf("regUpdates.Added[newIndex].EndAddress: %x \n", regUpdates.Added[newIndex].EndAddress);
				printf("regUpdates.Added[newIndex].RegionID: %d \n", regUpdates.Added[newIndex].RegionID);
				printf("regUpdates.Added[newIndex].Size: %d \n\n", regUpdates.Added[newIndex].Size);

				newIndex++;

				if (tdata->sc.syscall_number == 0x00d7 || tdata->sc.syscall_number == 0x0013 || tdata->sc.syscall_number == 0x0083 || tdata->sc.syscall_number == 0x00a8 || tdata->sc.syscall_number == 0x0181) {
					if (arg1 <= tdata->memArrayExit.Array[j].EndAddress && arg1 >= tdata->memArrayExit.Array[j].StartAddress) {
						printf("arg1: %x, StartAddress: %x , EndAddress: %x \n", arg1, tdata->memArrayExit.Array[j].StartAddress, tdata->memArrayExit.Array[j].EndAddress);
					}// add other ifs for following arguments
				}
				/*
				if (tdata->memArrayEntry.syscalNumb == 0x00a8) {
					if (arg2 <= tdata->memArrayExit.Array[j].EndAddress && arg2 >= tdata->memArrayExit.Array[j].StartAddress) {
						printf("Ret addres: %x, StartAddress: %x , EndAddress: %x \n", arg2, tdata->memArrayExit.Array[j].StartAddress, tdata->memArrayExit.Array[j].EndAddress);
					}
					if (arg3 <= tdata->memArrayExit.Array[j].EndAddress && arg3 >= tdata->memArrayExit.Array[j].StartAddress) {
						printf("Ret addres: %x, StartAddress: %x , EndAddress: %x \n", arg3, tdata->memArrayExit.Array[j].StartAddress, tdata->memArrayExit.Array[j].EndAddress);
					}
				}*/
			}
		}
		regUpdates.newRegions = newIndex;
	}
	if (lt) {		//Less region in exit than in entry
		printf("Less region in exit than in entry \n");
		printf("tdata->memArrayEntry.regionsSum: %d \n", tdata->memArrayEntry.regionsSum);
		printf("tdata->memArrayExit.regionsSum: %d \n", tdata->memArrayExit.regionsSum);
		deletedIndex = 0;
		for (int j = 0; j <= tdata->memArrayEntry.regionsSum; j++) {
			found = 0;
			for (int k = 0; k <= tdata->memArrayExit.regionsSum; k++) {// cycle on the memory map untill the end
				if (tdata->memArrayEntry.Array[j].StartAddress == tdata->memArrayExit.Array[k].StartAddress) {
					if (tdata->memArrayEntry.Array[j].EndAddress != tdata->memArrayExit.Array[k].EndAddress) {
						regUpdates.Resized[resizedIndex].StartAddress = tdata->memArrayExit.Array[j].StartAddress;
						regUpdates.Resized[resizedIndex].OldEndAddress = tdata->memArrayEntry.Array[k].EndAddress;
						regUpdates.Resized[resizedIndex].EndAddress = tdata->memArrayExit.Array[k].EndAddress;
						regUpdates.Resized[resizedIndex].Size = tdata->memArrayExit.Array[k].Size;
						regUpdates.Resized[resizedIndex].RegionID = tdata->memArrayExit.Array[k].RegionID;

						printf("\nregUpdates.Resized[resizedIndex].StartAddress: %x \n", regUpdates.Resized[resizedIndex].StartAddress);
						printf("regUpdates.Resized[resizedIndex].EndAddress: %x \n", regUpdates.Resized[resizedIndex].EndAddress);
						printf("regUpdates.Resized[resizedIndex].OldEndAddress: %x \n", regUpdates.Resized[resizedIndex].OldEndAddress);
						printf("regUpdates.Resized[resizedIndex].RegionID: %d \n", regUpdates.Resized[resizedIndex].RegionID);
						printf("regUpdates.Resized[resizedIndex].Size: %d \n\n", regUpdates.Resized[resizedIndex].Size);
						found = 1;
						resizedIndex++;
						if (tdata->sc.syscall_number == 0x00d7 || tdata->sc.syscall_number == 0x0013 || tdata->sc.syscall_number == 0x0083 || tdata->sc.syscall_number == 0x00a8 || tdata->sc.syscall_number == 0x0181) {
							if (arg1 <= tdata->memArrayExit.Array[j].EndAddress && arg1 >= tdata->memArrayExit.Array[j].StartAddress) {
								printf("arg1: %x, StartAddress: %x , EndAddress: %x \n", arg1, tdata->memArrayExit.Array[j].StartAddress, tdata->memArrayExit.Array[j].EndAddress);
							}// add other ifs for following arguments
						}
					}
					if (tdata->memArrayEntry.Array[j].EndAddress == tdata->memArrayExit.Array[k].EndAddress) {
						found = 1; // if i spot a known region, i break and keep looping on the entry array
						break;
					}
				}
			}
			if (!found) { //if a regions has been removed i put it in the memory update array
				regUpdates.Deleted[deletedIndex].EndAddress = tdata->memArrayExit.Array[j].EndAddress;
				regUpdates.Deleted[deletedIndex].StartAddress = tdata->memArrayExit.Array[j].StartAddress;
				regUpdates.Deleted[deletedIndex].RegionID = tdata->memArrayExit.Array[j].RegionID;
				regUpdates.Deleted[deletedIndex].Size = tdata->memArrayExit.Array[j].Size;
				printf("\nregUpdates.Deleted[deletedIndex].StartAddress: %x \n", regUpdates.Deleted[deletedIndex].StartAddress);
				printf("regUpdates.Deleted[deletedIndex].EndAddress: %x \n", regUpdates.Deleted[deletedIndex].EndAddress);
				printf("regUpdates.Deleted[deletedIndex].RegionID : %d \n", regUpdates.Deleted[deletedIndex].RegionID);
				printf("regUpdates.Deleted[deletedIndex].Size: %d \n\n", regUpdates.Deleted[deletedIndex].Size);
				deletedIndex++;
				if (tdata->sc.syscall_number == 0x00d7 || tdata->sc.syscall_number == 0x0013 || tdata->sc.syscall_number == 0x00a8) {
					if (arg1 <= tdata->memArrayExit.Array[j].EndAddress && arg1 >= tdata->memArrayExit.Array[j].StartAddress) {
						printf("arg1: %x, StartAddress: %x , EndAddress: %x \n", arg1, tdata->memArrayExit.Array[j].StartAddress, tdata->memArrayExit.Array[j].EndAddress);
					}// add other ifs for following arguments
				}
				if (tdata->sc.syscall_number == 0x0083 || tdata->sc.syscall_number == 0x0181) {
					if (arg1 <= tdata->memArrayEntry.Array[j].EndAddress && arg1 >= tdata->memArrayEntry.Array[j].StartAddress) {
						printf("arg1: %x, StartAddress: %x , EndAddress: %x \n", arg1, tdata->memArrayEntry.Array[j].StartAddress, tdata->memArrayEntry.Array[j].EndAddress);
					}// add other ifs for following arguments
					if (arg1 <= tdata->memArrayExit.Array[j].EndAddress && arg1 >= tdata->memArrayExit.Array[j].StartAddress) {
						printf("arg1: %x, StartAddress: %x , EndAddress: %x \n", arg1, tdata->memArrayExit.Array[j].StartAddress, tdata->memArrayExit.Array[j].EndAddress);
					}// add other ifs for following arguments
				}
			}
		}
		regUpdates.deletedRegions = deletedIndex;
	}

	if (eq) {
		printf("same numb of regions \n");
		for (int j = 0; j < tdata->memArrayEntry.regionsSum; j++) {
			found = 0;
			for (int k = 0; k <= tdata->memArrayExit.regionsSum; k++) {
				if (tdata->memArrayEntry.Array[j].StartAddress == tdata->memArrayExit.Array[k].StartAddress) {
					if (tdata->memArrayEntry.Array[j].EndAddress != tdata->memArrayExit.Array[k].EndAddress) {
						regUpdates.Resized[resizedIndex].StartAddress = tdata->memArrayExit.Array[j].StartAddress;
						regUpdates.Resized[resizedIndex].OldEndAddress = tdata->memArrayEntry.Array[k].EndAddress;
						regUpdates.Resized[resizedIndex].EndAddress = tdata->memArrayExit.Array[k].EndAddress;
						regUpdates.Resized[resizedIndex].Size = tdata->memArrayExit.Array[k].Size;
						regUpdates.Resized[resizedIndex].RegionID = tdata->memArrayExit.Array[k].RegionID;


						printf("\nregUpdates.Resized[resizedIndex].StartAddress: %x \n", regUpdates.Resized[resizedIndex].StartAddress);
						printf("regUpdates.Resized[resizedIndex].EndAddress: %x \n", regUpdates.Resized[resizedIndex].EndAddress);
						printf("regUpdates.Resized[resizedIndex].OldEndAddress: %x \n", regUpdates.Resized[resizedIndex].OldEndAddress);
						printf("regUpdates.Resized[resizedIndex].RegionID: %d \n", regUpdates.Resized[resizedIndex].RegionID);
						printf("regUpdates.Resized[resizedIndex].Size: %d \n\n", regUpdates.Resized[resizedIndex].Size);
						found = 1;
						resizedIndex++;
						if (tdata->sc.syscall_number == 0x00d7 || tdata->sc.syscall_number == 0x0013 || tdata->sc.syscall_number == 0x00a8) {
							if (arg1 <= tdata->memArrayExit.Array[j].EndAddress && arg1 >= tdata->memArrayExit.Array[j].StartAddress) {
								printf("arg1: %x, StartAddress: %x , EndAddress: %x \n", arg1, tdata->memArrayExit.Array[j].StartAddress, tdata->memArrayExit.Array[j].EndAddress);
							}// add other ifs for following arguments
						}
						if (tdata->sc.syscall_number == 0x0083 || tdata->sc.syscall_number == 0x0181) {
							if (arg1 <= tdata->memArrayEntry.Array[j].EndAddress && arg1 >= tdata->memArrayEntry.Array[j].StartAddress) {
								printf("ENTRY arg1: %x, StartAddress: %x , EndAddress: %x \n", arg1, tdata->memArrayEntry.Array[j].StartAddress, tdata->memArrayEntry.Array[j].EndAddress);
							}// add other ifs for following arguments
							if (arg1 <= tdata->memArrayExit.Array[j].EndAddress && arg1 >= tdata->memArrayExit.Array[j].StartAddress) {
								printf("EXIT arg1: %x, StartAddress: %x , EndAddress: %x \n", arg1, tdata->memArrayExit.Array[j].StartAddress, tdata->memArrayExit.Array[j].EndAddress);
							}// add other ifs for following arguments
						}
					}
					if (tdata->memArrayEntry.Array[j].EndAddress == tdata->memArrayExit.Array[k].EndAddress) {
						found = 1; // if i spot a known region, i break and keep looping on the entry array
						if (tdata->sc.syscall_number == 0x00d7 || tdata->sc.syscall_number == 0x0013 || tdata->sc.syscall_number == 0x00a8) {
							if (arg1 <= tdata->memArrayExit.Array[j].EndAddress && arg1 >= tdata->memArrayExit.Array[j].StartAddress) {
								printf("arg1: %x, StartAddress: %x , EndAddress: %x \n", arg1, tdata->memArrayExit.Array[j].StartAddress, tdata->memArrayExit.Array[j].EndAddress);
							}// add other ifs for following arguments
						}
						if (tdata->sc.syscall_number == 0x0083 || tdata->sc.syscall_number == 0x0181) {
							if (arg1 <= tdata->memArrayEntry.Array[j].EndAddress && arg1 >= tdata->memArrayEntry.Array[j].StartAddress) {
								printf("j:%d \n",j);
								printf("ENTRY arg1: %x, StartAddress: %x , EndAddress: %x \n", arg1, tdata->memArrayEntry.Array[j].StartAddress, tdata->memArrayEntry.Array[j].EndAddress);
							}// add other ifs for following arguments
							if (arg1 <= tdata->memArrayExit.Array[j].EndAddress && arg1 >= tdata->memArrayExit.Array[j].StartAddress) {
								printf("EXIT arg1: %x, StartAddress: %x , EndAddress: %x \n", arg1, tdata->memArrayExit.Array[j].StartAddress, tdata->memArrayExit.Array[j].EndAddress);
							}// add other ifs for following arguments
						}
						break;
					}
				}
			}
		}
	}
	regUpdates.resizedRegions = resizedIndex;
}

// function to enumerate memory regions before a syscall is executed
VOID funcEntry(pintool_tls* tdata) {
	W::MEMORY_BASIC_INFORMATION mbi;
	W::SIZE_T numBytes;
	W::DWORD MyAddress = 0;
	//sok variables
	W::PVOID maxAddr = 0;
	ADDRINT end = 0x7ffe0000; // address to query to -> 0x7ffe0000->KUSERDATA or 0x7fff0000->BLACK MAGIC
	int regions = 0;
	ADDRINT regionend = 0;
	W::SIZE_T size = 0;

	//cycle on the whole memroy, untill the end address
	while (numBytes = W::VirtualQuery((W::LPCVOID)MyAddress, &mbi, sizeof(mbi))) {
		if ((maxAddr && maxAddr >= mbi.BaseAddress) || end <= (ADDRINT)mbi.BaseAddress) break;
		maxAddr = mbi.BaseAddress;
		if (mbi.State != MEM_FREE) {
			// if memory is used store information about that memory in an array
			regionend = (ADDRINT)mbi.BaseAddress + mbi.RegionSize - 1;
			tdata->memArrayEntry.Array[regions].EndAddress = regionend;
			tdata->memArrayEntry.Array[regions].StartAddress = (ADDRINT)mbi.BaseAddress;
			tdata->memArrayEntry.Array[regions].RegionID = regions;
			tdata->memArrayEntry.Array[regions].Size = mbi.RegionSize;
			tdata->memArrayEntry.Array[regions].AllProtect = mbi.AllocationProtect;
			regions++;
		}
		size += mbi.RegionSize;
		MyAddress += mbi.RegionSize;
	}
	tdata->memArrayEntry.regionsSum = regions - 1;
}

// function to enumerate memory regions after a syscall is executed
VOID funcExit(pintool_tls* tdata) {
	W::MEMORY_BASIC_INFORMATION mbi;
	W::SIZE_T numBytes;
	W::DWORD MyAddress = 0;
	//sok variables
	W::PVOID maxAddr = 0;
	ADDRINT end = 0x7ffe0000; // address to query to -> 0x7ffe0000->KUSERDATA or 0x7fff0000->BLACK MAGIC
	int regions = 0;
	ADDRINT regionend = 0;
	W::SIZE_T size = 0;

	//cycle on the whole memroy, untill the end address
	while (numBytes = W::VirtualQuery((W::LPCVOID)MyAddress, &mbi, sizeof(mbi))) {
		if ((maxAddr && maxAddr >= mbi.BaseAddress) || end <= (ADDRINT)mbi.BaseAddress) break;
		maxAddr = mbi.BaseAddress;
		if (mbi.State != MEM_FREE) {
			// if memory is used store information about that memory in an array
			regionend = (ADDRINT)mbi.BaseAddress + mbi.RegionSize - 1;
			tdata->memArrayExit.Array[regions].EndAddress = regionend;
			tdata->memArrayExit.Array[regions].StartAddress = (ADDRINT)mbi.BaseAddress;
			tdata->memArrayExit.Array[regions].RegionID = regions;
			tdata->memArrayExit.Array[regions].Size = mbi.RegionSize;
			tdata->memArrayExit.Array[regions].AllProtect = mbi.AllocationProtect;
			regions++;
		}
		size += mbi.RegionSize;
		MyAddress += mbi.RegionSize;
	}
	tdata->memArrayExit.regionsSum = regions - 1;
}

VOID addKuserData(pintool_tls* tdata) {
	printf("add kuserdata \n");
	W::MEMORY_BASIC_INFORMATION mbi;
	W::SIZE_T numBytes;
	W::DWORD MyAddress = 0x7ffe0000;
	int regions = 0;
	ADDRINT regionend = 0;
	W::SIZE_T size = 0;

	//cycle on the whole memroy, untill the end address
	numBytes = W::VirtualQuery((W::LPCVOID)MyAddress, &mbi, sizeof(mbi));
		if (numBytes) {
			printf("mbi.BaseAddress: 0x%x, regionend: 0x%x, \n",(ADDRINT)mbi.BaseAddress, regionend);
			// if memory is used store information about that memory in an array
			regionend = (ADDRINT)mbi.BaseAddress + mbi.RegionSize - 1;
			tdata->memArrayExit.Array[regions].EndAddress = regionend;
			tdata->memArrayExit.Array[regions].StartAddress = (ADDRINT)mbi.BaseAddress;
			tdata->memArrayExit.Array[regions].RegionID = regions;
			tdata->memArrayExit.Array[regions].Size = mbi.RegionSize;
			tdata->memArrayExit.Array[regions].AllProtect = mbi.AllocationProtect;
		}
		size += mbi.RegionSize;
		MyAddress += mbi.RegionSize;
	tdata->memArrayExit.regionsSum = regions - 1;
}

//enumerate syscalls' ordinals
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
VOID HOOKS_NtProtectVirtualMemory_entry(CONTEXT *ctx, SYSCALL_STANDARD std) {
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
VOID HOOKS_NtAllocateVirtualMemory_entry(CONTEXT *ctx, SYSCALL_STANDARD std) {
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
		mem_array[img_counter].high = baseAddress + (int)RegSize - 1;
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
	pintool_tls* tdata;
	tdata = (pintool_tls*)PIN_GetThreadData(tls_key, thread_id);
	tdata->sc.syscall_number = PIN_GetSyscallNumber(ctx, std);
	//retrive stack pointer
	ADDRINT *ESP = (ADDRINT*)PIN_GetContextReg(ctx, REG_STACK_PTR);
	//search stack pointer in interval tree ranges
	ADDRINT ra = *((ADDRINT*)ESP + 1);
	itreenode_t* node = itree_search(itree, ra);
	int isNodeNull = (node == NULL);
	
	fillArg(ctx, std, tdata->sc.syscall_number);

	if (isNodeNull) {
		printf("ENTRY address NOT found in tree \n");
		if (tdata->sc.syscall_number > 0x200) {
			printf("****************Syscall number: %x ****************\n", tdata->sc.syscall_number);
			if (tdata->sc.syscall_number == 0x10e6) {
				return;
			}
			tdata->memArrayEntry.syscalNumb = tdata->sc.syscall_number;
			//fillArg(ctx, std, tdata->sc.syscall_number);
			funcEntry(tdata);
			tdata->memArrayEntry.syscallID = tdata->counter1;
			tdata->counter1++;
		}
		if (tdata->sc.syscall_number < 0x200) {
			printf("****************Syscall name: %s ****************\n", syscallIDs[tdata->sc.syscall_number]);
			tdata->memArrayEntry.syscalNumb = tdata->sc.syscall_number;
			//fillArg(ctx, std, tdata->sc.syscall_number);
			funcEntry(tdata);
			tdata->memArrayEntry.syscallID = tdata->counter1;
			tdata->counter1++;
		}
	}
	else {
		printf("------------------------------- \n");
		if (tdata->sc.syscall_number < 0x200) {
			printf("****************Syscall name: %s ****************\n", syscallIDs[tdata->sc.syscall_number]);
		}
		printf("address found in node \n");
		printf("Syscall originated in %s  ESP=0x%x RA==0x%x \n", node->data, *ESP, ra);
		printf("node min: 0x%x node max: 0x%x left:%d right:%d \n", node->start_addr, node->end_addr, node->left, node->right);
		tdata->counter1++;
		return;
	}

}

VOID HOOKS_SyscallExit(THREADID thread_id, CONTEXT *ctx, SYSCALL_STANDARD std) {
	//retrive thread data
	pintool_tls* tdata;
	tdata = (pintool_tls*)PIN_GetThreadData(tls_key, thread_id);	
	//retrive stack pointer
	ADDRINT *RIP = (ADDRINT*)PIN_GetContextReg(ctx, REG_INST_PTR);
	//retrive stack pointer
	ADDRINT *ESP = (ADDRINT*)PIN_GetContextReg(ctx, REG_STACK_PTR);
	//search stack pointer in interval tree ranges
	ADDRINT ra = *((ADDRINT*)ESP + 1);
	//search stack pointer in interval tree ranges
	itreenode_t* node = itree_search(itree, *ESP);

	printf("arg1: 0x%x, arg2: 0x%x, arg3: 0x%x \n", arg1, arg2, arg3);

	int isNodeNull = (node == NULL); 
	if (isNodeNull) {//if the stackpointer is found
		if (tdata->sc.syscall_number == 0x003c) { //check if it is ntcontinue
			printf("ntcontinue \n");
			int check;
			itreenode_t* node2 = itree_search(itree, *RIP);
			check = (node2 == NULL);
			if (check) {
				printf("node NOT found using RIP \n");
			}
			else {
				printf("node found using RIP \n");
			}
			return;
		}
		printf("EXIT node NOT found in tree\n");

		if (tdata->sc.syscall_number > 0x200) {// if syscall is not NTdll
			tdata->counter2++;
			printf("Syscounter1:%d, Syscounter2: %d id:%x\n", tdata->counter1, tdata->counter2, tdata->sc.syscall_number);
			return;
		}
		else {
			printf("in else prima di changed \n");
			tdata->memArrayExit.syscalNumb = tdata->sc.syscall_number;
			tdata->memArrayExit.syscallID = tdata->counter2;
			funcExit(tdata);
			changed(tdata);
			tdata->counter2++;
			printf("fefiffooooo \n");
			addKuserData(tdata);
			printf("tdata->memArrayEntry.regionsSum :%d , tdata->memArrayExit.regionsSum:%d \n", tdata->memArrayEntry.regionsSum, tdata->memArrayExit.regionsSum);
			printf("Syscounter1:%d, Syscounter2: %d id:%x\n", tdata->counter1, tdata->counter2, tdata->sc.syscall_number);
		}
	}
	else {
		printf("address found in node returning\n");
		printf("Syscall originated in %s  ESP=0x%x RA==0x%x \n", node->data, *ESP, ra);
		printf("node min: 0x%x node max: 0x%x left:%d right:%d \n", node->start_addr, node->end_addr, node->left, node->right);
		tdata->counter2++;
		return;
	}
	
	//reset status
	for (int i = 0; i < tdata->memArrayEntry.regionsSum; i++) {
		tdata->memArrayEntry.Array[i].StartAddress = 0;
		tdata->memArrayEntry.Array[i].EndAddress = 0;
		tdata->memArrayEntry.Array[i].Size = 0;
		tdata->memArrayEntry.Array[i].RegionID = 0;
	}
	for (int i = 0; i < tdata->memArrayExit.regionsSum; i++) {
		tdata->memArrayExit.Array[i].StartAddress = 0;
		tdata->memArrayExit.Array[i].EndAddress = 0;
		tdata->memArrayExit.Array[i].Size = 0;
		tdata->memArrayExit.Array[i].RegionID = 0;
	}
	tdata->memArrayEntry.syscallID = 0;
	tdata->memArrayEntry.syscalNumb = 0;
	tdata->memArrayEntry.regionsSum = 0;
	tdata->memArrayExit.syscallID = 0;
	tdata->memArrayExit.syscalNumb = 0;
	tdata->memArrayExit.regionsSum = 0;
}

//EnumSyscalls(); // parse ntdll for ordinals
//PIN_AddSyscallEntryFunction(SyscallEntry, NULL);
//PIN_AddThreadStartFunction(OnThreadStart, NULL);
//PIN_AddSyscallExitFunction(SyscallExit, NULL);	
#include <stdio.h>
#include <stdlib.h>
#include <Windows.h>

typedef struct _configurations_t {
    int score, num_api, budget;
    int id, parent_id;
    int epoch, born_in_epoch;
} configurations_t;
void CreateFileMappingEx(){
		LPCSTR file_path = "C:/pin-3.19/pinterest.txt";
		HANDLE hFile = CreateFile (file_path,//Enter the file to be copied here src
		GENERIC_READ|GENERIC_WRITE,
		FILE_SHARE_READ,
		NULL,
		CREATE_ALWAYS,
		FILE_ATTRIBUTE_NORMAL,
		NULL);

		HANDLE bucchi = CreateFileMappingA(
			hFile,
			NULL,
			PAGE_EXECUTE_READ,
			0,
			0,
			NULL
			);
}

int main(){
	void* r;
	//printf("Hello world");
	HANDLE hHeap = HeapCreate(HEAP_NO_SERIALIZE, 10, 15);
	int* pArr = (int* ) HeapAlloc(hHeap, 0, sizeof(int) * 30);	
	//printf("pArr before : %x \n", pArr );
	//printf("r: %x \n", r );
	r = HeapReAlloc(hHeap, HEAP_NO_SERIALIZE, pArr,1000);
	//printf("pArr after: %d \n", pArr );
	//printf("r: %d \n", r );
	HeapFree(hHeap, 0, pArr);
	HeapDestroy(hHeap);
	CreateFileMappingEx();
}
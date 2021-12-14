#include <stdlib.h>
#include <stdio.h>
#include <Windows.h>

int main(){
	HANDLE hHeap;
	void* r;
	//void* s;
	hHeap= HeapCreate(HEAP_NO_SERIALIZE, 0, 10);
    r = HeapAlloc(hHeap, HEAP_NO_SERIALIZE,11);
    //printf("%d \n", r);
   // r = HeapReAlloc(hHeap, HEAP_ZERO_MEMORY, r,sizeof(r)+2);
    //printf("%d \n", r);
    //printf("%x \n", s);
    HeapFree(hHeap, 0, r);

   // printf("%d \n", r);
	HeapDestroy(hHeap);

    printf("%d \n", r);
}	

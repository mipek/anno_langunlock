#include <windows.h>
#include <stdio.h>
#include <tchar.h>
#include <iostream>
#include "Utils.h"
#pragma pack(1)

#define CAPTION _T("anno_langunlock")

const uint8_t *SIG_LANGCHECK = (uint8_t*)"\x74\x1A\x0F\xB7\x44\x24";

HMODULE orig_module;
HINSTANCE my_instance;

extern "C" BOOL WINAPI DllMain(HINSTANCE instance, DWORD reason, LPVOID)
{
	if (reason == DLL_PROCESS_ATTACH) {
		my_instance = instance;
		orig_module = LoadLibrary(_T(".\\uplay_r1_loader64_org.dll"));
		if (!orig_module) {
			MessageBox(NULL, _T("Failed to load original dll (uplay_r1_loader64_org.dll)"), CAPTION, MB_OK|MB_TOPMOST|MB_ICONERROR);
			return FALSE;
		}

#if defined(DEBUG)
		// Create a console window
		create_console();
#endif //DEBUG

		module_info main_module;
		if (!get_module_info("Anno1800.exe", main_module)) {
			std::cout << "Error: Couldn't get module info" << std::endl;
		}

		std::cout << "Module base: " << (void*)main_module.base << std::endl;
		std::cout << "Module size: " << main_module.size << " bytes" << std::endl;
		
		// Scan for the pattern
		uint8_t *ptr = pattern_scan(main_module, SIG_LANGCHECK);
		std::cout << "Pattern scan result: " << (void*)ptr << std::endl;

		if (ptr != nullptr) {
			// Patch it
			DWORD old_prot;
			VirtualProtect(ptr, sizeof(uint8_t), PAGE_EXECUTE_READWRITE, &old_prot);
			*ptr = 0xEB;
			VirtualProtect(ptr, sizeof(uint8_t), old_prot, &old_prot);
			std::cout << "Patch completed" << std::endl;
		}
	}
	return TRUE;
}

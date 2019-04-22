#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <Psapi.h>
#include "Utils.h"
#include <cstdio>

void create_console()
{
	if (AllocConsole()) {
		freopen("CONIN$", "r", stdin);
		freopen("CONOUT$", "w", stdout);
		freopen("CONOUT$", "w", stderr);
		SetConsoleTitleW(L"UbiLangForce");
	}
}

bool get_module_info(const char *name, module_info &inf)
{
	MODULEINFO modinfo = { 0 };
	HMODULE handle = GetModuleHandle(name);
	if (handle == NULL) {
		return false;
	}

	if (GetModuleInformation(GetCurrentProcess(), handle, &modinfo, sizeof(MODULEINFO)) == 0) {
		return false;
	}

	inf.base = (uint8_t*)modinfo.lpBaseOfDll;
	inf.size = modinfo.SizeOfImage;
	return true;
}

static bool compare_data(const uint8_t *base, const uint8_t *pattern)
{
	size_t offs = 0;
	for (const uint8_t *sig = pattern; *sig; ++sig, ++offs) {
		if (*sig != *(base + offs) && *sig != (uint8_t)"\x2A") {
			return false;
		}
	}
	return true;
}

uint8_t *pattern_scan(module_info const& info, const uint8_t *pattern)
{
	uint8_t *cur = info.base;
	uint8_t *end = info.base + info.size;
	while (cur < end) {
		if (compare_data(cur, pattern)) {
			return cur;
		}
		++cur;
	}
	return nullptr;
}
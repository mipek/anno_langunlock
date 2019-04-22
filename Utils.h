#pragma once

#include <stdint.h>

struct module_info
{
	uint8_t *base;
	size_t size;
};

void create_console();

bool get_module_info(const char *name, module_info &inf);
uint8_t *pattern_scan(module_info const& info, const uint8_t *pattern);
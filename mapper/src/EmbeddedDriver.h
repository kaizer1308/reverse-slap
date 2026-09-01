#pragma once
#include <Windows.h>

extern unsigned char* g_P2CDriverData;
extern size_t g_P2CDriverSize;

BOOL InitializeDriverData();
void ReleaseDriverData();

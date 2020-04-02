// dllmain.cpp : 定义 DLL 应用程序的入口点。
#include "stdafx.h"
#include "detours.h"
#include <windows.h>
#include <fstream>
#include <iostream>
#include <string>
#include <mutex>
#include <io.h>
#include <stdio.h>
#include <direct.h>
#pragma comment(lib, "detours.lib")
using namespace std;
DWORD BaseAddr = (DWORD)GetModuleHandle(NULL);

char* wtoc(LPCTSTR str)
{
	DWORD dwMinSize;
	dwMinSize = WideCharToMultiByte(CP_ACP, NULL, str, -1, NULL, 0, NULL, FALSE); //计算长度
	char *out = new char[dwMinSize];
	WideCharToMultiByte(CP_OEMCP, NULL, str, -1, out, dwMinSize, NULL, FALSE);//转换
	return out;
}

TCHAR szBuffer[MAX_PATH] = { 0 };

void __stdcall SetDirPath(void* eax)
{
	string strOldName(wtoc(szBuffer));
	string strDirName = strOldName.substr(0, strOldName.find_last_of("\\") + 1);
	memset(eax, 0, strlen(strDirName.c_str()) + 0x1);
	memcpy(eax, strDirName.c_str(), strlen(strDirName.c_str()));
}

PVOID Hook1=NULL;
__declspec(naked) void ChangePath()
{
	_asm
	{
		pushad
		pushfd
		push eax
		call SetDirPath
		popfd
		popad
		jmp Hook1
	}
}

void memcopy(void* dest, void* src, size_t size)
{
	DWORD oldProtect;
	VirtualProtect(dest, size, PAGE_EXECUTE_READWRITE, &oldProtect);
	memcpy(dest, src, size);
}

void ChangeJmpSet()
{
	BYTE NOP[] = { 0x90 };
	BYTE JMP[] = { 0xEB };
	memcopy((void*)(BaseAddr + 0x7BA1F), JMP, sizeof(JMP));
	memcopy((void*)(BaseAddr + 0x7BA65), JMP, sizeof(JMP));
	memcopy((void*)(BaseAddr + 0x7B72D), NOP, sizeof(NOP));
	memcopy((void*)(BaseAddr + 0x7B72E), NOP, sizeof(NOP));
	memcopy((void*)(BaseAddr + 0x7B734), NOP, sizeof(NOP));
	memcopy((void*)(BaseAddr + 0x7B735), NOP, sizeof(NOP));
	memcopy((void*)(BaseAddr + 0x7B74E), NOP, sizeof(NOP));
	memcopy((void*)(BaseAddr + 0x7B74F), NOP, sizeof(NOP));
	memcopy((void*)(BaseAddr + 0x7B754), NOP, sizeof(NOP));
	memcopy((void*)(BaseAddr + 0x7B755), NOP, sizeof(NOP));
	memcopy((void*)(BaseAddr + 0x7B76F), NOP, sizeof(NOP));
	memcopy((void*)(BaseAddr + 0x7B770), NOP, sizeof(NOP));
	memcopy((void*)(BaseAddr + 0x7B6BD), NOP, sizeof(NOP));
	memcopy((void*)(BaseAddr + 0x7B6BE), NOP, sizeof(NOP));
	memcopy((void*)(BaseAddr + 0x7B6C4), NOP, sizeof(NOP));
	memcopy((void*)(BaseAddr + 0x7B6C5), NOP, sizeof(NOP));
	memcopy((void*)(BaseAddr + 0x7B6DE), NOP, sizeof(NOP));
	memcopy((void*)(BaseAddr + 0x7B6DF), NOP, sizeof(NOP));
	memcopy((void*)(BaseAddr + 0x7B6E4), NOP, sizeof(NOP));
	memcopy((void*)(BaseAddr + 0x7B6E5), NOP, sizeof(NOP));
	memcopy((void*)(BaseAddr + 0x7B6FF), NOP, sizeof(NOP));
	memcopy((void*)(BaseAddr + 0x7B700), NOP, sizeof(NOP));
}

void Init()
{

	HMODULE hMod = GetModuleHandle(NULL);
	if (hMod != NULL)
	{
		GetModuleFileName(hMod, szBuffer, sizeof(szBuffer) / sizeof(TCHAR) - 1);
	}
	if (!szBuffer)
	{
		MessageBox(0, L"GetDirError.", L"InitHook", 0);
		return;
	}
	ChangeJmpSet();
	Hook1 = (PVOID)(BaseAddr + 0x5AE96);
	DetourTransactionBegin();
	DetourAttach((void**)& Hook1, ChangePath);
	if (DetourTransactionCommit() != NO_ERROR)
	{
		MessageBox(NULL, L"HookError.", L"InitHook", 0);
		return;
	}
	MessageBox(NULL, L"Crack By AyamiKaze[mzsh@KF]", L"AyamiKaze", 0);
}

static void make_console() {
	AllocConsole();
	freopen("CONOUT$", "w", stdout);
	freopen("CONIN$", "r", stdin);
	std::cout << "Open Console Success!" << std::endl;
}
BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
		Init();
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}
extern "C" __declspec(dllexport) void dummy(void) {
	return;
}

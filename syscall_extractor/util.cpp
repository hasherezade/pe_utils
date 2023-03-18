#include "util.h"

BOOL(WINAPI* g_Wow64DisableWow64FsRedirection) (OUT PVOID* OldValue) = nullptr;
BOOL(WINAPI* g_Wow64RevertWow64FsRedirection) (IN PVOID OldValue) = nullptr;

BOOL util::wow64_disable_fs_redirection(OUT PVOID* OldValue)
{
	if (!g_Wow64DisableWow64FsRedirection) {
		HMODULE kernelLib = GetModuleHandleA("kernel32.dll");
		if (!kernelLib) return FALSE;

		FARPROC procPtr = GetProcAddress(kernelLib, "Wow64DisableWow64FsRedirection");
		if (!procPtr) return FALSE;

		g_Wow64DisableWow64FsRedirection = (BOOL(WINAPI*) (OUT PVOID*))procPtr;
	}
	if (!g_Wow64DisableWow64FsRedirection) {
		return FALSE;
	}
	return g_Wow64DisableWow64FsRedirection(OldValue);
}

BOOL util::wow64_revert_fs_redirection(IN PVOID OldValue)
{
	if (!g_Wow64RevertWow64FsRedirection) {
		HMODULE kernelLib = GetModuleHandleA("kernel32.dll");
		if (!kernelLib) return FALSE;

		FARPROC procPtr = GetProcAddress(kernelLib, "Wow64RevertWow64FsRedirection");
		if (!procPtr) return FALSE;

		g_Wow64RevertWow64FsRedirection = (BOOL(WINAPI*) (IN PVOID))procPtr;
	}
	if (!g_Wow64RevertWow64FsRedirection) {
		return FALSE;
	}
	return g_Wow64RevertWow64FsRedirection(OldValue);
}

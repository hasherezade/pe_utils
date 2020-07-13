#include <Windows.h>
#include <iostream>

#include <peconv.h> // include libPeConv header

#ifndef COMIMAGE_FLAGS_32BITPREFERRED
#define COMIMAGE_FLAGS_32BITPREFERRED 0x20000
#endif

#ifndef COMIMAGE_FLAGS_32BITREQUIRED
#define COMIMAGE_FLAGS_32BITREQUIRED 0x00002
#endif

typedef enum {
	PE_UNKNOWN = 0,
	PE_32BIT = 32,
	PE_64BIT = 64
} t_bitness;


bool is_wow_64(HANDLE process)
{
	FARPROC procPtr = GetProcAddress(GetModuleHandleA("kernel32"), "IsWow64Process");
	if (!procPtr) {
		//this system does not have a function IsWow64Process
		return false;
	}
	BOOL(WINAPI * is_process_wow64)(IN HANDLE, OUT PBOOL)
		= (BOOL(WINAPI*)(IN HANDLE, OUT PBOOL))procPtr;

	BOOL isCurrWow64 = FALSE;
	if (!is_process_wow64(process, &isCurrWow64)) {
		return false;
	}
	return isCurrWow64 ? true : false;
}

t_bitness get_bitness(BYTE *buffer, size_t buffer_size)
{
	if (!peconv::get_nt_hdrs(buffer)) {
		return PE_UNKNOWN;
	}
	bool is64 = peconv::is64bit(buffer);
	if (is64) {
		return PE_64BIT;
	}
	// in case of .NET files, a PE with a 32-bit header still may be loaded as 64, depending on the flags
	IMAGE_DATA_DIRECTORY* dotNetDir = peconv::get_directory_entry(buffer, IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR);
	if (!dotNetDir) {
#ifdef _DEBUG
		std::cout << "Not .NET\n";
#endif
		return PE_32BIT;
	}
	IMAGE_COR20_HEADER *dnet = peconv::get_dotnet_hdr(buffer, buffer_size, dotNetDir);
	if (!dnet) {
		return PE_32BIT;
	}
	bool is_real_32 = (dnet->Flags & COMIMAGE_FLAGS_32BITPREFERRED) || (dnet->Flags & COMIMAGE_FLAGS_32BITREQUIRED);
#ifdef _WIN64
	bool is_on_64 = true;
#else
	bool is_on_64 = is_wow_64(GetCurrentProcess());
#endif
	if (is_on_64 && !is_real_32) {
		// the system is 64 bit, so the .NET app got switched to the 64 bit mode
#ifdef _DEBUG
		std::cout << "This is 32-bit .NET App that will be loaded as 64 bit...\n";
#endif
		return PE_64BIT;
	}
	return PE_32BIT;
}

int main(int argc, char *argv[])
{
	if (argc < 2) {
		std::cout << "Checks if the given PE will run as 32 or 64 bit.\n"
			<< "Returns the number of bits.\n"
			"URL: https://github.com/hasherezade/pe_check\n"
			<< std::endl;
		std::cout << "args: <path to the PE>" << std::endl;

		system("pause");
		return 0;
	}
	LPCSTR pe_path = argv[1];
	size_t bufsize = 0;
	BYTE *buffer = peconv::load_pe_module(pe_path, bufsize, false, false);
	if (!buffer) {
		return 0;
	}

	t_bitness my_bitness = get_bitness(buffer, bufsize);
	peconv::free_pe_buffer(buffer);
#ifdef _DEBUG
	std::cout << "Bitness: " << my_bitness << "\n";
#endif
	return (int) my_bitness;
}

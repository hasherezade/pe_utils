#include <Windows.h>
#include <iostream>
#include <fstream>

#include <peconv.h> // include libPeConv header
#include "util.h"

size_t extract_syscalls(BYTE* pe_buf, size_t pe_size, std::stringstream& outs, size_t startID = 0)
{
	std::vector<std::string> names_list;
	if (!peconv::get_exported_names(pe_buf, names_list)) {
		return 0;
	}
	std::string prefix("Nt");
	std::map<DWORD, std::string> sys_functions;
	for (auto itr = names_list.begin(); itr != names_list.end(); ++itr) {
		std::string funcName = *itr;
		if (!funcName.compare(0, prefix.size(), prefix)) {
			ULONG_PTR va = (ULONG_PTR)peconv::get_exported_func(pe_buf, funcName.c_str());
			if (!va) continue;

			DWORD rva = DWORD(va - (ULONG_PTR)pe_buf);
			sys_functions[rva] = funcName;
		}
	}
	size_t id = startID;
	for (auto itr = sys_functions.begin(); itr != sys_functions.end(); ++itr) {
		std::string funcName = itr->second;
		outs << std::hex << "0x" << id++ << "," << funcName << "\n";
	}
	return id;
}

size_t extract_from_dll(IN const std::string &path, size_t startSyscallID, OUT std::stringstream &outs)
{
	size_t bufsize = 0;
	BYTE* buffer = peconv::load_pe_module(path.c_str(), bufsize, false, false);

	if (!buffer) {
		std::cerr << "Failed to load the PE: " << path << "\n";
		return 0;
	}

	size_t extracted_count = extract_syscalls(buffer, bufsize, outs, startSyscallID);
	peconv::free_pe_buffer(buffer);

	if (!extracted_count) {
		std::cerr << "No syscalls extracted from: " << path << "\n";
	}
	return extracted_count;
}

int loadInt(const std::string& str, bool as_hex)
{
	int intVal = 0;

	std::stringstream ss;
	ss << (as_hex ? std::hex : std::dec) << str;
	ss >> intVal;

	return intVal;
}

int main(int argc, char *argv[])
{
	LPCSTR pe_path = NULL;
	int startID = 0;
	if (argc < 2) {
		std::cout << "Extract syscalls from system DLLs (ntdll.dll, win32u.dll)\n"
			<< "\tOptional Args: <DllPath> <startSyscallID:hex>"
			<< std::endl;
	}
	else {
		pe_path = argv[1];
		if (argc > 2) {
			startID = loadInt(argv[2], true);
		}
	}

	PVOID old_val = NULL;
	util::wow64_disable_fs_redirection(&old_val);

	std::stringstream outs;
	size_t extracted_count = 0;

	if (pe_path) {
		extracted_count += extract_from_dll(pe_path, startID, outs);
	}
	else {
		char ntdll_path[MAX_PATH] = { 0 };
		ExpandEnvironmentStringsA("%SystemRoot%\\system32\\ntdll.dll", ntdll_path, MAX_PATH);
		extracted_count += extract_from_dll(ntdll_path, 0, outs);

		char win32u_path[MAX_PATH] = { 0 };
		ExpandEnvironmentStringsA("%SystemRoot%\\system32\\win32u.dll", win32u_path, MAX_PATH);
		extracted_count += extract_from_dll(win32u_path, 0x1000, outs);
	}

	util::wow64_revert_fs_redirection(&old_val);

	if (!extracted_count) {
		std::cerr << "Failed to extract syscalls.\n";
		return 0;
	}

	std::string outFileName = "syscalls.txt";
	std::ofstream myfile;
	myfile.open(outFileName);
	myfile << outs.str();
	myfile.close();
	std::cout << "Saved to: " << outFileName << std::endl;
	return 0;
}

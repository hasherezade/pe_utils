#include <Windows.h>
#include <iostream>
#include <fstream>

#include <peconv.h> // include libPeConv header


size_t extract_syscalls(BYTE* pe_buf, size_t pe_size, std::stringstream& outs)
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
	size_t id = 0;
	for (auto itr = sys_functions.begin(); itr != sys_functions.end(); ++itr) {
		std::string funcName = itr->second;
		outs << std::hex << "0x" << id++ << "," << funcName << "\n";
	}
	return id;
}

int main(int argc, char *argv[])
{
	if (argc < 2) {
		std::cout << "Extract syscalls from system DLLs.\n"
			<< "Arg: <DLL>"
			<< std::endl;
		system("pause");
		return 0;
	}
	LPCSTR pe_path = argv[1];
	size_t bufsize = 0;
	BYTE *buffer = peconv::load_pe_module(pe_path, bufsize, false, false);
	if (!buffer) {
		return 0;
	}
	std::stringstream outs;
	if (!extract_syscalls(buffer, bufsize, outs)) {
		std::cerr << "No syscalls extracted!\n";
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

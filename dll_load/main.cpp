#include <Windows.h>
#include <iostream>
#include <vector>
#include <sstream>

#define PAUSE_AFTER

size_t split_list(const std::string &sline, const char delimiter, std::vector<std::string> &args)
{
	std::istringstream f(sline);
	std::string s;
	while (getline(f, s, delimiter)) {
		args.push_back(s);
	}
	return args.size();
}

bool run_dll_with_args(const wchar_t* pe_path, std::vector<std::string> &exports)
{
	HMODULE lib = LoadLibraryW(pe_path);
	if (!lib) {
		return false;
	}
	std::vector<std::string>::iterator itr;
	for (itr = exports.begin(); itr != exports.end(); itr++) {
		std::string func_name = *itr;
		FARPROC func = NULL;
		if (func_name[0] == '#') {
			int ordinal;
			std::string ord_str = func_name.substr(1);
			std::stringstream ss;
			ss << std::dec << ord_str;
			ss >> ordinal;
			func = GetProcAddress(lib, MAKEINTRESOURCE(ordinal));
		}
		else {
			func = GetProcAddress(lib, func_name.c_str());
		}

		if (!func) continue;

		std::cout << "Calling the export: " << func_name << "\n";
		int(*exp_func)() = (int(*)())func;
		func();
	}
	return true;
}

int wmain(int argc, wchar_t *argv[])
{
	int is_dll_executed = 0;
#ifdef _WIN64
	bool is_on_64 = true;
#else
	bool is_on_64 = false;
#endif
	if (argc < 2) {
		std::cout << "Loads a given DLL. Calls exported functions if supplied.\n";
		if (is_on_64) {
			std::cout << "64-bit version\n" << std::endl;
		}
		else {
			std::cout << "32-bit version\n" << std::endl;
		}
		std::cout << "Args: <DLL> [*exports]\n";
		std::cout << "\t* - optional\n";
		std::cout << "\texports: a list of functions separated by ';'. Examples:\n";
		std::cout << "\t DllRegisterServer;DllUnregisterServer\n";
		std::cout << "\t #1;#2\n";
		system("pause");
		return 0;
	}
	wchar_t* pe_path = argv[1];

	std::vector<std::string> exports;
	if (argc >= 3) {
		// load exports:
		std::wstring paramsl = argv[2];
		std::string params(paramsl.begin(), paramsl.end());
		split_list(params, ';', exports);
	}

	if (run_dll_with_args(pe_path, exports)) {
		is_dll_executed = 1;
		std::cout << "[+] The Dll was run! " << std::endl;
#ifdef PAUSE_AFTER
		system("pause");
#endif
	}
	return is_dll_executed;
}

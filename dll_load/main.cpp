#include <Windows.h>
#include <iostream>
#include <vector>
#include <sstream>

size_t split_list(const std::string &sline, const char delimiter, std::vector<std::string> &args)
{
	std::istringstream f(sline);
	std::string s;
	while (getline(f, s, delimiter)) {
		args.push_back(s);
	}
	return args.size();
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
		std::cout << "Loads a given DLL. May call exported functions if supplied.\n";
		if (is_on_64) {
			std::cout << "64-bit version\n" << std::endl;
		}
		else {
			std::cout << "32-bit version\n" << std::endl;
		}
		std::cout << "args: <path to the PE>" << std::endl;
		std::cout << "Args: <DLL> [*exports]\n";
		std::cout << "\t * - optional]\n";
		system("pause");
		return 0;
	}
	wchar_t* pe_path = argv[1];
	HMODULE lib =  LoadLibraryW(pe_path);
	if (!lib) {
		return is_dll_executed;
	}
	is_dll_executed = 1;
	if (argc < 3) {
		// no more args to process
		return is_dll_executed;
	}
	std::wstring paramsl = argv[2];
	std::string params(paramsl.begin(), paramsl.end());
	std::vector<std::string> exports;
	split_list(params, ';', exports);

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
	return is_dll_executed;
}

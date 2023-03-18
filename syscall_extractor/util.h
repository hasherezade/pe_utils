#pragma once

#include <windows.h>

namespace util {
	BOOL wow64_disable_fs_redirection(OUT PVOID* OldValue);
	BOOL wow64_revert_fs_redirection(IN PVOID OldValue);
};

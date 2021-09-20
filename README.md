# PE utils
[![Build status](https://ci.appveyor.com/api/projects/status/0o7akheju8te49d6?svg=true)](https://ci.appveyor.com/project/hasherezade/pe-utils)

Set of small utilities, helpers for PIN Tools

+ **dll_load** - Loads a given DLL. Calls exported functions if supplied.
+ **pe_check** - Checks the bitness of the PE and outputs it as a return value.
+ **kdb_check** - Checks if the Kernel Debugger is enabled (no elevation required). Outputs the status as a return value.

You can display the returned values of **pe_check** and **kdb_check** by:

```
echo %errorlevel%
```

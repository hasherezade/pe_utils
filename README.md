# PE utils
[![Build status](https://ci.appveyor.com/api/projects/status/0o7akheju8te49d6?svg=true)](https://ci.appveyor.com/project/hasherezade/pe-utils)

Set of small, self-contained utilities to be used in other toolkits, i.e. as helpers for PIN Tools ([example](https://github.com/hasherezade/tiny_tracer/tree/master/install32_64)).

+ **dll_load** - Loads a given DLL. Calls exported functions if supplied.
+ **pe_check** - Checks the bitness of the PE and outputs it as a return value.
+ **kdb_check** - Checks if the Kernel Debugger is enabled (no elevation required). Outputs the status as a return value.

You can display the returned values of **pe_check** and **kdb_check** by:

```cmd
echo %errorlevel%
```

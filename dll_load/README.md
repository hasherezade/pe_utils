# dll_load

Custom DLL loader (similar to `rundll32`).
```
Loads a given DLL. Calls exported functions if supplied.
Args: <DLL> [*exports]
  * - optional
  exports: a list of functions separated by ';'. Examples:
  DllRegisterServer;DllUnregisterServer
  #1;#2
```

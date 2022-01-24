# dll_load

Custom DLL loader (similar to `rundll32`). It allows to:
+ run a DLL without any exports (only `DllMain` will be executed)
+ run multiple exports, one after another
+ pause execution after the DLL finished

```
Loads a given DLL. Calls exported functions if supplied.
Args: <DLL> [*exports]
  * - optional
  exports: a list of functions separated by ';'. Examples:
  DllRegisterServer;DllUnregisterServer
  #1;#2
```

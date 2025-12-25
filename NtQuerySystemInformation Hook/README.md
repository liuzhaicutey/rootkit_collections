## API interceptor
This is a System API response interceptor (Improved version of my previous NTQuerySysInfo Hook). When injected into a process (like Task Manager), hides specific executable names from the process list. It demonstrates two primary methods of redirection: IAT Hooking which modifies the Import Address Table of the target module, and Inline Hooking (Detouring) which manually overwrites function prologues with architecture-aware JMP instructions (x86/x64).
- If you want to check the older versions, I have saved one backup on my gist.

## Limitations:
- Process managers using kernel drivers as tested (ProcessHacker, System Informer) will bypass userland hooks entirely.
- This only covers NtQuerySystemInformation while other processes can use Process32First/Next, EnumProcesses, WTSEnumerateProcesses, etc.
- For production use, consider kernel-mode solutions or legitimate alternatives.

## Disclaimer:
For Educational Purposes Only. Unauthorized use of this technique against systems you do not own is illegal and unethical.

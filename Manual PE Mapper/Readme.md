# Manual PE Mapper

A **Custom In-Memory PE File Loader**, or assembler utility designed to manually map a running Windows executable or Dynamic Link Library (DLL) into a **new, clean block of memory** within the current process and prepare it for execution.
A classic technique for **reflective DLL injection**, **packing/unpacking**, and building custom **anti-debugging** mechanisms.

---

## Key Methods & Operations

The code has four critical stages of PE loading:

1.  **Memory Allocation & Copying:**
    * Uses `VirtualAlloc` to allocate the required memory at the image's preferred base address.
    * Copies all necessary data—the headers and all sections (like `.text`, `.data`)—from the original module to the new memory location using `memcpy`.

2.  **Import Resolution (Linking):**
    * The **`ProcessImports`** function parses the Import Directory to find external DLLs and functions.
    * It calls `LoadLibraryA` and `GetProcAddress` to dynamically find the actual memory addresses of every external function and writes them into the new image's Import Address Table (IAT). 

3.  **Relocation Fix-up:**
    * If the new image base address is different from the preferred address (due to ASLR), all internal absolute pointers are incorrect.
    * The **`ProcessRelocations`** function parses the **IMAGE\_BASE\_RELOCATION** directory and adds the memory delta (the base address difference) to every hardcoded pointer, ensuring all internal references are valid.

4.  **Execution Preparation:**
    * It uses `VirtualProtect` to set the necessary memory permissions (Read, Write, Execute) on the newly copied code and data sections.
    * It executes any required **TLS (Thread Local Storage) callbacks**.
    * Finally, it locates the new address of the program's main entry point and transfers control to it, beginning execution of the reassembled module.

---

## Contacts

https://t.me/Shaacidyne

# Shaacidyne Wiper #
A Windows bootloader wiper written in python, ASM, and C.
1. FOR LEGACY Payload, check the bootloader.asm and compile it: nasm -f bin -o bootloader.bin bootloader.asm (assemble via NASM).
2. FOR UEFI Payload: You should convert it to a .efi file using EDK or MSYS2 with GNU-EFI and GCC Compiler.
3. If you have your own .efi/.bin files, then the automated delivery mechanism of the python file may help you.
4. Save the bootloader.bin or the BOOTX64.EFI file in the same directory as the .py or .exe loader if you compiled it. Let the loader do its job.
5. Use it on a virtual machine for payload testing purposes (QEMU, VirtualBox, etc.) I HIGHLY RECOMMEND NOT TO TEST IT ON AN ACTUAL MACHINE.

# Limitations #
1. ~~Certificate signing logic terribly needed a fix. It will corrupt the bootloader by adding specified headers upon signage. For now, this script best works on systems with Secure Boot disabled.~~ Removed this. This will not work on devices with Secure Boot activated.

# Disclaimer #
The tool is a proof-of-concept and entirely used for educational purposes. It should not be used against machines you do not have permissions to test. The author is not responsible for any misuse or any damage that this tool may cause. 

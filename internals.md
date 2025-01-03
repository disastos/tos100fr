# Atari TOS 1.0 internals

Here are some pointers to essential internal TOS functions.\
Use `G` in Ghidra to go to the address or label.

Reconstructed source code of later TOS versions is available in the [th-otto/tos1x](https://github.com/th-otto/tos1x) repository. This is an essential resource to understand the whole operating system, with original labels and comments. Due to versions differences, some functions are identical, some differ more or less. In any case, adresses are different.

## BIOS/XBIOS

`0x00fc0000` os_entry: Start of ROM\
`0x00fc0020` main: Reset entry point\
`0x00fc074e` biostrap: Trap #13 BIOS handler\
`0x00fc0748` xbiostrap: Trap #14 XBIOS handler\
`0x00fc9cc0` line1010: Line-A handler\
`0x00fc079c` bios_vecs: Array of pointers to BIOS functions\
`0x00fc07ce` xbios_vecs: Array of pointers to XBIOS functions\
`0x00fc0634` int_vbl: VBL interrupt handler\
`0x00fc2f96` timercint: Timer C interrupt handler, 200 Hz system timer

## GEMDOS (a.k.a. BDOS)
`0x00fc4b78` osinit: BDOS entry point\
`0x00fc4d66` enter: Trap #1 GEMDOS handler\
`0x00fd1cc6` funcs: Pointers to GEMDOS functions

## VDI (a.k.a. GSX)
`0x00fc4cb4` ground_it: Trap #2 GEM handler for VDI (later hooked by AES)\
`0x00fc9d52` GSX_ENTRY: Internal VDI trap #2 dispatcher\
`0x00fc9cfe` atab: Array of pointers to Line-A functions\
`0x00fd2378` jmptb1: First array of pointers to VDI functions\
`0x00fd2414` jmptb2: Second array of pointers to VDI functions\
`0x0000293a` lineavars: Line-A variables

## AES/Desktop (a.k.a. Crystal)
`0x00fd91d0` gemstart: AES entry point\
`0x00fe3746` grptrp: Trap #2 GEM handler for AES\
`0x00feeb6a` linefhandler: Line-F handler, to call AES/Desktop functions\
`0x00feeba8` lineftab: Array of pointers to Line-F functions\
`0x00009f16` rlr: Pointer to the BASEPAGE of the current process\
`0x00fd9362` gem_main: AES internal entry point\
`0x00feb052` sh_main: AES shell entry point\
`0x00fe5e70` xif: Intermediate trap-to-AES function\
`0x00fe54d6` crysbind: AES function dispatcher\
`0x00fe76f8` deskmain: Desktop entry point


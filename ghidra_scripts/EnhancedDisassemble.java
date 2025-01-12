// Disassemble the listing at current location,
// including Line-F calls.
//@author Vincent Rivière
//@category Atari
//@keybinding
//@menupath
//@toolbar
//@runtime Java

import ghidra.app.script.GhidraScript;
import ghidra.app.script.GhidraState;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;

public class EnhancedDisassemble extends GhidraScript {

    // Check for an undefined Line-F instruction.
    private boolean isUndefinedLineF(Address address) throws Exception {
        Listing listing = currentProgram.getListing();
        if (!listing.isUndefined(address, address.next()))
            return false;

        Memory memory = currentProgram.getMemory();
        long opcode = memory.getShort(address) & 0xffff;

        return (opcode & 0xf000) == 0xf000;
    }

    // Check for an undefined "link" instruction.
    private boolean isUndefinedLink(Address address) throws Exception {
        Listing listing = currentProgram.getListing();
        if (!listing.isUndefined(address, address.next()))
            return false;

        Memory memory = currentProgram.getMemory();
        long opcode = memory.getShort(address) & 0xffff;

        return opcode == 0x4e56;
    }

    @Override
    public void run() throws Exception {
        if (currentAddress == null)
            throw new RuntimeException("currentAddress is null");

        Address address = currentAddress;
        Listing listing = currentProgram.getListing();

        while (!monitor.isCancelled()) {
            // Check for undefined "link" instruction.
            if (isUndefinedLink(address)) {
                printf("%s Undefined link\n", address);

                // Disassemble as much as possible.
                disassemble(address);

                // Create a function.
                createFunction(address, null);

                continue;
            }

            // Check for undefined Line-F function call.
            if (isUndefinedLineF(address)) {
                printf("%s Undefined Line-F\n", address);

                // Add the new Line-F reference, but run the script
                // on different state to avoid screen refreshing.
                GhidraState state2 = new GhidraState(state);
                state2.setCurrentAddress(address);
                runScript("AddLineFReference", state2);

                // Skip the Line-F call
                address = address.add(2);

                continue;
            }

            // Check for other undefined data.
            if (listing.isUndefined(address, address)) {
                // Try to disassemble.
                disassemble(address);
                if (!listing.isUndefined(address, address)) {
                    // Disassembly succeeded. Continue processing.
                    continue;
                }
                else {
                    // Disassembly failed. Stop processing.
                    printf("%s Stop.\n", address);
                    setCurrentLocation(address);
                    break;
                }
            }

            // Something is already defined here. Just skip and continue.
            CodeUnit codeUnit = listing.getCodeUnitAt(address);
            address = address.add(codeUnit.getLength());
        }
    }
}

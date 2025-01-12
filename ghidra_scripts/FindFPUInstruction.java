// Find next FPU instruction (or ColdFire integer instruction).
// This is generally a wrongly interpreted Line-F instruction.
//@author Vincent Rivière
//@category Atari
//@keybinding
//@menupath
//@toolbar
//@runtime Java

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;

public class FindFPUInstruction extends GhidraScript {

    // Check for a Line-F opcode recognized as instruction
    private boolean isFpuOpcode(Address address) throws Exception {
        Listing listing = currentProgram.getListing();
        if (listing.isUndefined(address, address.next()))
            return false;

        Memory memory = currentProgram.getMemory();
        long opcode = memory.getShort(address) & 0xffff;

        if ((opcode & 0xf000) != 0xf000)
            return false;

        Instruction instruction = listing.getInstructionAt(address);
        return instruction != null;
    }

    @Override
    public void run() throws Exception {
        Address address = currentAddress;

        Listing listing = currentProgram.getListing();
        while (!monitor.isCancelled()) {
            if (address.getOffset() >= 0x00ffff00) {
                // Definitely not found
                println("Not found.");
                return;
            }

            if (isFpuOpcode(address)) {
                // Found
                setCurrentLocation(address);
                return;
            }

            // Not found yet: advance to next instruction
            CodeUnit codeUnit = listing.getCodeUnitAt(address);
            address = address.add(codeUnit.getLength());
        }
    }
}

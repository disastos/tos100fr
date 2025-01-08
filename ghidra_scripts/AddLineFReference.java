//Create a reference to the matching Line-F function.
//Select an Line-F byte, then run this script.
//@author Vincent Rivière
//@category Atari
//@keybinding DOLLAR
//@menupath Edit.Add Line-F reference
//@runtime Java

import ghidra.app.script.GhidraScript;
import ghidra.program.model.util.*;
import ghidra.program.model.reloc.*;
import ghidra.program.model.data.*;
import ghidra.program.model.block.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.lang.protorules.*;
import ghidra.program.model.scalar.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.lang.*;
import ghidra.program.model.pcode.*;
import ghidra.program.model.address.*;
import ghidra.program.model.data.ISF.*;

public class AddLineFReference extends GhidraScript {

	// Check if an address is even.
	private boolean isEven(Address address) {
		long offset = address.getUnsignedOffset();
		//println(String.format("%08x", offset));
		return (offset & 1) == 0;
	}

	// Get a Symbol object from a label.
	// If multiple definitions exist, an exception is thrown.
	private Symbol getUniqueSymbol(String name) {
		SymbolIterator iter = currentProgram.getSymbolTable().getSymbols(name);
		if (!iter.hasNext())
			throw new RuntimeException("Symbol " + name + " not found.");

		Symbol symbol = iter.next();

		if (iter.hasNext())
			throw new RuntimeException("Symbol " + name + " found multiple times.");

		return symbol;
	}

	// Add a Line-F reference to an undefined Address.
	// Current location must be on a 0xfxxx undefined opcode.
	private void addLineFReference(Address address) throws Exception {
		Listing listing = currentProgram.getListing();
		Memory memory = currentProgram.getMemory();

		// Check that the first opcode byte is on even address
		if (!isEven(address)) {
			println("Please select an even address.");
			return;
		}

		// Address of the second opcode byte
		Address secondByteAddress = address.next();

		// Both bytes must be cleared
		if (!listing.isUndefined(address, secondByteAddress)) {
			println("Please clear first.");
			return;
		}

		// Read the opcode
		long opcode = memory.getShort(address) & 0xffff;
		//println(String.valueOf(opcode));

		// Check for Line-F opcode
		long opcodeLine = (opcode & 0xf000) >> 12;
		if (opcodeLine != 0xf) {
			println(String.format("Not a Line-F opcode: %04x", opcode));
			return;
		}

		// Create data for the opcode
		Data fdata = listing.createData(address, WordDataType.dataType);

		// Opcode bit 0 has a special meaning
		if ((opcode & 1) == 0) {
			// This opcode holds an offset into the Line-F table
			long foffset = opcode & 0x0ffe;
			//println("foffset=" + foffset);

			// Get the table symbol
			Symbol tableSymbol = getUniqueSymbol("lineftab");

			// Compute the address of the relevant table item
			Address addrItem = tableSymbol.getAddress().add(foffset);

			// Read the item value: address of actual function
			long functionOffset = memory.getInt(addrItem);
			//println(String.format("function=%08x", functionOffset));
			Address addrFunction = address.getNewAddress(functionOffset);

			// Add a reference to the function on the Line-F data
			fdata.addValueReference(addrFunction, RefType.UNCONDITIONAL_CALL);
		}
		else {
			// This opcode is a jump to the end of the function
			Symbol retSymbol = getUniqueSymbol("movinst");
			fdata.addValueReference(retSymbol.getAddress(), RefType.UNCONDITIONAL_JUMP);
		}
	}

	// Add a Line-F reference to the current location.
	// Prerequisite: data must be cleared.
	public void run() throws Exception {
		if (currentAddress == null) {
			println("No Location.");
			return;
		}

		addLineFReference(currentAddress);
	}
}

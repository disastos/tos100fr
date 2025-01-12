//Remove all references to the current address.
//@author Vincent Rivière
//@category Atari
//@keybinding
//@menupath
//@toolbar
//@runtime Java

import ghidra.app.script.GhidraScript;
import ghidra.program.model.symbol.*;

public class RemoveAllReferences extends GhidraScript {

    @Override
    public void run() throws Exception {
        if (currentAddress == null) {
            println("No Location.");
            return;
        }

        Reference[] refs = getReferencesTo(currentAddress);
        for (Reference ref : refs) {
            removeReference(ref);
        }
    }
}

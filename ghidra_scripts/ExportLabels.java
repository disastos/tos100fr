// Export all labels
//@author Vincent Rivière
//@category Atari
//@runtime Java

import ghidra.app.script.GhidraScript;
import ghidra.program.model.symbol.*;
import ghidra.program.model.address.*;
import java.io.*;

public class ExportLabels extends GhidraScript {

    // Export all labels
    @Override
    public void run() throws Exception {
        File outputFile = askFile("Select Output File", "Save");
        String outputPath = outputFile.getPath();

        BufferedWriter writer = new BufferedWriter(new FileWriter(outputPath));
        try {
            SymbolTable symbolTable = currentProgram.getSymbolTable();
            SymbolIterator iter = symbolTable.getAllSymbols(true);
            while (iter.hasNext() && !monitor.isCancelled()) {
                Symbol symbol = iter.next();
                Address address = symbol.getAddress();
                String label = symbol.getName();

                // Skip inner labels
                if (
                    label.contains("+")
                    || label.contains(".")
                    || label.contains("[")
                    || label.startsWith("LAB_")
                    || label.startsWith("switch")
                    || label.startsWith("caseD")
                    || label.startsWith("s_")
                ) continue;

                writer.write(String.format("0x%s %s\n", address.toString(), label));
            }
        }
        finally {
            writer.close();
        }
    }
}

// Import labels from an exported file
//@author Vincent Rivière
//@category Atari
//@runtime Java

import ghidra.app.script.GhidraScript;
import ghidra.program.model.symbol.*;
import ghidra.program.model.address.*;
import java.io.*;

public class ImportLabels extends GhidraScript {

    @Override
    public void run() throws Exception {
        SymbolTable symbolTable = currentProgram.getSymbolTable();

        File inputFile = askFile("Select Input File", "Load");
        String inputPath = inputFile.getPath();

        BufferedReader reader = new BufferedReader(new FileReader(inputPath));
        try {
            String line;
            while ((line = reader.readLine()) != null) {
                String[] fields = line.split(" +");
                String label = fields[0];
                String strOffset = fields[1];
                Address address = getAddressFactory().getAddress(strOffset);

                boolean labelExists = false;
                Symbol defaultSymbol = null;
                Symbol[] symbols = symbolTable.getSymbols(address);
                for (Symbol symbol : symbols) {
                    String symLabel = symbol.getName();
                    if (symLabel.equals(label)) {
                        labelExists = true;
                        break;
                    }

                    if (symbol.getSource() == SourceType.DEFAULT) {
                        defaultSymbol = symbol;
                        break;
                    }
                }

                if (labelExists)
                    continue;

                printf("0x%08x %s %s\n", address.getOffset(), label, defaultSymbol);

                if (defaultSymbol != null)
                    defaultSymbol.setName(label, SourceType.USER_DEFINED);
                else
                    symbolTable.createLabel(address, label, SourceType.USER_DEFINED);
            }
        }
        finally {
            reader.close();
        }
    }
}

/* 
 * Resolve API hash values to actual names
 * (c) 2020 2igosha igosha@kaspersky.com
 */

import ghidra.app.script.GhidraScript;
import ghidra.framework.cmd.Command;
import ghidra.program.model.lang.OperandType;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.*;
import java.io.*;
import java.util.*;
import ghidra.util.Msg;

public class ApiHashesScript extends GhidraScript {

    @Override
    public void run() throws Exception {
        // Load the api name list and hash it
        File file = askFile("Please specify a file with API names", "Api Hashes");
        if ( file == null ) {
            return;
        }
        String libName = askString("Please provide the dll name", "Api Hashes");
        if ( libName == null ) {
            return;
        }
        FileReader fr = new FileReader(file);
        BufferedReader br = new BufferedReader(fr);
        String name;
        HashMap<Integer, String> hashes = new HashMap<Integer, String>();
        while ( (name = br.readLine()) != null) {
            if ( name.isEmpty() ) {
                continue;
            }
            hashes.put(HashAPI(libName, name), name);
        }
        fr.close();

        // Now search for all operands matching
        Listing listing = currentProgram.getListing();
        InstructionIterator iter = listing.getInstructions(currentProgram.getMemory(), true);
        while (iter.hasNext() && !monitor.isCancelled()) {
            Instruction ins = iter.next();
            int numOps = ins.getNumOperands();
            boolean found = false;
            for (int i = 0; i < numOps && !found ; i++) {
                if (ins.getOperandType(i) != (OperandType.SCALAR)) {
                    continue;
                }
                Integer hashValue = (int)ins.getScalar(i).getUnsignedValue();
                String functionName = hashes.get(hashValue);
                if ( functionName != null ) {
                    writer.printf("%s found API HASH %s\n", ins.getMinAddress(), functionName);
                    listing.setComment(ins.getMinAddress(), CodeUnit.EOL_COMMENT, functionName);
                }
            }
        }
    }

    private int HashAPI(String libName, String name){
        int result = 0;
        for (int i = 0; i < libName.length(); i++){
            char c = libName.charAt(i);
            if ( c > 0x60 ) {
                c -= 0x20;
            }
            result = ( ( result >>> 0xD ) | ( result << ( 32 - 0xD ) ) ) + c;
            result = ( ( result >>> 0xD ) | ( result << ( 32 - 0xD ) ) ); // zero char for UTF-16
        }
        // That's for the terminating zero WORD
        result = ( ( result >>> 0xD ) | ( result << ( 32 - 0xD ) ) );
        result = ( ( result >>> 0xD ) | ( result << ( 32 - 0xD ) ) );

        int hash2 = 0;
        for (int i = 0; i < name.length(); i++){
            char c = name.charAt(i);
            hash2 = ( ( hash2 >>> 0xD ) | ( hash2 << ( 32 - 0xD ) ) ) + c;
        }
        result += ( ( hash2 >>> 0xD ) | ( hash2 << ( 32 - 0xD ) ) );
        // writer.printf("hash \"%s\", \"%s\" = 0x%X\n", libName, name, result);
        return result;
    }
}

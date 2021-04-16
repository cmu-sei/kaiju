/***
 * CERT Kaiju
 * Copyright 2021 Carnegie Mellon University.
 *
 * NO WARRANTY. THIS CARNEGIE MELLON UNIVERSITY AND SOFTWARE ENGINEERING
 * INSTITUTE MATERIAL IS FURNISHED ON AN "AS-IS" BASIS. CARNEGIE MELLON UNIVERSITY
 * MAKES NO WARRANTIES OF ANY KIND, EITHER EXPRESSED OR IMPLIED, AS TO ANY MATTER
 * INCLUDING, BUT NOT LIMITED TO, WARRANTY OF FITNESS FOR PURPOSE OR
 * MERCHANTABILITY, EXCLUSIVITY, OR RESULTS OBTAINED FROM USE OF THE MATERIAL.
 * CARNEGIE MELLON UNIVERSITY DOES NOT MAKE ANY WARRANTY OF ANY KIND WITH RESPECT
 * TO FREEDOM FROM PATENT, TRADEMARK, OR COPYRIGHT INFRINGEMENT.
 *
 * Released under a BSD (SEI)-style license, please see LICENSE.md or contact permission@sei.cmu.edu for full terms.
 *
 * [DISTRIBUTION STATEMENT A] This material has been approved for public release and unlimited distribution.
 * Please see Copyright notice for non-US Government use and distribution.
 *
 * Carnegie Mellon (R) and CERT (R) are registered in the U.S. Patent and Trademark Office by Carnegie Mellon University.
 *
 * This Software includes and/or makes use of the following Third-Party Software subject to its own license:
 * 1. OpenJDK (http://openjdk.java.net/legal/gplv2+ce.html) Copyright 2021 Oracle.
 * 2. Ghidra (https://github.com/NationalSecurityAgency/ghidra/blob/master/LICENSE) Copyright 2021 National Security Administration.
 * 3. GSON (https://github.com/google/gson/blob/master/LICENSE) Copyright 2020 Google.
 * 4. JUnit (https://github.com/junit-team/junit5/blob/main/LICENSE.md) Copyright 2020 JUnit Team.
 *
 * DM21-0087
 */
package kaiju.plugins.fnxrefs;

import java.io.File;
import java.io.FileWriter;
import java.util.StringJoiner;

import ghidra.program.model.util.PropertyMapManager;
import ghidra.program.model.util.ObjectPropertyMap;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.symbol.*;

import ghidra.util.Msg;
import kaiju.util.AddressUtils;

public final class HeadlessXrefsToCSV {

    public final static void writeCSV(File csvFile, Program currentProgram) throws Exception {

        FileWriter csvFileWriter = new FileWriter(csvFile,true);
        
        StringJoiner csv_fields_joined_header = new StringJoiner(",");
                
        csv_fields_joined_header.add("Fn Entry Address");
        csv_fields_joined_header.add("Code Ref Count");
        csv_fields_joined_header.add("Data Ref Count");
        csv_fields_joined_header.add("As BE?");
        csv_fields_joined_header.add("As LE?");
            
        csvFileWriter.write(csv_fields_joined_header.toString()+"\n");
        
        Memory mem = currentProgram.getMemory();
        Address minAddr = currentProgram.getMinAddress();
        ReferenceManager refman = currentProgram.getReferenceManager();

        // TODO: loop over all function entry point address
        for (Function fn : currentProgram.getFunctionManager().getFunctions(true)) {
            Address fnEntryAddress = fn.getEntryPoint();
            ReferenceIterator refiter = refman.getReferencesTo(fnEntryAddress);
            
            // the following uses ghidra's internal functions for identifying references
            
            int dataRefCnt = 0;
            int codeRefCnt = 0;
            for (Reference xref : refiter) {
                if (xref.getReferenceType().isData()) {
                    dataRefCnt++;
                } else {
                    codeRefCnt++;
                }
            }
            
            // we also do a search over the entire binary for this,
            // searches forward from the minimum address of the program thru entire program
            byte[] val = AddressUtils.addressToByteArray(fnEntryAddress);
            Address query = null;
            if (minAddr != null) {
                query = mem.findBytes​(minAddr, val, null, true, null);
            }
            String queryStr = (query == null) ? "false" : "true";
            // search for address in little endian format
            byte[] valLE = AddressUtils.addressToByteArrayLE(fnEntryAddress);
            if (minAddr != null) {
                query = mem.findBytes​(minAddr, valLE, null, true, null);
            }
            String leQueryStr = (query == null) ? "false" : "true";

            /*
            * Build CSV Line
            */
                
            StringJoiner csv_fields_joined = new StringJoiner(",");
                
            csv_fields_joined.add("0x"+fnEntryAddress.toString().toUpperCase());
            csv_fields_joined.add(Integer.toString(codeRefCnt));
            csv_fields_joined.add(Integer.toString(dataRefCnt));
            csv_fields_joined.add(queryStr);
            csv_fields_joined.add(leQueryStr);
            
            csvFileWriter.write(csv_fields_joined.toString()+"\n");
        }

        csvFileWriter.flush();
        csvFileWriter.close();
    }

}

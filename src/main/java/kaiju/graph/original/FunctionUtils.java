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
 * 5. Gradle (https://github.com/gradle/gradle/blob/master/LICENSE) Copyright 2021 Gradle Inc.
 * 6. markdown-gradle-plugin (https://github.com/kordamp/markdown-gradle-plugin/blob/master/LICENSE.txt) Copyright 2020 Andres Almiray.
 * 7. Z3 (https://github.com/Z3Prover/z3/blob/master/LICENSE.txt) Copyright 2021 Microsoft Corporation.
 * 8. jopt-simple (https://github.com/jopt-simple/jopt-simple/blob/master/LICENSE.txt) Copyright 2021 Paul R. Holser, Jr.
 *
 * DM21-0792
 */
package kaiju.graph.original;

import ghidra.program.database.ProgramDB;
import ghidra.program.database.code.CodeManager;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.block.CodeBlock;
import ghidra.program.model.block.CodeBlockIterator;
import ghidra.program.model.block.CodeBlockModel;
import ghidra.program.model.block.CodeBlockReferenceIterator;
import ghidra.program.model.block.SimpleBlockModel;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.CodeUnitIterator;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.FlowType;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.UsrException;
import ghidra.util.task.TaskMonitor;

import java.util.LinkedList;
import java.util.List;

import kaiju.common.*;

/**
 * Some utility functions for representing a Function in different formats,
 * particularly a CFG of CodeBlock flows.
 */
public class FunctionUtils implements KaijuLogger {

    private Address fep;
    private AddressSetView allAddresses;
    private int nAddresses;
    private AddressSetView chunks;
    private int nChunks;
    private List<CodeUnit> code_units; // in address order?
    private int nCodeUnits;
    
    private CodeManager cm;
    
    public AddressSetView getChunks() {
        return chunks;
    }
    
    public int getNumChunks() {
        return chunks.getNumAddressRanges();
    }
    
    public AddressSetView getAddresses() {
        return allAddresses;
    }
    
    public int getNumAddresses() {
        return allAddresses.getNumAddressRanges();
    }
    
    public Address getEntryPoint() {
        return fep;
    }
    
    public List<CodeUnit> getCodeUnits() {
        return code_units;
    }

    public FunctionUtils(Program program, Function function) {
    
        initialComputations(program, function);
    
    }
    
    private void initialComputations(Program program, Function function) {
    
        if (function == null) {
            // TODO: what's the best way to handle this?
            debug(this, "Empty function found!");
        }
        
        fep = function.getEntryPoint();
        
        // the CodeManager can be used to look up instruction stuff later, but
        // it's not exposed in the Program interface so we need to cast to the
        // underlying ProgramDB implementation of program to get at that:
        cm = ((ProgramDB) program).getCodeManager();
        
        computeChunks(function);
        computeCodeUnitsAndAddressSet(function);
    
    }
    
    private AddressSetView computeChunks(Function function) {
    
        String dmsg;
    
        // no real simple API to get Chunks/BasicBlocks(CodeBlocks)/Instructions
        // from a Function, well except for the "chunks" I suppose that come
        // back as the body of the function as an AddressSetView:
        chunks = function.getBody();
        
        nChunks = 0;
        for (AddressRange chunk: chunks) {
            dmsg = "  ";
            nChunks++;
            
            if (chunk.contains(fep)) {
                dmsg += "[FnEP] ";
            }
            // if (chunk.getMinAddress() < ep) { // odd, this doesn't work, and
            // there is no toLong() method?  But there is a compareTo(), which
            // does work:
            if (chunk.getMinAddress().compareTo(fep) < 0) {
                dmsg += "[pre EP] ";
            }
            dmsg += "chunk from " + chunk.getMinAddress().toString() + " to " + chunk.getMaxAddress().toString();
            debug(this, dmsg);
        }
        
        debug(this, "Fn has " + nChunks + " chunk(s)");
        
        return chunks;
    
    }
    
    /**
     * Compute CodeUnits and AddressSets for the Function.
     * Sets the allAddresses and code_units class variables.
     */
    private void computeCodeUnitsAndAddressSet(Function function) {
    
        AddressSet addrs = new AddressSet();
        String dmsg;
        
        // note this should include Data (but NOT Unknown) CodeUnits as well 
        CodeUnitIterator cuiter = cm.getCodeUnits(chunks, true);
        
        if (!cuiter.hasNext()) {
            debug(this, "Empty CodeUnit Iterator in Function!");
        }
        
        nAddresses = 0;
        nCodeUnits = 0;
        code_units = new LinkedList<CodeUnit>();
        for (CodeUnit cu: cuiter) {
            addrs.add(cu.getAddress());
            nAddresses++;
            
            code_units.add(cu);
            nCodeUnits++;
            
            dmsg = "  ";
            dmsg += "CodeUnit from " + cu.getMinAddress().toString() + " to " + cu.getMaxAddress().toString();
            debug(this, dmsg);
        }
        
        // cast AddressSet class to AddressSetView interface
        allAddresses = (AddressSetView) addrs;
        
        debug(this, "Fn has " + nAddresses + " address(es)");
    
    }

}

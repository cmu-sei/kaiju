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
package kaiju.tools.fnhashclassic;

import ghidra.program.database.code.CodeManager;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.InstructionPrototype;
import ghidra.program.model.lang.Mask;
import ghidra.program.model.lang.OperandType;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.block.CodeBlock;
import ghidra.program.model.symbol.FlowType;
import ghidra.util.task.TaskMonitor;

import java.util.List;
import java.util.ArrayList;

/**
 * an inner class to gather and hold basic block (CodeBlock) data for hashing purposes.
 */
public class BlockHashData {

    public FlowType ft;
    public long numaddr;
    public boolean is_ep; // if this bb is the entry point for the function
    public Address saddr; // start addr
    public Address eaddr; // end addr
    public Address [] bbentries; // entry points (can have more than one???)
    public List<Instruction> insns; // list of the Instructions
    public List<byte []> ebytes; // exact bytes for each instruction
    public List<byte []> pbytes; // PICed bytes for each instruction
    public int num_bytes;

    // CTOR will do all the real work for gathering the data
    public BlockHashData(CodeBlock bb, CodeManager cm, TaskMonitor monitor) throws Exception {
    
        ft = bb.getFlowType();
        numaddr = bb.getNumAddresses();
        long curprogress = monitor.getProgress();
        //is_ep = bb.getMinAddress().equals(ep);
        monitor.setProgress(curprogress + numaddr);
        //debug(msg);
        // iterate over all instructions in the CodeBlock...uh, doesn't seem to
        // be a straightforward way to do that?  Sigh.  The FunctionGraph plugin
        // is doing it, but following that code is non-trivial...looks like I
        // have to walk them manually?
        Address iaddr = bb.getMinAddress();
        saddr = bb.getMinAddress();
        eaddr = bb.getMaxAddress();
        bbentries = bb.getStartAddresses(); // uh, really?  can have multiple entry pts?
        if (bbentries.length != 1) {
        } else if (!bbentries[0].equals(iaddr)) {
        }
        insns = new ArrayList<Instruction>();
        ebytes = new ArrayList<byte []>();
        pbytes = new ArrayList<byte []>();
        while (iaddr.compareTo(eaddr) <= 0 && !monitor.isCancelled()) {
            monitor.setMessage(iaddr.toString());
            // get the Instruction at iaddr:
            Instruction insn = cm.getInstructionAt(iaddr);
            // save it to our internal list of insns for easily revisiting later, maybe?
            insns.add(insn);
            /*
            // Cory noticed a bug w/ trying to figure out if a CodeUnit is an
            // Instruction or Data, neither property seems to be assigned, and
            // this test seems to confirm because every Instruction I'm getting,
            // the corresponding CodeUnit does NOT have that property defined on
            // it:
            CodeUnit cu = cm.getCodeUnitAt(iaddr);
            if (cu.hasProperty(CodeUnit.INSTRUCTION_PROPERTY)) {
            debug("iaddr prop insn @ " + iaddr.toString());
            } else if (cu.hasProperty(CodeUnit.DEFINED_DATA_PROPERTY)) {
            debug("iaddr prop data @ " + iaddr.toString());
            } else {
            debug("iaddr no prop data or insn @ " + iaddr.toString());
            }
            */
            byte [] bytes = insn.getBytes();
            ebytes.add(bytes);
            num_bytes += bytes.length;
            byte [] picbytes = insn.getBytes(); // need a copy of it
            InstructionPrototype insnp = insn.getPrototype();
            //Mask picmask = new MaskImpl(picbytes); // a mask really is just a wrapped byte []?
            //debug(((MaskImpl)picmask).toString());
            int numOperands = insn.getNumOperands();
            ArrayList<Mask> opMasks = new ArrayList<Mask>();
            for (int o=0;o<numOperands;++o) {
                String sep = insn.getSeparator(o);
                // don't want "null" or a trailing comma
                if (o == numOperands-1) {
                    sep = "";
                } else if (sep == null) { 
                    sep = ", ";
                }
                opMasks.add(insnp.getOperandValueMask(o));
                int ot = insn.getOperandType(o);
                boolean picit = OperandType.isCodeReference(ot) ||
                                OperandType.isDataReference(ot) ||
                                OperandType.isAddress(ot) ||
                                OperandType.doesRead(ot) || // implies address according to the docs
                                OperandType.doesWrite(ot) || // implies address according to the docs
                                OperandType.isImmediate(ot) || // maybe? need to check if could be an address too
                                OperandType.isRelative(ot) || // maybe? see above
                                OperandType.isScalar(ot) // maybe? see above
                                ;
                if (picit) {
                    picbytes = opMasks.get(o).complementMask(picbytes,picbytes);
                    // found and reported a bug in complementMask (fixed in 9.0.1 or
                    // 9.0.2 so going back to the code above which now works as
                    // expected):
                    //   https://github.com/NationalSecurityAgency/ghidra/issues/187
                    // where it ORs the complemented & ANDed mask into the result
                    // bytes, so using same src and result as I am makes it a no-op.
                    // Pretty sure it should just write the byte into the results
                    // array...to work around for now I'll create a temp byte array
                    // for the results, zeroed out, which will replace picbytes
                    // correctly then:
                    //byte [] newpicbytes = new byte[picbytes.length]; // seems to be 0 initialized
                    //picbytes = opMasks.get(o).complementMask(picbytes,newpicbytes);

                    //picmask = new MaskImpl(picbytes);
                }
            }
            pbytes.add(picbytes);

            int len = insn.getLength();
            if (len <= 0 || len != bytes.length) {
            //debug("ERROR: insn @ " + iaddr.toString() + " has a bad length: " + len);
            break;
            }
        
            // iterate to get next Instruction address
            iaddr = iaddr.add(insn.getLength()); // Address.add creates a new Address, doesn't modify
        } // end while loop
        
    } // end CTOR

}

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

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import ghidra.framework.options.Options;
import ghidra.program.database.code.CodeManager;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.Undefined;
import ghidra.program.model.lang.InstructionPrototype;
import ghidra.program.model.lang.Mask;
import ghidra.program.model.lang.OperandType;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.UsrException;
import ghidra.util.task.TaskMonitor;
import kaiju.common.KaijuLogger;
import kaiju.util.HexUtils;

/**
 * an inner class to gather and hold CodeUnit data for hashing purposes.
 */
public class UnitHashData implements KaijuLogger {

    //public FlowType ft; // only valid with BlockModel interpretation
    public long numaddr;
    public boolean is_ep; // if this cu is the entry point for the function
    public Address saddr; // start addr
    public Address eaddr; // end addr
    public Address [] cuentries; // entry points (can have more than one???)
    public List<Instruction> insns; // list of the Instructions
    public List<byte []> ebytes; // exact bytes for each instruction
    public List<byte []> pbytes; // PICed bytes for each instruction
    public List<byte []> pmask; // PIC mask - 1 if an address, 0 if other bytes, for YARA signature generation
    public int num_bytes;

    // CTOR will do all the real work for gathering the data
    public UnitHashData(CodeUnit cu, CodeManager cm, TaskMonitor monitor) throws Exception, UsrException {
    
        // determine user's custom options
        Options opt = cu.getProgram().getOptions(Program.ANALYSIS_PROPERTIES);
        int opt_num_insns_in_block = opt.getInt(FnHashOptions.NAME + "." + FnHashOptions.MIN_INSNS_OPTION_NAME, FnHashOptions.MIN_INSNS_OPTION_DEFAULT);
        
        //logger.debug(this, "options are: " + opt_num_insns_in_block);
    
        String msg;
        //ft = cu.getFlowType();
        //numaddr = cu.getNumAddresses();
        long curprogress = monitor.getProgress();
        //is_ep = bb.getMinAddress().equals(ep);
        monitor.setProgress(curprogress + numaddr);
        //msg = "  >> bb @ 0x" + bb.getMinAddress().toString() + "-0x" + bb.getMaxAddress() + ", Entry: " + is_ep + ", Num addr: " + numaddr + ", Flow type: " + ft.toString() + ", Num Dest: " + bb.getNumDestinations(monitor);
        msg = "  >> cu @ 0x" + cu.getMinAddress().toString() + "-0x" + cu.getMaxAddress();
        //debug(msg);
        // iterate over all instructions in the CodeBlock...uh, doesn't seem to
        // be a straightforward way to do that?  Sigh.  The FunctionGraph plugin
        // is doing it, but following that code is non-trivial...looks like I
        // have to walk them manually?
        Address iaddr = cu.getMinAddress();
        // TODO: may have to fix this by passing in fep as parameter
        //is_ep = cu.getMinAddress().equals(fep);
        saddr = cu.getMinAddress();
        eaddr = cu.getMaxAddress();
        //cuentries = cu.getStartAddresses(); // uh, really?  can have multiple entry pts?
        //if (cuentries.length != 1) {
        //  msg = "ERROR: cu @ " + iaddr.toString() + " has multiple entry points: " + cuentries.length;
        // debug(msg);
        //} else if (!cuentries[0].equals(iaddr)) {
        //  msg = "ERROR: cu @ " + iaddr.toString() + " has entry point different from min addr: " + cuentries[0].toString();
        //  debug(msg);
        //}
        insns = new ArrayList<Instruction>();
        ebytes = new ArrayList<byte []>();
        pbytes = new ArrayList<byte []>();
        pmask = new ArrayList<byte []>();
      
        while (iaddr.compareTo(eaddr) <= 0 && !monitor.isCancelled()) {
            monitor.setMessage(iaddr.toString());
            Instruction insn = null;
            if ( cu instanceof Instruction ) {
                // get the Instruction at iaddr:
                insn = cm.getInstructionAt(iaddr);
            } else if (cu instanceof Data ) {
                // do data; likely interpretation error?
                Data dataUnit = cm.getDataAt(iaddr);
                //debug("Got DATA bytes!");
                // go to next codeUnit? No... this just stops processing of the function
                // truncating it!
                //break;
                msg = "Unexpected Data!";
                throw new UsrException(msg);
            } else if (cu instanceof Undefined) {
                // do Undefined; likely interpretation error?
                Data undefinedUnit = cm.getUndefinedAt(iaddr);
                //debug("Got UNDEFINED data bytes!");
                // go to next codeUnit? No... this just stops processing of the function
                // truncating it!
                //break;
                msg = "Unexpected Data!";
                throw new UsrException(msg);
            }
            // save it to our internal list of insns for easily revisiting later, maybe?
            insns.add(insn);
        
        
            // REGRESSION TESTING
            //debug("Mnemonic: " + insn.getMnemonicString());
            //debug("Category: " + insn_get_generic_category(insn, "x86"));

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
            byte[] bytes = insn.getBytes();
            ebytes.add(bytes);
            num_bytes += bytes.length;
            byte[] picbytes = insn.getBytes(); // need a copy of exact bytes
            byte[] yaramask = insn.getBytes(); // set all the bits to 1
            Arrays.fill(yaramask, 0, yaramask.length, (byte)255);
            
            InstructionPrototype insnp = insn.getPrototype();
            // No direct way to just get a default string of the whole Instruction?  Really???
            msg = iaddr.toString() + " " + insn.getMnemonicString() + " ";
            //Mask picmask = new MaskImpl(picbytes); // a mask really is just a wrapped byte []?
            //debug(((MaskImpl)picmask).toString());
            int numOperands = insn.getNumOperands();
            ArrayList<Mask> opMasks = new ArrayList<Mask>();
            for (int o=0;o<numOperands;++o) {
                msg += insn.getDefaultOperandRepresentation(o);
                String sep = insn.getSeparator(o);
                // don't want "null" or a trailing comma
                if (o == numOperands-1) {
                    sep = "";
                } else if (sep == null) { 
                    sep = ", ";
                }
                msg += sep;
                
                // stores the mask that identifies the bytes of this operand in the instruction
                Mask opMask = insnp.getOperandValueMask(o);
                opMasks.add(opMask);
                
                int ot = insn.getOperandType(o);
                // the different operand checks available are documented at:
                // https://ghidra.re/ghidra_docs/api/ghidra/program/model/lang/OperandType.html
                boolean picit = OperandType.isAddress(ot) ||
                                OperandType.isCodeReference(ot) ||
                                OperandType.isDataReference(ot) ||
                                OperandType.doesRead(ot) || // implies address according to the docs
                                OperandType.doesWrite(ot) || // implies address according to the docs
                                //OperandType.isImmediate(ot) || // maybe? need to check if could be an address too
                                //OperandType.isRelative(ot) || // maybe? see above
                                OperandType.isScalarAsAddress(ot) // maybe? see above
                                ;
                // need to have additional checks about addresses/references inside
                // current chunk vs outside to really decide to PIC or not, but can
                // ignore for now.  Also, there seem to be some bits being set for
                // things like [ESI + 4] operands that aren't any of the above that
                // I think I might want to PIC out too perhaps?  And for that the
                // mask value is AFAICT for both the register and the offset, not
                // sure if I can get at either individually, which is a "bit" of a
                // bummer (pardon the pun)
                
                // TODO: should really do relative checks, something like:
                // if possible_addr < fn.min_addr or possible_addr > fn.max_addr then PICd_addr = false
                //   and
                // alternate: check if possible_addr is in list of all addrs associated with function
                // hack for constants:
                // if possible_addr < 0x1000 then really_addr = false
                if (OperandType.isByte(ot)) {
                    if (insn.getByte(o) <= 0xFF) {
                        picit = false;
                    }
                }
                else if (OperandType.isWord(ot)) {
                    if (insn.getShort(o) < 0x1000) {
                        picit = false;
                    }
                }
                else if (OperandType.isQuadWord(ot)) {
                    if (insn.getLong(o) < 0x1000) {
                        picit = false;
                    }
                }
                else {
                    if (insn.getUnsignedInt(o) < 0x1000) {
                        picit = false;
                    }
                }
                
                
                
                // for yara, need to document where to put ?? for addresses vs legit null bytes.
                // store a FF byte if an address, and 00 byte for all else

        // ALPHA: the yara masks are broken still...
                if (picit) {
                    
                    // TODO: the bytes are not necessarily all zero,
                    // just the parts of the instruction associated with an address
                    
                    // since opMask marks bytes of operand with 1s,
                    // we complement and apply mask to get 0s in this
                    // operand's place in picbytes
                    opMask.complementMask(picbytes, picbytes);
                    
                    //Arrays.fill(yaramask, 0, picbytes.length, (byte)255);
                    opMask.complementMask(yaramask, yaramask);
                }
            }
        
            // print the bytes too?
            msg += " ; Bytes: ";
            msg += HexUtils.byteArrayToHexString(bytes," ");
            //debug(msg);
            // TODO: test to see if this instance of getBytes() needs StandardCharsets.UTF_8 set as arg
            //debug("     mnemMask: " + HexUtils.byteArrayToHexString(mnemMask.getBytes()," "));
            //debug(opmstr);
            //debug(otstr);
            //picbytes = picmask.applyMask(bytes,picbytes);
            //debug("     picbytes: " + HexUtils.byteArrayToHexString(picbytes," "));

            pbytes.add(picbytes);
            pmask.add(yaramask);

            int len = insn.getLength();
            if (len <= 0 || len != bytes.length) {
                //debug("ERROR: insn @ " + iaddr.toString() + " has a bad length: " + len);
                break;
            }
            iaddr = iaddr.add(insn.getLength()); // Address.add creates a new Address, doesn't modify
        } // end while loop
        
    } // end CTOR
    
} // end Class UnitHashData

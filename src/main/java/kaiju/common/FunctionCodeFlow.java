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
package kaiju.common;

import ghidra.app.services.BlockModelService;
import ghidra.framework.plugintool.ServiceProviderStub;
import ghidra.program.database.ProgramDB;
import ghidra.program.database.code.CodeManager;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Program;
import ghidra.program.model.block.CodeBlock;
import ghidra.program.model.block.CodeBlockIterator;
import ghidra.program.model.block.CodeBlockModel;
import ghidra.program.model.block.CodeBlockReferenceIterator;
import ghidra.program.model.block.SimpleBlockModel;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

import java.util.List;

import kaiju.common.FunctionUtils;
import kaiju.util.MultiLogger;

/**
 * A class to represent the control flow graph (CFG) of a function in a
 * given program.
 * CodeUnits represent either instructions or data; a CodeBlock is roughly
 * equivalent to a basic block.
 * The default scheme for ordering these bytes is at the BasicBlock level
 * ordered by Address. There is an option for ordering the bytes by
 * control flow.
 * @param function A function in a program
 * @param currentProgram A program to analyze
 * @param monitor A TaskMonitor object to track progress
 * @see https://ghidra.re/ghidra_docs/api/ghidra/program/model/listing/CodeUnit.html
 */
public class FunctionCodeFlow {

    private AddressSetView chunks;
    private CodeBlockModel bb_model;
    // by default Ghidra iterates on CodeBlocks in address order,
    // so assume basic_blocks in address order
    private List<CodeBlock> basic_blocks;
    private List<Instruction> bb_insns;
    private int nBlocks;

    public FunctionCodeFlow(Function function, Program currentProgram, TaskMonitor monitor) throws CancelledException {
    
        if (function == null) {
            throw new CancelledException();
        }

        // We first do some basic set up to pick BlockModel.
        // could/should perhaps just do this based in isRunningHeadless() answer?
        try {
            ServiceProviderStub sps = new ServiceProviderStub();
            BlockModelService blockModelService = sps.getService(BlockModelService.class);
            try {
                // We explicitly call for SimpleBlockModel, because the default
                // active block model seems to be BasicBlockModel.
                // The SimpleBlockModel ends blocks at a CALL where the BasicBlockModel doesn't.
                // Instructions in address order.
                // Read more about SimpleBlockModel at:
                // https://ghidra.re/ghidra_docs/api/ghidra/program/model/block/SimpleBlockModel.html
                bb_model = blockModelService.getNewModelByName(blockModelService.SIMPLE_BLOCK_MODEL_NAME);
            } catch (ghidra.util.exception.NotFoundException nfe) {
                throw new CancelledException();
            }

        } catch (NullPointerException npe) {
            // We explicitly call SimpleBlockModel rather than BasicBlockModel
            // for same reasons as above.
            bb_model = new SimpleBlockModel(currentProgram, false);
        }
        
        // no real simple API to get Chunks/BasicBlocks(CodeBlocks)/Instructions
        // from a Function, well except for the "chunks" I suppose that come
        // back as the body of the function as an AddressSetView:
        chunks = function.getBody(); 
        Address fep = function.getEntryPoint();
        
        CodeBlockIterator bbiter = null;
        try {
            // get an iterator over the CodeBlocks (basic blocks, maybe data too?)
            // via the BlockModelService & the function chunks:
            bbiter = bb_model.getCodeBlocksContaining(chunks, monitor);
        } catch (Exception e) {
            // we probably want to do better exception checking and handling later
            throw new CancelledException();
        }
        
        // can now iterate over the basic blocks getting addresses, not sure how
        // to get at instructions "properly" yet...
        for (;bbiter.hasNext();) {
            CodeBlock bb = bbiter.next();
            basic_blocks.add(bb);
        }
        
        for (AddressRange chunk: chunks) {
//             if (chunk.contains(fep)) {
//                 dmsg += "[FnEP] ";
//             }
            // if (chunk.getMinAddress() < ep) { // odd, this doesn't work, and
            // there is no toLong() method?  But there is a compareTo(), which
            // does work:
//             if (chunk.getMinAddress().compareTo(fep) < 0) {
//                 dmsg += "[pre EP] ";
//             }
//             dmsg += "chunk from " + chunk.getMinAddress().toString() + " to " + chunk.getMaxAddress().toString();
            //debug(dmsg);
        }
        
        CodeManager cm = ((ProgramDB)currentProgram).getCodeManager();
        InstructionIterator insn_iter = cm.getInstructions(chunks, true);
        for (;insn_iter.hasNext();) {
            Instruction insn = insn_iter.next();
            bb_insns.add(insn);
        }
    
    }
    
    private List<CodeBlock> computeBasicBlocks(Program program, TaskMonitor monitor) throws CancelledException {
        
        nBlocks = 0;
        CodeBlockIterator bbiter = null;        

        try {
            // get an iterator over the CodeBlocks (basic blocks, maybe data too?)
            // via the BlockModelService & the function chunks:
            // NOTE: following line was working in original GhidraScript
            //BlockModelService blockModelService = state.getTool().getService(BlockModelService.class);
            ServiceProviderStub sps = new ServiceProviderStub();
            BlockModelService blockModelService = sps.getService(BlockModelService.class);
            ////debug("the active block model is: " + blockModelService.getActiveBlockModelName());
            //bbm = blockModelService.getActiveBlockModel();
            // note that the default active block model seems to be the
            // SimpleBlockModel, but just in case that ever changes, I want to
            // explicitly ask for the SimpleBlockModel because it will end a block
            // at a CALL where the BasicBlolckModel does not, and I don't want to
            // be surprised if the default changes for some reason:
            try {
                bb_model = blockModelService.getNewModelByName(blockModelService.SIMPLE_BLOCK_MODEL_NAME);
            } catch (ghidra.util.exception.NotFoundException nfe) {
                // TODO: catch me if you can
            }

        } catch (NullPointerException npe) {
            // Could also create a new model, which seems to be how the
            // FunctionGraph plugin does it, but seems more correct to reuse the one
            // that the service provides:
            //bbm = new BasicBlockModel(currentProgram);
            // and as I discovered from above, the default SimpleBlockModel is
            // actually what I want as it will end a block at a CALL where the
            // BasicBlockModel doesn't (and EXCLUDE externals):
            bb_model = new SimpleBlockModel(program, false);
          
        }
        
        // TODO: probably need to wrap this in try/catch and throw an error if cancelled
        bbiter = bb_model.getCodeBlocksContaining(chunks, monitor);
        
        // can now iterate over the basic blocks getting addresses, not sure how
        // to get at instructions "properly" yet...
        for (;bbiter.hasNext();) {
            nBlocks++;
            CodeBlock bb = bbiter.next();

            basic_blocks.add(bb); // save this off for later

            //dumpBB(bb);
        }
        
        return basic_blocks;
    }
    
    public List<CodeBlock> getBasicBlocksInAddrOrder() {
        return basic_blocks;
    }
    
    // TODO: actually get control flow order!
    public List<CodeBlock> getBasicBlocksInControlFlowOrder() {
        return basic_blocks;
    }
    
    public int getNumBasicBlocks() {
        return basic_blocks.size();
    }
    
    public List<Instruction> getInstructionsInAddrOrder() {
        return bb_insns;
    }
    
    // TODO: actually get control flow order!
    public List<Instruction> getInstructionsInControlFlowOrder() {
        return bb_insns;
    }
    
}

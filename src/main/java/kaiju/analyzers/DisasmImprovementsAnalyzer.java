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
package kaiju.analyzers;

import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.options.Options;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.address.AddressRangeImpl;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.data.BuiltInDataTypeManager;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.lang.Processor;
import ghidra.program.model.listing.BookmarkManager;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

import java.util.HashSet;

import kaiju.util.MultiLogger;

 /**
 * A Ghidra analyzer pass that improves function partitioning in a program.
 * Previously known as "MakeAlignment".
 * Documentation is at:
 * https://ghidra.re/ghidra_docs/api/ghidra/app/services/AbstractAnalyzer.html
 */
public class DisasmImprovementsAnalyzer extends AbstractAnalyzer {
    public static final boolean doingdebug = true;
    
    private final static String NAME = "CERT Disassembly Improvements";
    private final static String DESCRIPTION = "Improved program partitioning and disassembly algorithm.";
    protected static final String OPTION_NAME_MA_FILE = "Run CERT Disassembly Improvements";
    
    private MultiLogger logger;
    
    public DisasmImprovementsAnalyzer() {

        super(NAME, DESCRIPTION, AnalyzerType.DATA_ANALYZER);

        // Data type propagation is the latest analysis phase. This will run after
        // that because it needs to update functions and data types, see:
        // https://ghidra.re/ghidra_docs/api/ghidra/app/services/AnalysisPriority.html
        setPriority(AnalysisPriority.DATA_TYPE_PROPOGATION.after());

        // Analysis is enabled by default,
        setDefaultEnablement(true);

        setSupportsOneTimeAnalysis();
        
        logger = MultiLogger.getInstance();
    }

    private DataTypeManager dataTypeManager;
    private DataType alignmentType;
    private DataType stringType;
    private Listing listing;
    private Memory memory;
    private AddressSetView allAddresses;
    private AddressSetView undefinedAddresses;
    private TaskMonitor monitor;
    private Program currentProgram;

    // Records of what we've done.
    private AddressSet alignmentAddresses;
    private AddressSet codeAddresses;
    private AddressSet stringAddresses;
    private HashSet<Address> skippedAddresses;

    public enum BlockType {
        CODE, DATA, ALIGNMENT, OTHER
    }

    /** 
     * This analyzer is selected by default to run in the Auto-Analyze feature.
     */
    @Override
    public boolean getDefaultEnablement(final Program program) {

        return true;
    }

    /** 
     * Checks if the program is X86 architecture before running this analyzer.
     * This tool makes some assumptions that are only valid for X86,
     * therefore we do not apply it to any program that is not this architecture.
     */
    @Override
    public boolean canAnalyze(final Program program) {

        // Only analyze 32-bit or less X86 programs. OOAnalyzer can handle nothing else
        final Processor processor = program.getLanguage().getProcessor();
        if (program.getLanguage().getDefaultSpace().getSize() > 32) {
            return false;
        }
        return processor.equals(Processor.findOrPossiblyCreateProcessor("x86"));
    }

    @Override
    public boolean added(final Program program, final AddressSetView set, final TaskMonitor monitor,
            final MessageLog log) throws CancelledException {


        logger.debug(this, "Running the Disassembly Improvements analyzer!");
        this.currentProgram = program;
        this.monitor = monitor;

        if (currentProgram == null) {
            logger.debug(this, "Failed to find currentProgram!");
            System.exit(-1);
        }

        logger.debug(this, currentProgram.toString());

        // I should do something here to ensure that the program being
        // analyzed is for the X86 architecture, since many of my
        // heuristics are really X86 specific.

        listing = currentProgram.getListing();
        memory = currentProgram.getMemory();

        // Find the "Alignment" type in the builtin data type manager.
        dataTypeManager = BuiltInDataTypeManager.getDataTypeManager();
        alignmentType = findGhidraType("Alignment");
        if (alignmentType == null) {
            logger.debug(this, "Unable to find builtin alignment type! Aborting.");
            return false;
        }
        // Find the "string" type in the builtin data type manager.
        stringType = findGhidraType("string");
        if (stringType == null) {
            logger.debug(this, "Unable to find builtin string type! Aborting.");
            return false;
        }

        // currentProgram getminAddress() and getMaxAddress()?
        allAddresses = memory.getAllInitializedAddressSet();

        alignmentAddresses = new AddressSet();
        codeAddresses = new AddressSet();
        stringAddresses = new AddressSet();
        skippedAddresses = new HashSet<Address>();

        int total_changes = 0;
        while (true) {
            int changed = 0;
            logger.debug(this, "Analyzing gaps...");

            undefinedAddresses = this.listing.getUndefinedRanges(allAddresses, false, monitor);
            for (final AddressRange range : undefinedAddresses) {
                changed += analyzeGap(range);
            }
            if (changed == 0)
                break;
            total_changes += changed;
        }

        // Report what we've done (in "ranges" where we can)...
        logger.debug(this, "Took no action at the following addresses: " + skippedAddresses);
        logger.debug(this, "Made alignment in the following ranges: " + alignmentAddresses);
        logger.debug(this, "Made code in the following ranges: " + codeAddresses);
        logger.debug(this, "Speculatively made strings in the following ranges: " + stringAddresses);

        return false;
    }

    /* 
     * Note this gets the Minimum address in a CodeUnit that
     * may correspond to the Address OR _address_ if no CodeUnit is found;
     *  this should not be confused
     * with the getStartAddress() implemented for InstructionBlock:
     * https://ghidra.re/ghidra_docs/api/ghidra/program/model/lang/InstructionBlock.html#getStartAddress()
     */
    private Address getStartAddress(final Address address) {
        final CodeUnit cu = listing.getCodeUnitContaining(address);
        if (cu == null) {
            logger.debug(this, "No CodeUnit for " + address);
	    // Why is this passed back with no error?
	    // When do we want to keep processing when
	    // no CodeUnit is defined with _address_ as
	    // a member?
            return address;
        }
        return cu.getMinAddress();
    }

    private Address getPreviousStartAddress(final Address startAddress) {
        // We can't call getStartAddress here, because previous might not be a valid address.
        //final Address previous = startAddress.subtract(1);
        // from the documentation, it seems more correct to use previous() here than subtract():
        // https://ghidra.re/ghidra_docs/api/ghidra/program/model/address/Address.html#previous()
        final Address previous = startAddress.previous();
        if (previous == null)
            // only happens when startAddress was 0x00 so previous returns null
            // TODO: is there something better to do here?
            return startAddress;
        // Further, getStartAddress will return previous if we failed to find anything.
        final Address previousStart = getStartAddress(previous);
        if (previousStart == previous)
            return startAddress;
        // Otherwise, everything went smoothly.
        return previousStart;
    }

    public int makeAlignment(final Address address) {
        Data alignData;
        try {
            alignData = listing.createData(address, alignmentType);
            final Address minAddr = alignData.getMinAddress();
            final Address maxAddr = alignData.getMaxAddress();
            final AddressRange range = new AddressRangeImpl(minAddr, maxAddr);
            logger.debug(this, "Created alignment at: " + range);
            alignmentAddresses.add(range);
            return 1;
        } catch (final CodeUnitInsertionException e) {
            // Don't report the exception, because we're going to just leave the address alone?
            logger.debug(this, "Failed to make alignment at " + address);
            skippedAddresses.add(address);
            return 0;
        }
    }

    public int makeCode(final Address address) {
        // Making code at a previous gap might have converted this gap to code, so we need to
        // check again to see if this address range is still a gap...
        if (getBlockType(address) == BlockType.CODE)
            return 0;

        // logger.debug(this, "Making code at " + address);
        final ghidra.app.cmd.disassemble.DisassembleCommand disassembleCmd =
                new ghidra.app.cmd.disassemble.DisassembleCommand(address, undefinedAddresses,
                        true);

        disassembleCmd.enableCodeAnalysis(true);
        disassembleCmd.applyTo(currentProgram, monitor);

        // I'm not sure what good the status message is really.
        final String statusMsg = disassembleCmd.getStatusMsg();
        if (statusMsg != null) {
            logger.debug(this, "Disassembly status at " + address + " was: " + disassembleCmd.getStatusMsg());
            skippedAddresses.add(address);
            return 0;
        }

        final AddressSet insnsCreated = disassembleCmd.getDisassembledAddressSet();
        logger.debug(this, "Created instructions at: " + insnsCreated);
        codeAddresses.add(insnsCreated);
        return 1;
    }

    public int makeString(final Address address) {
        Data stringData;
        try {
            stringData = listing.createData(address, stringType);
            final Address minAddr = stringData.getMinAddress();
            final Address maxAddr = stringData.getMaxAddress();
            final AddressRange range = new AddressRangeImpl(minAddr, maxAddr);
            logger.debug(this, "Created string at: " + range);
            currentProgram.getBookmarkManager().setBookmark(address, "string", "KaijuDiasmImprovements", "created a string at this address");
            stringAddresses.add(range);
            return 1;
        } catch (final CodeUnitInsertionException e) {
            // Don't report the exception, because we're going to just leave the address alone?
            logger.debug(this, "Failed to make string at " + address);
            skippedAddresses.add(address);
            return 0;
        }
    }

    // Return the type of the block at address.
    private BlockType getBlockType(final Address address) {
        // Instruction insn = listing.getInstructionContaining(address);
        // if (insn != null)
        final CodeUnit cu = listing.getCodeUnitAt(address);
        // TODO: put cu in Optional container

        if (cu instanceof Instruction)
            return BlockType.CODE;
        // Data data = listing.getDataContaining(address);
        // if (data == null)
        if (cu instanceof Data) {
            final Data tempdata = (Data) cu;
            if (alignmentType == tempdata.getDataType())
                return BlockType.ALIGNMENT;
            return BlockType.DATA;
        } else {
            return BlockType.OTHER;
        }


        // I'm a little surprised that an approach like this didn't work:
        // if (cu.hasProperty(CodeUnit.INSTRUCTION_PROPERTY)) return true;
        // CodeUnit properties are *not* set by the Framework code
        // Use /isinstance/ instead.
    }

    // Return the type of the block immediately before address, skipping over one alignment
    // block if the immediately preceding block is an alignment block.
    private BlockType getPreviousBlockType(final Address address) {
        final Address previous = getPreviousStartAddress(address);
	// TODO: what happens here if (previous == address)?
        final BlockType blockType = getBlockType(previous);
        if (blockType == BlockType.ALIGNMENT) {
            final Address before_alignment = getPreviousStartAddress(previous);
            return getBlockType(before_alignment);
        }
        return blockType;
    }

    // Outstanding bugs in ooex7:
    // 0x0041e4a1 -> 0x004302a0 (but latter was already made into alignment. :-()
    // Lots of unmade functions around 0x417b50 - 0x417cb8
    // Problems with exception handler data structures not made correctly around 0x412a1e
    // Next on todo list is to handle the very-large-gap bug I just fixed in ROSE.

    public int analyzeGap(final AddressRange range) {
        // logger.debug(this, "Undefined bytes at " + range);
        final Address minAddr = range.getMinAddress();
        
        // If we've already processed this address, don't try again.
        if (skippedAddresses.contains(minAddr))
            return 0;

        // logger.debug(this, "Analyzing gap: " + range + " with block type " + getBlockType(minAddr));

        // Upgrade the byte to an integer because types are signed in Java.
        int b = 0;
        try {
            b = memory.getByte(minAddr) & 0xFF;
        } catch (final MemoryAccessException e) {
            e.printStackTrace();
            return 0;
        }

        // Address previous = minAddr.subtract(1);

        final BlockType previousBlockType = getPreviousBlockType(minAddr);
        switch (previousBlockType) {
            case CODE:
                if (b == 0xCC)
                    return makeAlignment(minAddr);
                else
                    return makeCode(minAddr);
            case DATA:
                if (b == 0x00)
                    return makeAlignment(minAddr);
                break;
            case ALIGNMENT:
                logger.debug(this, "I'm a little surprised to find alignment at " + minAddr);
                break;
            case OTHER:
                logger.debug(this, "I'm a little surprised to find other at " + minAddr);
                break;
        }

        logger.debug(this, "Skipping address: " + minAddr);
        skippedAddresses.add(minAddr);
        return 0;
    }

    private DataType findGhidraType(final String name) {
        DataType dt = dataTypeManager.getDataType(CategoryPath.ROOT, name);
        if (dt == null) {
            dt = dataTypeManager.getDataType(CategoryPath.ROOT, name);
            if (dt != null) {
                dt = dt.clone(dataTypeManager);
            }
        }
        return dt;
    }


}

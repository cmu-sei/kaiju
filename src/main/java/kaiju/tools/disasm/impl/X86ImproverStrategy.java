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
package kaiju.tools.disasm.impl;

import java.util.Arrays;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.address.AddressRangeImpl;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.listing.Bookmark;
import ghidra.program.model.listing.BookmarkManager;
import ghidra.util.task.TaskMonitor;

import kaiju.tools.disasm.DisasmStrategy;
import kaiju.tools.disasm.GhidraTypeUtilities;
import kaiju.tools.disasm.GhidraTypeUtilities.BlockType;
import kaiju.util.Pair;

/**
 * Implementation of DisasmStrategy, specialized for x86 architecture.
 * Makes use of the "Strategy" design pattern:
 * https://howtodoinjava.com/design-patterns/behavioral/strategy-design-pattern/
 */
public class X86ImproverStrategy implements DisasmStrategy {

    private Program currentProgram;
    private TaskMonitor monitor;
    private Memory memory;
    private Listing listing;
    private BookmarkManager bookmarkManager;

    public X86ImproverStrategy(Program currentProgram, TaskMonitor monitor) {
        this.currentProgram = currentProgram;
        this.monitor = monitor;
        memory = currentProgram.getMemory();
        listing = currentProgram.getListing();
        bookmarkManager = currentProgram.getBookmarkManager();
    }

    private Pair<AddressRange, Integer>
        makeX86Alignment(Listing listing, final AddressRange range, TaskMonitor monitor) {
        // Length is the length of the gap, not necessarily the length that we want to
        // turn into alignment.  We should only make alignment from matching CC or zero
        // bytes.

        // Get the initial byte and ensure that it is 0x00 or 0xCC.
        final Address minAddr = range.getMinAddress();
        int initialByte = 0;
        try {
            initialByte = memory.getByte(minAddr) & 0xFF;
        }
        catch (final MemoryAccessException e) {
            return new Pair<AddressRange, Integer>(range, 0);
        }
        if (initialByte != 0x00 && initialByte != 0xCC) {
            return new Pair<AddressRange, Integer>(range, 0);
        }

        // Count how many adjacent bytes are also 0x00 or 0xCC.
        Address nextAddr;
        int alignLength = 0;
        while (alignLength < range.getLength()) {
            try {
                nextAddr = minAddr.add(alignLength);
                if ((memory.getByte(nextAddr) & 0xFF) != initialByte) break;
            }
            catch (final MemoryAccessException e) {
                // If we run past the end of memory,
                break;
            }
            alignLength += 1;
        }

        // Make alignment just for the bytes that are 0x00 or 0xCC.
        return makeAlignment(listing, range, alignLength, monitor);
    }

    // Returns addresses handled (min, max) and whether anything was changed.
    public Pair<AddressRange, Integer> analyzePartialGap(final AddressRange range) {
        // debug(this, "Undefined bytes at " + range);
        final Address minAddr = range.getMinAddress();

        // If we've already processed this address, don't try again.
        //if (skippedAddresses.contains(minAddr))
        //    return 0;

        // debug(this, "Analyzing gap: " + range + " with block type " + getBlockType(minAddr));

        // Look at the next byte.
        int byteLookAhead = 0;
        try {
            byteLookAhead = memory.getByte(minAddr) & 0xFF;
        } catch (final MemoryAccessException e) {
            e.printStackTrace();
            return new Pair<AddressRange, Integer>(range, 0);
        }

        // Look at the next four bytes.
        int wordLookAhead = 0xFF;
        try {
            wordLookAhead = memory.getInt(minAddr) & 0xFFFFFFF;
        } catch (final MemoryAccessException e) {
            wordLookAhead = 0xFF;
        }

        // Address previous = minAddr.subtract(1);

        final BlockType previousBlockType = GhidraTypeUtilities.getPreviousBlockType(currentProgram, minAddr);
        //debug(this, "Previous type was " +  previousBlockType);
        switch (previousBlockType) {
            case CODE:
                if (byteLookAhead == 0xCC) {
                    return makeX86Alignment(listing, range, monitor);
                }
                else if (wordLookAhead == 0) {
                    return makeX86Alignment(listing, range, monitor);
                }
                else {
                    // Make sure the previous block did not end with a disassembly
                    // failure.  If it did, we probably do not want to make more code at
                    // that location.
                    Bookmark[] bookmarks = bookmarkManager.getBookmarks(minAddr);

                    boolean hasDisassemblyError = Arrays.stream(bookmarks)
                        .anyMatch(bookmark -> bookmark.getCategory().equals("Bad Instruction") && bookmark.getTypeString().equals("Error"));

                    if (hasDisassemblyError) {
                        //debug(this, "Disassembly error at " + minAddr + "; making alignment instead of code.");
                        return makeX86Alignment(listing, range, monitor);
                    }
                    else {
                        debug(this, "Calling make code at " + range);
                        return makeCode(currentProgram, listing, range, monitor);
                    }
                }
            case DATA:
                // BUG! If there's a reference to this address, it is probably NOT alignment!
                if (byteLookAhead == 0)
                    return makeX86Alignment(listing, range, monitor);
                break;
            case ALIGNMENT:
                debug(this, "I'm a little surprised to find alignment at " + minAddr);
                break;
            case OTHER:
                debug(this, "I'm a little surprised to find other at " + minAddr);
                break;
        }

        //debug(this, "Skipping address: " + minAddr);
        return new Pair<AddressRange, Integer>(range, 0);
    }

    public Pair<AddressRange, Integer> analyzeGap(final AddressRange range) {
        AddressRangeImpl newRange = new AddressRangeImpl(range);
        Integer changed = 0;
        while (true) {
            Pair<AddressRange, Integer> completed = analyzePartialGap(newRange);
            // If we changed something, remember that.
            if (completed.second == 1) {
                changed = 1;
            }
            else {
                break;
            }

            // If this action consumed the entire gap, we're done.
            Address maxCompleted = completed.first.getMaxAddress();
            Address maxGap = range.getMaxAddress();
            if (maxCompleted.equals(maxGap)) {
                break;
            }
            // Otherwise, try again after whatever we just created.
            else {
                Address nextAddr = maxCompleted.add(1);
                newRange = new AddressRangeImpl(nextAddr, maxGap);
                final BlockType previousBlockType = GhidraTypeUtilities.getPreviousBlockType(currentProgram, nextAddr);
                debug(this, "Trying again at " + newRange + ", previous type is " + previousBlockType);
            }
        }
        return new Pair<AddressRange, Integer>(range, changed);
    }

}

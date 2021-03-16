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
package kaiju.fnhash.context.impl;

import ghidra.program.model.listing.CodeUnit;

import kaiju.fnhash.context.InsnCategorizer;

/**
 * Implementation of InsnCategorizer, specialized for MIPS architecture.
 * Makes use of the "Strategy" design pattern:
 * https://howtodoinjava.com/design-patterns/behavioral/strategy-design-pattern/
 */
public class MipsStrategy implements InsnCategorizer {

    public String[] getValidCategories() {
        return new String[] {
        "BR", // branch instructions and jumps
        "COP", // coprocessor instructions
        "CMP", // comparisons
        "FLT", // floating point instructions
        "I/O", // input/output operations and memory sync
        "LOGIC", // logical operations
        "MATH", // basic arithmetic
        "NOP", // no operation
        "UNCAT", // uncategorized, unknown?
        "SYS", // system interrupts and exceptions
        "TRAP",
        "XFER" // transfer of data to and from memory
        };
    }

    public String getInsnCategory(CodeUnit insn) {
    
        String result = "UNCAT";
    
        // grab the insn mnemonic
        String mnemonic = insn.getMnemonicString().toLowerCase();
        
        // MIPS ISA:
        // https://www.dsi.unive.it/~gasparetto/materials/MIPS_Instruction_Set.pdf
        // https://www.cs.cmu.edu/afs/cs/academic/class/15740-f97/public/doc/mips-isa.pdf
        
        // check the instructions by running mnemonic thru regexes.
        // TODO: this is *super* error prone, how can we do it better?
        if (mnemonic.matches("abs.*")) {result = "FLT";}
        else if (mnemonic.matches("add\\..*")) {result = "FLT";}
        else if (mnemonic.matches("add.*")) {result = "MATH";}
        else if (mnemonic.matches("and.*")) {result = "LOGIC";}
        else if (mnemonic.matches("bc1.*")) {result = "FLT";}
        else if (mnemonic.matches("break.*")) {result = "SYS";} // set a breakpoint for interrupt
        else if (mnemonic.matches("b.*")) {result = "BR";}
        else if (mnemonic.matches("ceil.*")) {result = "FLT";}
        else if (mnemonic.matches("CEIL.*")) {result = "FLT";}
        else if (mnemonic.matches("cfc.*")) {result = "FLT";}
        else if (mnemonic.matches("ctc.*")) {result = "FLT";}
        else if (mnemonic.matches("cvt.*")) {result = "FLT";}
        else if (mnemonic.matches("C\\.cond.*")) {result = "FLT";}
        else if (mnemonic.matches("cop.*")) {result = "I/O";} // coprocessor instructions, should be own category?
        else if (mnemonic.matches("dadd.*")) {result = "MATH";}
        else if (mnemonic.matches("ddiv.*")) {result = "MATH";}
        else if (mnemonic.matches("dm.*")) {result = "FLT";}
        else if (mnemonic.matches("div\\..*")) {result = "FLT";}
        else if (mnemonic.matches("div.*")) {result = "MATH";}
        else if (mnemonic.matches("dmul.*")) {result = "MATH";}
        else if (mnemonic.matches("dsll.*")) {result = "LOGIC";}
        else if (mnemonic.matches("dsr.*")) {result = "LOGIC";}
        else if (mnemonic.matches("dsub.*")) {result = "MATH";}
        else if (mnemonic.matches("floor.*")) {result = "FLT";}
        else if (mnemonic.matches("FLOOR.*")) {result = "FLT";}
        else if (mnemonic.matches("j.*")) {result = "BR";}
        else if (mnemonic.matches("ldc1.*")) {result = "FLT";}
        else if (mnemonic.matches("ldxc1.*")) {result = "FLT";}
        else if (mnemonic.matches("lwc1.*")) {result = "FLT";}
        else if (mnemonic.matches("lwxc1.*")) {result = "FLT";}
        else if (mnemonic.matches("l.*")) {result = "XFER";}
        else if (mnemonic.matches("madd.*")) {result = "FLT";}
        else if (mnemonic.matches("mfc1.*")) {result = "FLT";}
        else if (mnemonic.matches("mfhi.*")) {result = "XFER";}
        else if (mnemonic.matches("mflo.*")) {result = "XFER";}
        else if (mnemonic.matches("mov\\..*")) {result = "FLT";}
        else if (mnemonic.matches("movf.*")) {result = "FLT";}
        else if (mnemonic.matches("movn.*")) {result = "FLT";}
        else if (mnemonic.matches("movt.*")) {result = "FLT";}
        else if (mnemonic.matches("movz.*")) {result = "FLT";}
        else if (mnemonic.matches("mov.*")) {result = "XFER";}
        else if (mnemonic.matches("msub.*")) {result = "FLT";}
        else if (mnemonic.matches("mtc1.*")) {result = "FLT";}
        else if (mnemonic.matches("mthi.*")) {result = "XFER";}
        else if (mnemonic.matches("mtlo.*")) {result = "XFER";}
        else if (mnemonic.matches("mul\\..*")) {result = "FLT";}
        else if (mnemonic.matches("mul.*")) {result = "MATH";}
        else if (mnemonic.matches("neg.*")) {result = "FLT";}
        else if (mnemonic.matches("nmadd.*")) {result = "FLT";}
        else if (mnemonic.matches("nmsub.*")) {result = "FLT";}
        else if (mnemonic.matches("nor.*")) {result = "LOGIC";}
        else if (mnemonic.matches("or.*")) {result = "LOGIC";}
        else if (mnemonic.matches("prefx.*")) {result = "FLT";}
        else if (mnemonic.matches("pref.*")) {result = "XFER";} // prefetch, what's the right category?
        else if (mnemonic.matches("recip.*")) {result = "FLT";}
        else if (mnemonic.matches("round.*")) {result = "FLT";}
        else if (mnemonic.matches("rsqrt.*")) {result = "FLT";}
        else if (mnemonic.matches("sb.*")) {result = "XFER";}
        else if (mnemonic.matches("sc.*")) {result = "XFER";}
        else if (mnemonic.matches("sdc1.*")) {result = "FLT";}
        else if (mnemonic.matches("sdxc1.*")) {result = "FLT";}
        else if (mnemonic.matches("sd.*")) {result = "XFER";}
        else if (mnemonic.matches("sh.*")) {result = "XFER";}
        else if (mnemonic.matches("sll.*")) {result = "LOGIC";}
        else if (mnemonic.matches("slt.*")) {result = "CMP";}
        else if (mnemonic.matches("sra.*")) {result = "LOGIC";}
        else if (mnemonic.matches("srl.*")) {result = "LOGIC";}
        else if (mnemonic.matches("sqrt.*")) {result = "FLT";}
        else if (mnemonic.matches("sub\\..*")) {result = "FLT";}
        else if (mnemonic.matches("sub.*")) {result = "MATH";}
        else if (mnemonic.matches("swc1.*")) {result = "FLT";}
        else if (mnemonic.matches("swxc1.*")) {result = "FLT";}
        else if (mnemonic.matches("sw.*")) {result = "XFER";}
        else if (mnemonic.matches("sync.*")) {result = "I/O";} // sync to shared memory between coprocessors
        else if (mnemonic.matches("syscall.*")) {result = "SYS";}
        else if (mnemonic.matches("trunc.*")) {result = "FLT";}
        else if (mnemonic.matches("t.*")) {result = "TRAP";}
        else if (mnemonic.matches("xor.*")) {result = "LOGIC";}
        
        return result;
    
    }
}

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
 * Implementation of InsnCategorizer, specialized for PowerPC architecture.
 * Makes use of the "Strategy" design pattern:
 * https://howtodoinjava.com/design-patterns/behavioral/strategy-design-pattern/
 */
public class PpcStrategy implements InsnCategorizer {

    public String[] getValidCategories() {
        return new String[] {
        "BR", // branch instructions
        "CMP", // comparisons
        "FLT", // floating point instructions
        "FPP", // fixed point processor instructions
        "I/O", // input/output operations and memory sync
        "LOGIC", // logical operations
        "MATH", // basic arithmetic
        "NOP", // no operation
        "SIMD", // parallelization and vector operations
        "SYS", // system interrupts
        "TRAP", // traps
        "UNCAT", // uncategorized, unknown?
        "XFER" // transfer of data to and from memory
        };
    }

    public String getInsnCategory(CodeUnit insn) {
    
        String result = "UNCAT";
    
        // grab the insn mnemonic
        String mnemonic = insn.getMnemonicString().toLowerCase();
        
        // we use the PPC ISA manual here, and categorize based on how manual lists them (e.g., which chapter/section)
        // a given instruction is introduced in
        // -- "PowerPC User Instruction Set Architecture", Book 1, Version 2.01, Sept 2003
        // http://math-atlas.sourceforge.net/devel/assembly/ppc_isa.pdf
        
        // check the instructions by running mnemonic thru regexes.
        // TODO: this is *super* error prone, how can we do it better?
        if (mnemonic.matches("add.*")) {result = "MATH";} // fixed point arithmetic, see pg 49
        else if (mnemonic.matches("and.*")) {result = "LOGIC";} // fixed point logical, see pg 62
        else if (mnemonic.matches("a.*")) {result = "MATH";} // POWER fixed point arithmetic, see pg 49-51 (a, ao, ai, ...)
        else if (mnemonic.matches("b.*")) {result = "BR";} // all the branch insns seem to start with b, see pg 23-24
        else if (mnemonic.matches("ca.*")) {result = "MATH";} // POWER fixed point arithmetic, see pg 49 (cau, cax, ...)
        else if (mnemonic.matches("cmp.*")) {result = "CMP";} // fixed point comparisons, see pg 58
        else if (mnemonic.matches("cnt.*")) {result = "LOGIC";} // fixed point logical counts, see pg 67
        else if (mnemonic.matches("c.*")) {result = "BR";} // conditional logic, see pg 26-27
        else if (mnemonic.matches("dcb.*")) {result = "I/O";} // cache commands, is I/O correct?
        else if (mnemonic.matches("div.*")) {result = "MATH";} // fixed point arithmetic, see pg 49
        else if (mnemonic.matches("ds.*")) {result = "I/O";} // user-level cache
        else if (mnemonic.matches("eieio")) {result = "I/O";}
        else if (mnemonic.matches("eqv.*")) {result = "LOGIC";} // fixed point logical, see pg 65
        else if (mnemonic.matches("ext.*")) {result = "LOGIC";} // fixed point logical, see pg 66
        else if (mnemonic.matches("f.*")) {result = "FLT";} // floating point move instructions, see pg 104
        else if (mnemonic.matches("icbi")) {result = "I/O";} // cache commands, is I/O correct?
        else if (mnemonic.matches("isync")) {result = "I/O";}
        else if (mnemonic.matches("lwarx")) {result = "I/O";}
        else if (mnemonic.matches("lf.*")) {result = "FLT";} // floating point load instructions, pg 98
        else if (mnemonic.matches("lv.*")) {result = "SIMD";} // vector loads
        else if (mnemonic.matches("l.*")) {result = "FPP";} // fixed point load instructions, pg 32
        else if (mnemonic.matches("mcrf")) {result = "BR";} // conditional move, pg 28
        else if (mnemonic.matches("mcrfs")) {result = "FLT";} // floating conditional move, pg 114
        else if (mnemonic.matches("mcrxr")) {result = "XFER";} // deprecated move, pg 131
        else if (mnemonic.matches("mfcr")) {result = "XFER";}
        else if (mnemonic.matches("mfmsr")) {result = "XFER";}
        else if (mnemonic.matches("mfspr")) {result = "XFER";}
        else if (mnemonic.matches("mftb")) {result = "XFER";}
        else if (mnemonic.matches("mffs")) {result = "FLT";} // floating conditional move, pg 114
        else if (mnemonic.matches("mul.*")) {result = "MATH";} // fixed point arithmetic, see pg 49
        else if (mnemonic.matches("mtcrf")) {result = "XFER";}
        else if (mnemonic.matches("mtmsr")) {result = "XFER";}
        else if (mnemonic.matches("mtspr")) {result = "XFER";}
        else if (mnemonic.matches("mtfs.*")) {result = "FLT";} // floating conditional move, pg 114
        else if (mnemonic.matches("m[tf]s.*")) {result = "FLT";} // floating conditional move, pg 114
        else if (mnemonic.matches("m[tf].*")) {result = "XFER";} // move to/from, see pg 78
        else if (mnemonic.matches("nand.*")) {result = "LOGIC";} // fixed point logical, see pg 62
        else if (mnemonic.matches("neg.*")) {result = "MATH";} // fixed point arithmetic, see pg 53
        else if (mnemonic.matches("nor.*")) {result = "LOGIC";} // fixed point logical, see pg 62
        else if (mnemonic.matches("nop")) {result = "NOP";}
        else if (mnemonic.matches("not")) {result = "LOGIC";} // fixed point logical not, see pg 154
        else if (mnemonic.matches("or.*")) {result = "LOGIC";} // fixed point logical, see pg 63
        else if (mnemonic.matches("rfi")) {result = "SYS";} // interrupts, is BR or SYS correct?
        else if (mnemonic.matches("r.*")) {result = "LOGIC";} // fixed point logical rotate, see pg 69; should it be its own category?
        else if (mnemonic.matches("sc")) {result = "BR";} // system call
        else if (mnemonic.matches("stwcx")) {result = "I/O";}
        else if (mnemonic.matches("sync")) {result = "I/O";}
        else if (mnemonic.matches("sf.*")) {result = "MATH";} // POWER fixed point arithmetic, see pg 51
        else if (mnemonic.matches("s[lr].*")) {result = "LOGIC";} // fixed point logical shift left/right, see pg 74
        else if (mnemonic.matches("stf.*")) {result = "FLT";} // floating point store instructions, pg 101
        else if (mnemonic.matches("sub.*")) {result = "MATH";} // fixed point arithmetic, see pg 49
        else if (mnemonic.matches("s.*")) {result = "FPP";} // fixed point store instructions, pg 38
        else if (mnemonic.matches("tlb.*")) {result = "I/O";} // buffer management, is I/O right?
        else if (mnemonic.matches("t.*")) {result = "TRAP";} // fixed point trap, see pg 60
        else if (mnemonic.matches("vxor.*")) {result = "LOGIC";}
        else if (mnemonic.matches("v.*")) {result = "SIMD";} // catch-all since rest of v- instructions seem to be vector things
        else if (mnemonic.matches("xor.*")) {result = "LOGIC";} // fixed point logical, see pg 62
        
        return result;
    
    }
}

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
 * Implementation of InsnCategorizer, specialized for ARM32/64 architecture.
 * Makes use of the "Strategy" design pattern:
 * https://howtodoinjava.com/design-patterns/behavioral/strategy-design-pattern/
 */
public class ArmStrategy implements InsnCategorizer {

    public String[] getValidCategories() {
        return new String[] {
        "BR", // branch and control instructions
        "CMP", // comparisons
        "COP", // coprocessor instructions
        "DATA", // data processing excluding arithmetic (math) and logic operations, mostly bit-level operations?
        "CRYPTO", // cryptographic operations like hashes and ciphers, optional extension of arm architecture
        "FLT", // floating point instructions
        "I/O", // input/output operations and memory sync
        "LOGIC", // logical operations
        "MATH", // basic arithmetic
        "NOP", // no operation
        "REG", // register load and store (why not XFER?)
        "MREG", // multi register load and store, only for ARM32/Thumb32
        "SIMD", // parallelization, optional extension of arm architecture, pg B1-87
        "SYS", // system interrupts and exceptions
        "UNCAT" // uncategorized, unknown?
        };
    }

    public String getInsnCategory(CodeUnit insn) {
    
        String result = "UNCAT";
    
        // grab the insn mnemonic
        String mnemonic = insn.getMnemonicString().toLowerCase();
        
        // we use the ARM ISA manual here, and categorize based on how manual lists them.
        // Instructions and categories are introduced in
        // -- "Arm Instruction Set Reference Guide", 2018
        // https://static.docs.arm.com/100076/0100/arm_instruction_set_reference_guide_100076_0100_00_en.pdf
        // Arm32 instruction reference starts on page C2-156.
        // Note most ARM instructions can have condition codes (EQ, etc) or a set condition code (S) 
        // as part of the insn mnemonic
        //
        // NOTE: this manual does not include older versions of A32 insns (e.g., SMC<-SMI)
        // Older insn categories here: https://github.com/tschoonj/xraylib-web/blob/master/geshi/arm.php
        // Also here:
        //
        // "RealView Compilation Tools Assembler Guide	Version 4.0"
        // ARM and Thumb Instructions
        // http://infocenter.arm.com/help/topic/com.arm.doc.dui0204j/Cihedhif.html
        //
        // "ARM Architecture Reference Manual ARMv7-A and ARMv7-R edition"
        // https://static.docs.arm.com/ddi0406/cd/DDI0406C_d_armv7ar_arm.pdf
        //
        // TODO: A64 & CRYPTO insns (even more reason to make SLEIGH expressions ...)
        // 
        // check the instructions by running mnemonic thru regexes.
        // TODO: this is *super* error prone, how can we do it better?
        // TODO: If kept as regexes, reorder to optimize based on instruction frequencies
        if (mnemonic.matches("ad[cd].*")) {result = "MATH";} // fixed point arithmetic, see pg 49
        else if (mnemonic.matches("adr.*")) {result = "REG";}
        else if (mnemonic.matches("aes.*")) {result = "CRYPTO";} // v8 AES insns
        else if (mnemonic.matches("and.*")) {result = "LOGIC";}
        else if (mnemonic.matches("asr.*")) {result = "REG";} // synonym for MOV
        else if (mnemonic.matches("bcax.*")) {result = "CRYPTO";} // v8 Bit Clear and XOR
        else if (mnemonic.matches("bf[ci].*")) {result = "DATA";}
        else if (mnemonic.matches("bic.*")) {result = "LOGIC";}
        else if (mnemonic.matches("bkpt")) {result = "SYS";} // Not sure if it CAN have Cond. codes?
        else if (mnemonic.matches("blx.*")) {result = "BR";} // Probably redundant
        else if (mnemonic.matches("bl.*")) {result = "BR";} // Probably redundant
        else if (mnemonic.matches("bxj.*")) {result = "BR";} // Also has SYS (Jazelle), but control flow change
        else if (mnemonic.matches("bx.*")) {result = "BR";} // Probably redundant
        else if (mnemonic.matches("b.*")) {result = "BR";} // assume a branch; possesive uneeded in Java
        else if (mnemonic.matches("cb[nz].*")) {result = "BR";} // also a CMP
        else if (mnemonic.matches("cdp.*")) {result = "COP";}
        else if (mnemonic.matches("clrex.*")) {result = "SYS";}
        else if (mnemonic.matches("clz.*")) {result = "LOGIC";}
        else if (mnemonic.matches("cm[pn].*")) {result = "CMP";}    
        else if (mnemonic.matches("cps.*")) {result = "SYS";}    
        else if (mnemonic.matches("cpy.*")) {result = "REG";} // synonym for unconditional MOV (pre-Armv8)    
        else if (mnemonic.matches("crc.*")) {result = "MATH";} // CRC32[C]; maybe CRYPTO? Armv8.1 and later
        else if (mnemonic.matches("csdb.*")) {result = "SYS";} // Consumption of Speculative Data Barrier     
        else if (mnemonic.matches("dbg.*")) {result = "SYS";}  // Can also be NOP when unimplemented on processor
        else if (mnemonic.matches("dcps.")) {result = "SYS";}  // Debug switch[1-3]; No condition codes (likely)    
        else if (mnemonic.matches("dmb.*")) {result = "SYS";}  // Data memory barrier (could be own category?)  
        else if (mnemonic.matches("dsb.*")) {result = "SYS";}  // Data sync barrier (see above)   
        else if (mnemonic.matches("eor3.*")) {result = "CRYPTO";} // v8 SHA3 Three-way Exclusive OR
        else if (mnemonic.matches("eor.*")) {result = "LOGIC";}// Can BR if PC used (deprecated)   
        else if (mnemonic.matches("eret.*")) {result = "SYS";} // Used for virtualiztion (yet another cat?)   
        else if (mnemonic.matches("esb.*")) {result = "SYS";}  // Another barrier insn    
        else if (mnemonic.matches("hltq")) {result = "NOP";} // NOP when Halting debug-mode is disabled    
        else if (mnemonic.matches("hlt")) {result = "SYS";} // supported only in the Armv8 architecture?
        else if (mnemonic.matches("hvc")) {result = "SYS";} // Another hypervisor insn (no CCs)    
        else if (mnemonic.matches("isb.*")) {result = "SYS";} // barrier (flushes insn pipeline)    
        else if (mnemonic.matches("it.*")) {result = "SYS";} // No CCs, just '[it]*'; Not BR as PC not changed?    
        else if (mnemonic.matches("lda.*")) {result = "REG";} // LDAEX as well; SYS effects as well (Armv8 only)
        else if (mnemonic.matches("ldc.*")) {result = "COP";} // LDC2 as well 
        else if (mnemonic.matches("ldm.*")) {result = "MREG";} // BR when loading PC    
        else if (mnemonic.matches("ldr.*")) {result = "REG";} // LDRD/EX (doubleword) as well; BR when PC loaded
        else if (mnemonic.matches("lsl.*")) {result = "REG";} // Another MOV synonym; BR when PC loaded
        else if (mnemonic.matches("lsr.*")) {result = "REG";} // Another MOV synonym; BR when PC loaded
        else if (mnemonic.matches("mcrr.*")) {result = "COP";} // MREG as well    
        else if (mnemonic.matches("mcr.*")) {result = "COP";}    
        else if (mnemonic.matches("mla.*")) {result = "MATH";}
        else if (mnemonic.matches("mls.*")) {result = "MATH";} // Also SIMD/vector   
        else if (mnemonic.matches("movs.*")) {result = "BR";} // p. C2-370, syn for SUBS
        else if (mnemonic.matches("mov.*")) {result = "REG";} // MOVT as well; BR when PC is target
        else if (mnemonic.matches("mrc.*")) {result = "COP";}    
        else if (mnemonic.matches("mrrc.*")) {result = "COP";} // MREG as well    
        else if (mnemonic.matches("mrs.*")) {result = "REG";} // Also COP    
        else if (mnemonic.matches("msr.*")) {result = "REG";} // Also COP    
        else if (mnemonic.matches("mul.*")) {result = "MATH";}    
        else if (mnemonic.matches("mvn.*")) {result = "REG";} // BR when PC is target   
        else if (mnemonic.matches("nop.*")) {result = "NOP";}    
        else if (mnemonic.matches("orn.*")) {result = "LOGIC";}    
        else if (mnemonic.matches("orr.*")) {result = "LOGIC";} // BR when PC used (deprecated)   
        else if (mnemonic.matches("pkhbt.*")) {result = "REG";} // MREG?   
        else if (mnemonic.matches("pkhtb.*")) {result = "REG";} // MREG? (reverse)   
        else if (mnemonic.matches("pl.*")) {result = "SYS";}    // NOP if unimplemented
        else if (mnemonic.matches("pop.*")) {result = "MREG";}  // synonym for LDMIA sp! reglist    
        else if (mnemonic.matches("push.*")) {result = "MREG";} // synonym for STMDB sp!, reglist    
        else if (mnemonic.matches("q.*")) {result = "MATH";} // saturation math instructions    
        else if (mnemonic.matches("rax1.*")) {result = "CRYPTO";} // v8 SHA3 Rotate and Exclusive OR
        else if (mnemonic.matches("rbit.*")) {result = "LOGIC";}    
        else if (mnemonic.matches("rev.*")) {result = "REG";} // LOGIC? REG{16,SH} (half-word reverse order)    
        else if (mnemonic.matches("rfe.*")) {result = "BR";} // unconditional in Armv8/A32 mode    
        else if (mnemonic.matches("ror.*")) {result = "LOGIC";} // synonym for MOV with shifted register ops    
        else if (mnemonic.matches("rrx.*")) {result = "LOGIC";} // synonym for MOV with shifted register ops    
        else if (mnemonic.matches("rs[bc].*")) {result = "MATH";}    
        else if (mnemonic.matches("sa.*")) {result = "MATH";} // funky signed parallel math insns    
        else if (mnemonic.matches("sbc.*")) {result = "MATH";} // BR if PC used in A32 (deprecated)    
        else if (mnemonic.matches("sbfx.*")) {result = "LOGIC";} // 32-bit only instruction    
        else if (mnemonic.matches("sdiv.*")) {result = "MATH";}  // 32-bit only insn (optional on older versions?)
        else if (mnemonic.matches("sel.*")) {result = "REG";} // used with signed parallel insns (i.e. MATH)   
        else if (mnemonic.matches("setend")) {result = "SYS";} // setting the CPSR feels SYS-y to me (no CCs)   
        else if (mnemonic.matches("setpan.*")) {result = "XXX";} // NOP when executed in User mode 
        else if (mnemonic.matches("sev.*")) {result = "SYS";} // SEVL as well; NOP if unimplemented    
        else if (mnemonic.matches("sg")) {result = "SYS";} // secure code branch labeling    
        else if (mnemonic.matches("sha.*")) {result = "CRYPTO";} // v8 SHA family of insn
        else if (mnemonic.matches("sh.*")) {result = "MATH";} // Signed halving parallel math
        else if (mnemonic.matches("sm[34].*")) {result = "CRYPTO";} // v8 Chinese SM3 and SM4 family of insns 
        else if (mnemonic.matches("sm[ci].*")) {result = "SYS";} // SMC was SMI in older A32 spec   
        else if (mnemonic.matches("sm[lmu].*")) {result = "MATH";} // SML (dual, wide) as well
        else if (mnemonic.matches("srs.*")) {result = "REG";} // stores return state (not user mode)   
        else if (mnemonic.matches("ssat.*")) {result = "LOGIC";}    
        else if (mnemonic.matches("ssax.*")) {result = "MATH";}    
        else if (mnemonic.matches("ssub.*")) {result = "MATH";}    
        else if (mnemonic.matches("stc.*")) {result = "COP";}    
        else if (mnemonic.matches("stl.*")) {result = "REG";}    
        else if (mnemonic.matches("stm.*")) {result = "MREG";}    
        else if (mnemonic.matches("str.*")) {result = "REG";}    
        else if (mnemonic.matches("subs.*")) {result = "BR";} // Exception return, (see rfe)    
        else if (mnemonic.matches("sub.*")) {result = "MATH";} // BR if PC is target    
        else if (mnemonic.matches("svc.*")) {result = "BR";} // SuperVisor Call; SYS also likely    
        else if (mnemonic.matches("swi.*")) {result = "SYS";} // Older ARM insn to do Thumb switch
        else if (mnemonic.matches("swp.*")) {result = "REG";} // Deprecated in Armv8    
        else if (mnemonic.matches("sxta.*")) {result = "MATH";}    
        else if (mnemonic.matches("sxt.*")) {result = "LOGIC";}    
        else if (mnemonic.matches("sys.*")) {result = "COP";} // ironically, not a SYS (unless COP->SYS)    
        else if (mnemonic.matches("tb[bh]")) {result = "BR";} // Unconditional    
        else if (mnemonic.matches("teq.*")) {result = "LOGIC";}    
        else if (mnemonic.matches("tst.*")) {result = "LOGIC";}    
        else if (mnemonic.matches("tt.*")) {result = "SYS";}    
        else if (mnemonic.matches("ua.*")) {result = "MATH";}    
        else if (mnemonic.matches("ub.*")) {result = "LOGIC";}    
        else if (mnemonic.matches("udf.*")) {result = "BR";} // UDF is not conditional in A32
        else if (mnemonic.matches("udiv.*")) {result = "MATH";}    
        else if (mnemonic.matches("uh.*")) {result = "MATH";} // TODO: collapse into ua.*    
        else if (mnemonic.matches("um.*")) {result = "MATH";}    
        else if (mnemonic.matches("uq.*")) {result = "MATH";}    
        else if (mnemonic.matches("us.*")) {result = "MATH";}    
        else if (mnemonic.matches("uxt.*")) {result = "LOGIC";}    
        else if (mnemonic.matches("ux.*")) {result = "MATH";}
        else if (mnemonic.matches("v.*")) {result = "SIMD";} // p. 445, C3.1 (also Floating Point... TODO)
        else if (mnemonic.matches("wf[ei].*")) {result = "SYS";} // NOP if not implemented    
        else if (mnemonic.matches("yield.*")) {result = "SYS";} // NOP if not implemented    
        else if (mnemonic.matches("xar.*")) {result = "CRYPTO";} // v8 SHA3 Exclusive OR and Rotate
        
        return result;
    
    }
}

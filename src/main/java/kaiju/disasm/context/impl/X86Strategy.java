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
package kaiju.disasm.context.impl;

import ghidra.program.model.listing.CodeUnit;

import kaiju.disasm.context.InsnCategorizer;

/**
 * Implementation of InsnCategorizer, specialized for x86 architecture.
 * Makes use of the "Strategy" design pattern:
 * https://howtodoinjava.com/design-patterns/behavioral/strategy-design-pattern/
 */
public class X86Strategy implements InsnCategorizer {

    public String[] getValidCategories() {
        return new String[] {
        "BR", // branch instructions
        "CMP", // comparisons
        "CRYPTO", // cryptographic operations like hashes and ciphers
        "FLT", // floating-point operations
        "I/O", // input/output operations
        "LOGIC", // logical operations
        "MATH", // basic arithmetic
        "NOP",  // No Operation (except clock cycles?)
        "SIMD", // parallelization
        "STR", // string handling
        "SYS", // system interrupts
        "UNCAT", // uncategorized, unknown?
        "VMM", // virtualization
        "XFER" // memory transfer
        };
    }

    public String getInsnCategory(CodeUnit insn) {
    
        String result = "UNCAT";
    
        // okay, I think a lot of these comparisons for x86 can be simplified by using the first
        // couple of chars in the mnemonic much of the time, so let's start there:
        String mnemonic = insn.getMnemonicString().toLowerCase();
        
        // check the instructions by running mnemonic thru regexes.
        // TODO: this is *super* error prone, how can we do it better?
        if      (mnemonic.matches("aa.*")) {result = "MATH";}
        else if (mnemonic.matches("ad[cd]")) {result = "MATH";}
        else if (mnemonic.matches("ad.*")) {result = "SIMD";}
        else if (mnemonic.matches("aes.*")) {result = "CRYPTO";}
        else if (mnemonic.matches("andn?")) {result = "LOGIC";}
        else if (mnemonic.matches("an.*")) {result = "SIMD";}
        else if (mnemonic.matches("be.*")) {result = "LOGIC";} // like bextr
        else if (mnemonic.matches("bls.*")) {result = "LOGIC";}
        else if (mnemonic.matches("bl.*")) {result = "SIMD";}
        else if (mnemonic.matches("bsw.*")) {result = "XFER";}
        else if (mnemonic.matches("b[stz].*")) {result = "LOGIC";}
        else if (mnemonic.matches("ca.*")) {result = "BR";} // like call
        else if (mnemonic.matches("c[bdqw].*")) {result = "XFER";} // is XFER right here?
        else if (mnemonic.matches("cmov.*")) {result = "XFER";}
        else if (mnemonic.matches("cmp")) {result = "CMP";}
        else if (mnemonic.matches("cmpx.*")) {result = "XFER";} // is XFER right here?
        else if (mnemonic.matches("cmpp.*")) {result = "SIMD";}
        else if (mnemonic.matches("cmps.*")) {result = "STR";} // there is actually a conflict here w/ CMPSD being STR or SIMD based on operands and there is a CMPSS that is SIMD only...but lets err on the likely more common case I assume, for now
        else if (mnemonic.matches("cld.*")) {result = "STR";} // CLD, let's call that STR related I guess
        else if (mnemonic.matches("cl.*")) {result = "SYS";} // most of the other CL* ones feel like SYS, I think...
        else if (mnemonic.matches("co.*")) {result = "SIMD";}
        else if (mnemonic.matches("cp.*")) {result = "SYS";} // like cpuid, is SYS right here?
        else if (mnemonic.matches("cr.*")) {result = "MATH";} // like crc32, MATH or maybe CRYPTO?
        else if (mnemonic.matches("cv.*")) {result = "SIMD";}
        else if (mnemonic.matches("d[abcdefgh].*")) {result = "MATH";}
        else if (mnemonic.matches("div")) {result = "MATH";}
        else if (mnemonic.matches("d.*")) {result = "SIMD";}
        else if (mnemonic.matches("em.*")) {result = "FLT";} // like emms
        else if (mnemonic.matches("en.*")) {result = "XFER";} // like enter, initially I picked BR, but it's really like (push ebp;sub esp,#) XFER+MATH (see LEAVE too)
        else if (mnemonic.matches("e.*")) {result = "SIMD";} // like extractps
        else if (mnemonic.matches("f.*")) {result = "FLT";}
        else if (mnemonic.matches("hlt")) {result = "SYS";}
        else if (mnemonic.matches("h.*")) {result = "SIMD";}
        else if (mnemonic.matches("i[dm].*")) {result = "MATH";} // like idiv or imul
        else if (mnemonic.matches("in")) {result = "I/O";}
        else if (mnemonic.matches("inc.*")) {result = "MATH";}
        else if (mnemonic.matches("ins[bwd]?")) {result = "I/O";} // or is it STR?
        else if (mnemonic.matches("ins.*")) {result = "SIMD";}
        else if (mnemonic.matches("int.*")) {result = "BR";} // or is it SYS?
        else if (mnemonic.matches("inv.*")) {result = "SYS";}
        else if (mnemonic.matches("ir.*")) {result = "BR";} // like iret, should this be SYS?
        else if (mnemonic.matches("j.*")) {result = "BR";} // various forms of jmp
        else if (mnemonic.matches("la.*")) {result = "XFER";}
        else if (mnemonic.matches("lds.*")) {result = "XFER";}
        else if (mnemonic.matches("ld.*")) {result = "SIMD";}
        else if (mnemonic.matches("lea")) {result = "MATH";}
        else if (mnemonic.matches("le[as].*")) {result = "MATH";} // like les, leave; initially I picked BR but it's really like (mov esp,ebp;pop ebp) XFER+XFER? (see ENTER too)
        else if (mnemonic.matches("lgs")) {result = "XFER";}
        else if (mnemonic.matches("lg.*")) {result = "SYS";} // like lgdt
        else if (mnemonic.matches("le[as].*")) {result = "MATH";}
        else if (mnemonic.matches("l[ilm].*")) {result = "SYS";} // LIDT LLDT LMSW
        else if (mnemonic.matches("lod.*")) {result = "STR";} // like lods
        else if (mnemonic.matches("lo.*")) {result = "BR";} // loops
        else if (mnemonic.matches("lz.*")) {result = "LOGIC";} // lzcnt
        else if (mnemonic.matches("l[fs]s.*")) {result = "XFER";}
        else if (mnemonic.matches("l.*")) {result = "SYS";} // like lsl, ltr
        else if (mnemonic.matches("mov")) {result = "XFER";}
        else if (mnemonic.matches("movs")) {result = "STR";}
        else if (mnemonic.matches("movs[bwdq].*")) {result = "STR";} // note, collision w/ MOVSD between STR & SIMD
        else if (mnemonic.matches("movsx.*")) {result = "XFER";}
        else if (mnemonic.matches("movs.*")) {result = "SIMD";}
        else if (mnemonic.matches("movzx.*")) {result = "XFER";}
        else if (mnemonic.matches("mov.*")) {result = "SIMD";}
        else if (mnemonic.matches("mo.*")) {result = "SYS";} // like monitor
        else if (mnemonic.matches("m[ai].*")) {result = "SIMD";} // like max, min
        else if (mnemonic.matches("mf.*")) {result = "XFER";} // like mfence
        else if (mnemonic.matches("mulx?.*")) {result = "MATH";} // mul and mulx
        else if (mnemonic.matches("mu.*")) {result = "SIMD";}
        else if (mnemonic.matches("m.*")) {result = "SYS";} // like mwait
        else if (mnemonic.matches("neg")) {result = "MATH";}
        else if (mnemonic.matches("nop")) {result = "NOP";}
        else if (mnemonic.matches("not")) {result = "LOGIC";}
        else if (mnemonic.matches("or")) {result = "LOGIC";}
        else if (mnemonic.matches("or.*")) {result = "SIMD";}
        else if (mnemonic.matches("outs?.*")) {result = "I/O";}
        else if (mnemonic.matches("pause")) {result = "SYS";}
        else if (mnemonic.matches("pa.*")) {result = "SIMD";} // most of pa*, but is it all/correct?
        else if (mnemonic.matches("popcnt")) {result = "LOGIC";}
        else if (mnemonic.matches("pop.*")) {result = "XFER";}
        else if (mnemonic.matches("po.*")) {result = "SIMD";} // like por
        else if (mnemonic.matches("pre.*")) {result = "XFER";} // like pre*
        else if (mnemonic.matches("push.*")) {result = "XFER";}
        else if (mnemonic.matches("pdep")) {result = "LOGIC";}
        else if (mnemonic.matches("pext")) {result = "LOGIC";}
        else if (mnemonic.matches("p.*")) {result = "SIMD";} // lots of p* are SIMD, but is that correct?
        else if (mnemonic.matches("ret")) {result = "BR";}
        else if (mnemonic.matches("rsm")) {result = "SYS";}
        else if (mnemonic.matches("r[co][lr]")) {result = "LOGIC";} // RCL/RCR/ROL/ROR
        else if (mnemonic.matches("rd.*")) {result = "SYS";}
        else if (mnemonic.matches("rorx")) {result = "LOGIC";}
        else if (mnemonic.matches("r.*")) {result = "SIMD";}
        else if (mnemonic.matches("s[ah].")) {result = "LOGIC";}
        else if (mnemonic.matches("s..x")) {result = "LOGIC";}
        else if (mnemonic.matches("sa.*")) {result = "XFER";} // SAHF, is XFER right here?
        else if (mnemonic.matches("sb.*")) {result = "MATH";}
        else if (mnemonic.matches("sc.*")) {result = "STR";}
        else if (mnemonic.matches("se.*")) {result = "LOGIC";} // is this right for setcc?
        else if (mnemonic.matches("sf.*")) {result = "XFER";} // is this right for sfence?
        else if (mnemonic.matches("s[gil].*")) {result = "SYS";} // like sgdt, sidt, sldt
        else if (mnemonic.matches("sha.*")) {result = "CRYPTO";} // sha*
        else if (mnemonic.matches("sh[lr]d.*")) {result = "LOGIC";}
        else if (mnemonic.matches("sh.*")) {result = "SIMD";}
        else if (mnemonic.matches("sq.*")) {result = "SIMD";}
        else if (mnemonic.matches("std.*")) {result = "STR";} // STD, same logic for calling this STR as for CLD
        else if (mnemonic.matches("st[ri].*")) {result = "SYS";}
        else if (mnemonic.matches("stm.*")) {result = "FLT";}
        else if (mnemonic.matches("sto.*")) {result = "STR";}
        else if (mnemonic.matches("sub")) {result = "MATH";}
        else if (mnemonic.matches("su.*")) {result = "SIMD";}
        else if (mnemonic.matches("s[wy].*")) {result = "SYS";} // SWAPGS and SYS*
        else if (mnemonic.matches("test")) {result = "CMP";}
        else if (mnemonic.matches("tzcnt")) {result = "LOGIC";}
        else if (mnemonic.matches("ud.*")) {result = "SYS";} // is this right for ud2?
        else if (mnemonic.matches("ver.*")) {result = "SYS";}
        else if (mnemonic.matches("vm[~a].*")) {result = "VMM";}
        else if (mnemonic.matches("v.*")) {result = "SIMD";}
        else if (mnemonic.matches("w.*")) {result = "SYS";}
        else if (mnemonic.matches("xor")) {result = "LOGIC";}
        else if (mnemonic.matches("xchq")) {result = "XFER";}
        else if (mnemonic.matches("xadd")) {result = "MATH";}
        else if (mnemonic.matches("xorp.*")) {result = "SIMD";}
        else if (mnemonic.matches("xlat.*")) {result = "XFER";}
        else if (mnemonic.matches("x.*")) {result = "SYS";}
        
        return result;
    
    }
}

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
package kaiju.fnhash.context;

import ghidra.program.model.listing.CodeUnit;

import kaiju.fnhash.context.InsnCategorizer;
import kaiju.fnhash.context.InvalidStrategyException;
import kaiju.fnhash.context.impl.X86Strategy;
import kaiju.fnhash.context.impl.PpcStrategy;
import kaiju.fnhash.context.impl.MipsStrategy;
import kaiju.fnhash.context.impl.ArmStrategy;

/**
 * A helper class that checks the context of an instruction awaiting categorization
 * for hashing purposes, and selects the appropriate strategy to use.
 * Makes use of the "Strategy" design pattern:
 * https://howtodoinjava.com/design-patterns/behavioral/strategy-design-pattern/
 */
public class InsnContext {

    InsnCategorizer categorizer;

    // sets the strategy so appropriate implementation class is called
    public void setCategorizerStrategy(InsnCategorizer strategy) {
        this.categorizer = strategy;
    }
    
    // convenience function allowing to specify string representation
    // of an architecture rather than a specific class
    public void setCategorizerStrategy(String strategy) throws InvalidStrategyException {
    
        String arch = strategy.toLowerCase();
        
        if (arch.equals("x86")) {
            setCategorizerStrategy(new X86Strategy());
        } else if (arch.equals("powerpc")) {
            setCategorizerStrategy(new PpcStrategy());
        } else if (arch.equals("mips")) {
            setCategorizerStrategy(new MipsStrategy());
        } else if (arch.equals("arm")) {
            setCategorizerStrategy(new ArmStrategy());
        } else {
            throw new InvalidStrategyException();
        }
    
    }
    
    public String getInsnCategory(CodeUnit insn) {
        return categorizer.getInsnCategory(insn);
    }
    
    public String[] getValidCategories() {
        return categorizer.getValidCategories();
    }
}

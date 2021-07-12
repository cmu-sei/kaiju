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
package kaiju.graph.original;

import ghidra.graph.GVertex;
import ghidra.program.model.lang.Mask;
import ghidra.program.model.lang.OperandType;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.mem.MemoryAccessException;

/**
 * A vertex that contains CodeUnit info.
 * Since this extends CodeUnit then it has the same API as CodeUnit,
 * we just also extend GVertex for symmetry to use with InsnControlFlowGraph.
 */
public interface CodeUnitVertex extends CodeUnit, GVertex, InsnControlFlowGraphElement {

    /**
     * An alias for getBytes() to make it explicit
     * that we're getting the exact bytes and not
     * modified in any way.
     */
    public default byte[] getExactBytes() {
        try {
            return this.getBytes();
        } catch (MemoryAccessException mae) {
            //TODO: how do we best handle this here?
            return null;
        }
    }
    
    public default byte[] getPICBytes() {
        byte[] picbytes = getExactBytes();
        // TODO: this needs to be fully implemented
        int numOperands = this.getNumOperands();
        for (int op=0; op < numOperands; ++op) {
            // an Instruction is a type of CodeUnit
            if ( this instanceof Instruction ) {
                int optype = ((Instruction) this).getOperandType(op);
                boolean picit = OperandType.isAddress(optype) ||
                                OperandType.isCodeReference(optype) ||
                                OperandType.isDataReference(optype) ||
                                OperandType.doesRead(optype) || // implies address according to the docs
                                OperandType.doesWrite(optype) // implies address according to the docs
                                //OperandType.isImmediate(optype) || // maybe? need to check if could be an address too
                                //OperandType.isRelative(optype) || // maybe? see above
                                //OperandType.isScalarAsAddress(optype) // maybe? see above
                                ;
            }
        }
        
        return picbytes;
    }
    
    @Override
    public default void accept(InsnControlFlowGraphElementVisitor visitor) {
        visitor.visit(this);
    }

}

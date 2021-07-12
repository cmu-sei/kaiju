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

import ghidra.graph.GEdge;
import ghidra.program.model.listing.CodeUnit;

/**
 * An edge that contains properties and state related to a user interface.
 */
public class CodeUnitEdge implements GEdge<CodeUnitVertex>, InsnControlFlowGraphElement {

    private CodeUnitVertex startCU;
    private CodeUnitVertex endCU;
    
    public CodeUnitEdge(CodeUnitVertex start, CodeUnitVertex end) {
        startCU = start;
        endCU = end;
    }

    /**
     * Get the start, or tail, of the edge
     * 
     * <P>In the edge x -&gt; y, x is the start
     * 
     * @return the start
     */
    @Override
    public CodeUnitVertex getStart() {
        return startCU;
    }

    /**
     * Get the end, or head, of the edge
     * 
     * <P>In the edge x -&gt; y, y is the end
     * 
     * @return the end
     */
    @Override
    public CodeUnitVertex getEnd() {
        return endCU;
    }
    
    @Override
    public void accept(InsnControlFlowGraphElementVisitor visitor) {
        visitor.visit(this);
    }

}

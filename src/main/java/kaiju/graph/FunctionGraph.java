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
package kaiju.graph;

import java.lang.reflect.InvocationTargetException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Program;
import ghidra.service.graph.AttributedGraph;
import ghidra.service.graph.AttributedVertex;
// TODO: the AttributedGraph API changed in Ghidra 10.1, we use reflection in the constructor to test for this
//import ghidra.service.graph.GraphType;
import ghidra.util.task.TaskMonitor;
import kaiju.common.KaijuLogger;

public class FunctionGraph implements KaijuLogger {

    private Program program;
    private AttributedGraph attrgraph;
    private Map<AttributedVertex, Function> vertex2fn;
    private Map<Function, AttributedVertex> fn2vertex;
    //private MultiLogger logger;
    private TaskMonitor monitor;

    /**
     * Takes a Program and then runs the hashing algorithms
     * on each Function.
     * Meant to sort of implement a Visitor pattern to allow
     * easy extensibility.
     */
    public FunctionGraph(Program currentProgram, TaskMonitor currentMonitor) {
    
        java.lang.reflect.Method m;
        try {
            m = attrgraph.getClass().getMethod("AttributeGraph");
        } catch (NoSuchMethodException e) {
            //TODO: what do we do?
            m = null;
        }
        
        try {
            // if we can load GraphType, then we know we have Ghidra 10.1+
            Class<?> graphtypeclass = Class.forName("ghidra.service.graph.GraphType");
            try {
                // create a GraphType object, then feed it to AttributedGraph
                Class<?>[] types = {String.class, String.class, List.class, List.class};
                Object[] params = {"Kaiju Function Graph", graphtypeclass.getDeclaredConstructor(types).newInstance()};
                attrgraph = (AttributedGraph) (m.invoke(params));
            } catch (NoSuchMethodException nsme) {
                // TODO: this comes from GraphType new instance, do we do anything?
            } catch (InstantiationException ie) {
                // TODO: this comes from GraphType new instance, do we do anything?
            } catch (IllegalAccessException iae) {
                // TODO: this comes from AttributedGraph new instance, do we do anything?
            } catch (InvocationTargetException ite) {
                // TODO: this comes from AttributedGraph new instance, do we do anything?
            }
        } catch (ClassNotFoundException cnfe) {
            //if couldn't load, assume pre Ghidra 10.1
            try {
                // pre Ghidra 10.1 we could construct AttributedGraph with no params
                attrgraph = (AttributedGraph) (m.invoke(null));
            } catch (IllegalAccessException iae) {
                // TODO: anything?
            } catch (InvocationTargetException ite) {
                // TODO: anything?
            }
        }
        
        program = currentProgram;
        vertex2fn = new HashMap<>();
        fn2vertex = new HashMap<>();
        //logger = MultiLogger.getInstance();
        monitor = currentMonitor;
        fnToGraph();
    }
    
    private void fnToGraph() {
        // start analyzing functions
        // iterate over all functions (if not currently in a function or if running headless):
        FunctionIterator fiter = program.getFunctionManager().getFunctions(true);
        
        int fncount = 0;
        if (fiter == null) {
            warn(this, "No functions found?");
        } else {
            while (fiter.hasNext()) {
                Function function = fiter.next();
                if (monitor.isCancelled()) {
                    break;
                }
                if (function == null) {
                    debug(this, "Skipping Null Function Reference");
                    continue;
                }
                if (function.isThunk()) {
                    debug(this, "Skipping Thunk @ 0x" + function.getEntryPoint().toString());
                    continue;
                }
                try {
                    // add a new vertex to represent this function
                    AttributedVertex addedVertex = attrgraph.addVertex();
                    // TODO: add hash info as vertex attributes
                    updateVertexAttributes(addedVertex, function);
                    // add the vertex to the maps so can find later
                    vertex2fn.put(addedVertex, function);
                    fn2vertex.put(function, addedVertex);
                    fncount++;
                } catch (Exception e) {
                    error(this, "Error while building function graph", e);
                }
            }
        }
        info(this, "Function graph created. Contains " + fncount + " functions.");
    }
    
    private void updateVertexAttributes(AttributedVertex vertex, Function function) {
        // 
    }

}



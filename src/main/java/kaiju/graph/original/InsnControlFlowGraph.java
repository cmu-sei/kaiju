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

import generic.stl.Pair;
import generic.stl.RedBlackNode;
import generic.stl.RedBlackTree;
import ghidra.graph.GDirectedGraph;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.CodeUnit;

import java.lang.Boolean;
import java.util.Collection;
import java.util.Comparator;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;
import java.util.Vector;

/**
 * A directed graph representing the CodeUnits (Instructions and Data) in a Function or Program.
 * 
 * Unlike {@link GImplicitDirectedGraph}, this graph is constructed explicitly in memory. Edges and
 * vertices are added and removed like any other collection, and these elements represent the
 * entirety of the graph at any given time.
 *
 * The CodeUnits in the graph are sorted by Address using a RedBlackTree.
 * https://ghidra.re/ghidra_docs/api/generic/stl/RedBlackTree.html
 * 
 * @param <CodeUnitVertex> the type of vertices
 * @param <CodeUnitEdge> the type of edges
 */
public class InsnControlFlowGraph implements GDirectedGraph<CodeUnitVertex, CodeUnitEdge>, InsnControlFlowGraphElement {

    private RedBlackTree<Address,CodeUnitVertex> cfg_vertices_in_address_order;
    //private TreeSet<CodeUnitVertex> cfg_vertices
    private TreeSet<CodeUnitEdge> cfg_edges;
    
    public InsnControlFlowGraph() {
        //cfg_vertices = new TreeSet<CodeUnitVertex>();
        cfg_edges = new TreeSet<CodeUnitEdge>();
        
        AddressComparator ac = new AddressComparator();
        cfg_vertices_in_address_order = new RedBlackTree<Address,CodeUnitVertex>(ac,false);
    }
    
    public InsnControlFlowGraph(RedBlackTree<Address,CodeUnitVertex> init_cfg_vertices, TreeSet<CodeUnitEdge> init_cfg_edges) {
        cfg_vertices_in_address_order = init_cfg_vertices;
        cfg_edges = init_cfg_edges;
    }
    
    /**
     * Implement the accept() function as part of the Visitor pattern.
     * This function defines how to apply the visitor to each element of the CFG.
     * Currently, only vertices are recognized as elements in the implementation,
     * but the infrastructure allows recognizing both edges and vertices as elements.
     *
     * @param visitor the InsnControlFlowGraphElementVisitor implementation
     */
    @Override
    public void accept(InsnControlFlowGraphElementVisitor visitor) {
        for (InsnControlFlowGraphElement element : getVerticesInAddressOrder()) {
            element.accept(visitor);
        }
        //visitor.visit(this);
    }

    /**
     * Add a vertex to the CFG.
     * The vertex will automatically be added according its Address value.
     * @param v the vertex
     * @return true if the add was successful, false otherwise
     */
    public boolean addVertex(CodeUnitVertex v) {
        Pair<RedBlackNode<Address,CodeUnitVertex>,Boolean> result = cfg_vertices_in_address_order.put(v.getMinAddress(), v);
        return result.second.booleanValue();
    }

    /**
     * Remove a vertex from the CFG.
     * @param v the vertex
     * @return true
     */
    public boolean removeVertex(CodeUnitVertex v) {
        cfg_vertices_in_address_order.remove(v.getMinAddress());
        return true;
    }

    /**
     * Removes the given vertices from the graph.
     * Convenience function to allow removing more than one vertex in a single call.
     * 
     * @param vertices the vertices to remove
     */
    public void removeVertices(Iterable<CodeUnitVertex> vertices) {
        for (CodeUnitVertex v : vertices) {
            cfg_vertices_in_address_order.remove(v.getMinAddress());
        }
    }

    /**
     * Add an edge
     * @param e the edge
     */
    public void addEdge(CodeUnitEdge e) {
        cfg_edges.add(e);
    }

    /**
     * Removes an edge
     * @param e the edge
     * @return true if the graph contained the given edge
     */
    public boolean removeEdge(CodeUnitEdge e) {
        return cfg_edges.remove(e);
    }

    /**
     * Removes the given edges from the graph
     * 
     * @param edges the edges to remove
     */
    public void removeEdges(Iterable<CodeUnitEdge> edges) {
        // need to convert Iterable to a Collection
        TreeSet<CodeUnitEdge> result = new TreeSet<CodeUnitEdge>();
        edges.forEach(result::add);
        cfg_edges.removeAll(result);
    }

    /**
     * Locates the edge object for the two vertices
     * 
     * @param start the start vertex
     * @param end the end vertex
     * @return the edge
     */
    public CodeUnitEdge findEdge(CodeUnitVertex start, CodeUnitVertex end) {
        return new CodeUnitEdge(start, end);
    }

    /**
     * Retrieve all the vertices in a Collection.
     * Currently, implemented as a Vector sorted by address order,
     * due to the use of  the Red-Black Tree to store vertices.
     * @return the vertices
     */
    public Collection<CodeUnitVertex> getVertices() {
        Vector<CodeUnitVertex> result = new Vector<CodeUnitVertex>();
        CodeUnitVertex iter = cfg_vertices_in_address_order.getFirst().getValue();
        int n = cfg_vertices_in_address_order.size();
        // add the first node
        if (iter != null) {
            result.add(iter);
            n--;
            while (n>0) {
                iter = cfg_vertices_in_address_order.upperBound(iter.getMinAddress()).getValue();
                result.add(iter);
                n--;
            }
        }
        return result;
    }
    
    /**
     * Retrieve all the edges in a Vector sorted by address order.
     * Guaranteed to be in address order from lowest to highest address.
     * Right now just falls back on a general implementation that could
     * change in future.
     * Use this function in API if need guaranteed address order.
     */
    public Collection<CodeUnitVertex> getVerticesInAddressOrder() {
        return getVertices();
    }

    /**
     * Retrieve all the edges
     * @return the edges
     */
    public Collection<CodeUnitEdge> getEdges() {
        return cfg_edges;
    }

    /**
     * Test if the graph contains a given vertex
     * @param v the vertex
     * @return true if the vertex is in the graph, or false
     */
    public boolean containsVertex(CodeUnitVertex v) {
        return cfg_vertices_in_address_order.containsKey(v.getMinAddress());
    }

    /**
     * Test if the graph contains a given edge
     * @param e the edge
     * @return true if the edge is in the graph, or false
     */
    public boolean containsEdge(CodeUnitEdge e) {
        return cfg_edges.contains(e);
    }

    /**
     * Test if the graph contains an edge from one given vertex to another
     * @param from the source vertex
     * @param to the destination vertex
     * @return true if such an edge exists, or false
     */
    public boolean containsEdge(CodeUnitVertex from, CodeUnitVertex to) {
        return cfg_edges.contains(new CodeUnitEdge(from, to));
    }

    /**
     * Test if the graph is empty, i.e., contains no vertices or edges
     * @return true if the graph is empty, or false
     */
    public boolean isEmpty() {
        return cfg_vertices_in_address_order.isEmpty() && cfg_edges.isEmpty();
    }

    /**
     * Count the number of vertices in the graph
     * @return the count
     */
    public int getVertexCount() {
        return cfg_vertices_in_address_order.size();
    }

    /**
     * Count the number of edges in the graph
     * @return the count
     */
    public int getEdgeCount() {
        return cfg_edges.size();
    }

    /**
     * Compute the incident edges that end at the given vertex
     * 
     * @param v the destination vertex
     * @return the in-edges to the given vertex
     */
    public Collection<CodeUnitEdge> getInEdges(CodeUnitVertex v) {
        TreeSet<CodeUnitEdge> in_edges = new TreeSet<CodeUnitEdge>();
        for (CodeUnitEdge e : cfg_edges) {
            if (e.getEnd().equals(v)) {
                in_edges.add(e);
            }
        }
        
        return in_edges;
    }

    /**
     * Compute the incident edges that start at the given vertex
     * 
     * @param v the source vertex
     * @return the out-edges from the given vertex
     */
    public Collection<CodeUnitEdge> getOutEdges(CodeUnitVertex v) {
        TreeSet<CodeUnitEdge> out_edges = new TreeSet<CodeUnitEdge>();
        for (CodeUnitEdge e : cfg_edges) {
            if (e.getStart().equals(v)) {
                out_edges.add(e);
            }
        }
        
        return out_edges;
    }

    /**
     * Copy this graph.
     * 
     * <P>Note: the vertices and edges in the copy may be the same instances in the new graph
     * and not themselves copies.
     * 
     * @return the new copy
     */
    public InsnControlFlowGraph copy() {
        return new InsnControlFlowGraph(cfg_vertices_in_address_order, cfg_edges);
    }

    /**
     * Creates a new instance of this graph with no vertices or edges.  This is useful when 
     * you wish to build a new graph using the same type as this graph.
     * 
     * @return the new copy
     */
    public InsnControlFlowGraph emptyCopy() {
        return new InsnControlFlowGraph();
    }
    
}


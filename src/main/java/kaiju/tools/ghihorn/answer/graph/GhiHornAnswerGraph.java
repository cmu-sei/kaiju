package kaiju.tools.ghihorn.answer.graph;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.util.Collection;
import java.util.List;
import ghidra.graph.GDirectedGraph;
import ghidra.graph.GraphAlgorithms;
import ghidra.graph.GraphFactory;
import ghidra.graph.algo.GraphNavigator;
import kaiju.tools.ghihorn.answer.format.GhiHornDisplaySettings;
import kaiju.tools.ghihorn.answer.graph.display.GhiHornVisualAnswerGraph;
import kaiju.tools.ghihorn.hornifer.horn.HornProgram;
import kaiju.tools.ghihorn.z3.GhiHornFixedpointStatus;

/**
 * A graph that allows for filtering
 */
public class GhiHornAnswerGraph {

    private final GDirectedGraph<GhiHornAnswerGraphVertex, GhiHornAnswerGraphEdge> graph;
    private final GhiHornFixedpointStatus status;
    private final HornProgram hornProgram;

    /**
     * 
     * @param hp
     * @param s
     */
    public GhiHornAnswerGraph(final HornProgram hp, GhiHornFixedpointStatus s) {
        this.graph = GraphFactory.createDirectedGraph();
        this.status = s;
        this.hornProgram = hp;
    }

    /**
     * 
     * @param s
     * @return
     */
    public GhiHornVisualAnswerGraph toVisualGraph(GhiHornDisplaySettings s) {
        return new GhiHornVisualAnswerGraph(graph, s);
    }

    /**
     * Add a new vertex
     * 
     * @param v
     */
    public void addVertex(final GhiHornAnswerGraphVertex v) {
        if (v != null) {
            graph.addVertex(v);
        }
    }

    /**
     * Remove a vertex if it exists
     * @param v
     */
    public void removeVertex(final GhiHornAnswerGraphVertex v) {
        if (graph.containsVertex(v)) {
            graph.removeVertex(v);
        }
    }

    /**
     * 
     * @return the vertices in no particular order
     */
    public Collection<GhiHornAnswerGraphVertex> getVertices() {
        return graph.getVertices();
    }

    /**
     * 
     * @param v
     * @return
     */
    public boolean containsVertex(final GhiHornAnswerGraphVertex v) {
        return graph.containsVertex(v);
    }

    /**
     * 
     * @param e
     */
    public void addEdge(final GhiHornAnswerGraphEdge e) {
        if (e != null) {
                    
            graph.addEdge(e);
        }
    }

    /**
     * 
     * @param e
     * @return
     */
    public boolean containsEdge(final GhiHornAnswerGraphEdge e) {
        return graph.containsEdge(e);
    }

    /**
     * 
     * @return vertices in pre order
     */
    public List<GhiHornAnswerGraphVertex> getVerticesInPreOrder() {
        return GraphAlgorithms.getVerticesInPreOrder(this.graph,
                GraphNavigator.topDownNavigator());
    }

    /**
     * @return vertices in post order
     */
    public List<GhiHornAnswerGraphVertex> getVerticesInPostOrder() {
        return GraphAlgorithms.getVerticesInPostOrder(this.graph,
                GraphNavigator.topDownNavigator());
    }

    /**
     * @return the hornProgram
     */
    public HornProgram getHornProgram() {
        return hornProgram;
    }

    public String toString() {

        final ByteArrayOutputStream baos = new ByteArrayOutputStream();
        final String utf8 = StandardCharsets.UTF_8.name();
        try (PrintStream ps = new PrintStream(baos, true, utf8)) {
            GraphAlgorithms.printGraph(graph, ps);
            return baos.toString(utf8);
        } catch (Exception e) {
            e.printStackTrace();
        }

        return "";
    }

    /**
     * @return the status
     */
    public GhiHornFixedpointStatus getStatus() {
        return status;
    }
}

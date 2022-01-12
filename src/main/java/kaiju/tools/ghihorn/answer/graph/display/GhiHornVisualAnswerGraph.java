package kaiju.tools.ghihorn.answer.graph.display;

import java.util.HashMap;
import java.util.Map;
import ghidra.graph.GDirectedGraph;
import ghidra.graph.graphs.FilteringVisualGraph;
import ghidra.graph.viewer.layout.VisualGraphLayout;
import kaiju.tools.ghihorn.answer.format.GhiHornDisplaySettings;
import kaiju.tools.ghihorn.answer.graph.GhiHornAnswerGraphEdge;
import kaiju.tools.ghihorn.answer.graph.GhiHornAnswerGraphVertex;


/**
 * A visual reprentation of an answer graph
 */
public class GhiHornVisualAnswerGraph
        extends FilteringVisualGraph<GhiHornAnswerGraphVisualVertex, GhiHornAnswerGraphVisualEdge> {

    private VisualGraphLayout<GhiHornAnswerGraphVisualVertex, GhiHornAnswerGraphVisualEdge> layout;
    private GDirectedGraph<GhiHornAnswerGraphVertex, GhiHornAnswerGraphEdge> answerGraph;
    private GhiHornDisplaySettings displaySettings;

    /**
     * Create a visual graph
     * @param ag
     * @param s
     */
    public GhiHornVisualAnswerGraph(
            GDirectedGraph<GhiHornAnswerGraphVertex, GhiHornAnswerGraphEdge> answerGraph,
            GhiHornDisplaySettings settings) {

        super();

        final Map<GhiHornAnswerGraphVertex, GhiHornAnswerGraphVisualVertex> vtxMap =
                new HashMap<>();

        for (GhiHornAnswerGraphVertex ansVtx : answerGraph.getVertices()) {
            final GhiHornAnswerGraphVisualVertex vizVtx =
                    new GhiHornAnswerGraphVisualVertex(ansVtx.getAttributes(), settings);  
            vtxMap.put(ansVtx, vizVtx);
            addVertex(vizVtx);
        }

        for (GhiHornAnswerGraphEdge e : answerGraph.getEdges()) {

            GhiHornAnswerGraphVisualVertex start = vtxMap.get(e.getStart());
            GhiHornAnswerGraphVisualVertex end = vtxMap.get(e.getEnd());
            

            addEdge(new GhiHornAnswerGraphVisualEdge(start, end));
        }

        this.displaySettings = settings;
        this.answerGraph = answerGraph;
    }

    @Override
    public VisualGraphLayout<GhiHornAnswerGraphVisualVertex, GhiHornAnswerGraphVisualEdge> getLayout() {
        return layout;
    }

    /**
     * @param layout the layout to set
     */
    public void setLayout(
            VisualGraphLayout<GhiHornAnswerGraphVisualVertex, GhiHornAnswerGraphVisualEdge> layout) {
        this.layout = layout;
    }

    @Override
    public GhiHornVisualAnswerGraph copy() {

        GhiHornVisualAnswerGraph newGraph =
                new GhiHornVisualAnswerGraph(answerGraph, displaySettings);

        for (GhiHornAnswerGraphVisualVertex v : vertices.keySet()) {
            newGraph.addVertex(v);
        }

        for (GhiHornAnswerGraphVisualEdge e : edges.keySet()) {
            newGraph.addEdge(e);
        }
        return newGraph;
    }
}

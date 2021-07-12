package kaiju.tools.ghihorn.display.graph;

import java.util.Collection;
import ghidra.graph.GraphAlgorithms;
import ghidra.graph.VisualGraph;
import ghidra.graph.viewer.layout.AbstractVisualGraphLayout;
import ghidra.graph.viewer.layout.GridLocationMap;
import ghidra.util.exception.CancelledException;
import kaiju.tools.ghihorn.answer.graph.GhiHornAnswerGraph;
import kaiju.tools.ghihorn.answer.graph.display.GhiHornAnswerGraphVisualEdge;
import kaiju.tools.ghihorn.answer.graph.display.GhiHornAnswerGraphVisualVertex;
import kaiju.tools.ghihorn.answer.graph.display.GhiHornVisualAnswerGraph;

/**
 * Simple graph
 */
public class GhiHornAnswerGraphLayout
        extends
        AbstractVisualGraphLayout<GhiHornAnswerGraphVisualVertex, GhiHornAnswerGraphVisualEdge> {

    public static final String NAME = "GhiHorn Layout";

    protected GhiHornAnswerGraphLayout(final GhiHornVisualAnswerGraph answerGraph) {
        super(answerGraph, "GhiHorn Layout");
    }

    @Override
    public GhiHornVisualAnswerGraph getVisualGraph() {
        return (GhiHornVisualAnswerGraph) getGraph();
    }

    @Override
    public AbstractVisualGraphLayout<GhiHornAnswerGraphVisualVertex, GhiHornAnswerGraphVisualEdge> createClonedLayout(
            VisualGraph<GhiHornAnswerGraphVisualVertex, GhiHornAnswerGraphVisualEdge> newGraph) {

        if (!(newGraph instanceof GhiHornAnswerGraph)) {
            throw new IllegalArgumentException(
                    "Must pass a " + GhiHornAnswerGraph.class.getSimpleName()
                            + "to clone the " + getClass().getSimpleName());
        }

        GhiHornAnswerGraphLayout newLayout =
                new GhiHornAnswerGraphLayout((GhiHornVisualAnswerGraph) newGraph);
        return newLayout;
    }

    @Override
    protected GridLocationMap<GhiHornAnswerGraphVisualVertex, GhiHornAnswerGraphVisualEdge> performInitialGridLayout(
            VisualGraph<GhiHornAnswerGraphVisualVertex, GhiHornAnswerGraphVisualEdge> g)
            throws CancelledException {

        GridLocationMap<GhiHornAnswerGraphVisualVertex, GhiHornAnswerGraphVisualEdge> grid =
                new GridLocationMap<>();

        GhiHornAnswerGraphVisualVertex[] sources =
                GraphAlgorithms.getSources(g).toArray(new GhiHornAnswerGraphVisualVertex[0]);

        int scale = 1;
        for (int v = 0; v < sources.length; v++) {
            grid.set(sources[v], 0, 0);
			assignRows(sources[v], g, grid, 1, scale);
            scale += 10;
        }
        return grid;
    }

    /**
     * Taken from Ghidra. Not sure it is all that great
     * @param v
     * @param g
     * @param grid
     * @param row
     * @param col
     */
    private void assignRows(GhiHornAnswerGraphVisualVertex v,
            VisualGraph<GhiHornAnswerGraphVisualVertex, GhiHornAnswerGraphVisualEdge> g,
            GridLocationMap<GhiHornAnswerGraphVisualVertex, GhiHornAnswerGraphVisualEdge> grid,
            int row, int col) {

        int existing = grid.row(v);
        if (existing > 0) {
            return; // already processed
        }

        grid.row(v, row);
        grid.col(v, col);
        int nextRow = row++;

        Collection<GhiHornAnswerGraphVisualEdge> children = g.getOutEdges(v);
        int n = children.size();
        int middle = n / 2;
        int start = col - middle;
        int childCol = start;

        for (GhiHornAnswerGraphVisualEdge edge : children) {            
            GhiHornAnswerGraphVisualVertex child = edge.getEnd();
            assignRows(child, g, grid, nextRow + 1, childCol++);
        }
    }
}



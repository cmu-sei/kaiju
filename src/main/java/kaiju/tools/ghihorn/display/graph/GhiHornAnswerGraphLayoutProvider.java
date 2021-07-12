package kaiju.tools.ghihorn.display.graph;

import ghidra.graph.viewer.layout.AbstractLayoutProvider;
import ghidra.graph.viewer.layout.VisualGraphLayout;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import kaiju.tools.ghihorn.answer.graph.display.GhiHornAnswerGraphVisualEdge;
import kaiju.tools.ghihorn.answer.graph.display.GhiHornAnswerGraphVisualVertex;
import kaiju.tools.ghihorn.answer.graph.display.GhiHornVisualAnswerGraph;

public class GhiHornAnswerGraphLayoutProvider
        extends
        AbstractLayoutProvider<GhiHornAnswerGraphVisualVertex, GhiHornAnswerGraphVisualEdge, GhiHornVisualAnswerGraph> {

    /**
     * 
     */
    @Override
    public VisualGraphLayout<GhiHornAnswerGraphVisualVertex, GhiHornAnswerGraphVisualEdge> getLayout(
            GhiHornVisualAnswerGraph g,
            TaskMonitor monitor) throws CancelledException {

        GhiHornAnswerGraphLayout layout = new GhiHornAnswerGraphLayout(g);
        initVertexLocations(g, layout);
        return layout;
    }

    /**
     * 
     */
    @Override
    public String getLayoutName() {
        return GhiHornAnswerGraphLayout.NAME;
    }
}

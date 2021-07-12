package kaiju.tools.ghihorn.answer.graph;

import ghidra.graph.DefaultGEdge;

public class GhiHornAnswerGraphEdge extends DefaultGEdge<GhiHornAnswerGraphVertex> {

	public GhiHornAnswerGraphEdge(GhiHornAnswerGraphVertex start, GhiHornAnswerGraphVertex end) {
        super(start, end);
    }
}

package kaiju.tools.ghihorn.answer.graph.display;


import ghidra.graph.viewer.edge.AbstractVisualEdge;


/**
 * An edge for the {@link SampleGraph}
 */
public class GhiHornAnswerGraphVisualEdge extends AbstractVisualEdge<GhiHornAnswerGraphVisualVertex> {

	public GhiHornAnswerGraphVisualEdge(GhiHornAnswerGraphVisualVertex start, GhiHornAnswerGraphVisualVertex end) {
		super(start, end);
	}

	@SuppressWarnings("unchecked")
	// Suppressing warning on the return type; we know our class is the right type
	@Override
	public GhiHornAnswerGraphVisualEdge cloneEdge(GhiHornAnswerGraphVisualVertex start, GhiHornAnswerGraphVisualVertex end) {
		return new GhiHornAnswerGraphVisualEdge(start, end);
	}
}

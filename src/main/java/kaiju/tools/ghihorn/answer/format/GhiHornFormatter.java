package kaiju.tools.ghihorn.answer.format;

import kaiju.tools.ghihorn.answer.graph.GhiHornAnswerGraphVertex;
import kaiju.tools.ghihorn.answer.GhiHornAnswerAttributes;
import kaiju.tools.ghihorn.answer.graph.GhiHornAnswerGraph;

public interface GhiHornFormatter<T> {

    public void format(final GhiHornAnswerGraph graph, T formatter);

    public void format(GhiHornAnswerGraphVertex vtx, T formatter);

    public void format(GhiHornAnswerAttributes attrs, T formatter);
}

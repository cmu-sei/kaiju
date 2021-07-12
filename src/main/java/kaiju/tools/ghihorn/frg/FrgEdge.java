package kaiju.tools.ghihorn.frg;

import ghidra.graph.GEdge;

public class FrgEdge implements GEdge<FrgVertex> {

	private FrgVertex start;
	private FrgVertex end;

	public FrgEdge(FrgVertex start, FrgVertex end) {
		this.start = start;
		this.end = end;
	}

	@Override
	public FrgVertex getStart() {
		return start;
	}

	@Override
	public FrgVertex getEnd() {
		return end;
	}

	@Override
	public String toString() {
		return start.toString() + " -> " + end.toString();
	}
}

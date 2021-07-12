package kaiju.tools.ghihorn.frg;

import ghidra.program.model.listing.Function;

import java.util.List;

public class FrgResult {

	private final List<FrgVertex> path;
	private final Function fromFunction;
	private final Function toFunction;

	public FrgResult(Function fromFunction, Function toFunction, List<FrgVertex> path) {
		this.fromFunction = fromFunction;
		this.toFunction = toFunction;
		this.path = path;
	}

	public Function getFromFunction() {
		return fromFunction;
	}

	public Function getToFunction() {
		return toFunction;
	}

	public int getPathLength() {
		return path.size();
	}

	public List<FrgVertex> getPath() {
		return path;
	}
}
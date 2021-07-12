package kaiju.tools.ghihorn.cfg;

import ghidra.graph.GVertex;

// Taken from the Ghidra PAL, with a few modPifications
public class HighCfgVertex<L, E> implements GVertex {

	// Locator and entity are required
	private final L locator;
	private final E entity;

	public HighCfgVertex(final L loc, final E e) {
		this.locator = loc;
		this.entity = e;
	}

	@Override
	public int hashCode() {
		return this.locator.hashCode();
	}

	@Override
	public boolean equals(Object other) {
		if (other instanceof HighCfgVertex<?, ?>) {
			return this.locator.equals(((HighCfgVertex<?, ?>) other).locator);
		}
		return false;
	}

	public L getLocator() {
		return this.locator;
	}

	public E getEntity() {
		return this.entity;
	}

	@Override
	public String toString() {
		//@formatter:off
		return new StringBuilder()
		 .append(locator)
		 .append("\n")
		 .append(entity)
		 .append("----------")
		 .toString();
		//@formatter:on
	}


}

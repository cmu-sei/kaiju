
package kaiju.tools.ghihorn.cfg;

import ghidra.graph.DefaultGEdge;

public class HighCfgEdge<L, E> extends DefaultGEdge<HighCfgVertex<L, E>> {
    private HighCfgEdgeGuard guard;
	// Information about the conditions under which this edge is taken
	// private HighCfgConstraint constraint;

	/**
	 * Set a conditional edge
	 * 
	 * @param start
	 * @param end
	 */
	public HighCfgEdge(HighCfgVertex<L, E> start, HighCfgVertex<L, E> end) {
		super(start, end);
		this.guard = null;
	}

	@Override
	public String toString() {
		HighCfgVertex<L, E> start = getStart();
		HighCfgVertex<L, E> end = getEnd();
		if (this.guard != null) {
			return start.getLocator() + "->" + end.getLocator() + ". " + guard.toString();
		}
		return start.getLocator() + "->" + end.getLocator();
    }   

    public void setGuard(HighCfgEdgeGuard g) {
        this.guard = g;
    }

	/**
	 * Fetch the edge condition
	 * 
	 * @return
	 */
	public HighCfgEdgeGuard getGuard() {
		return this.guard;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see java.lang.Object#hashCode()
	 */
	@Override
	public int hashCode() {
		return super.hashCode() * 31;		
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see java.lang.Object#equals(java.lang.Object)
	 */
	@SuppressWarnings("unchecked")
	@Override
	public boolean equals(Object o) {

		// Edge equality is predicated on the hashcode
		if (o == null) {
			return false;
		}
		if (this == o) {
			return true;
		}
		if (!super.equals(o)) {
			return false;
		}
		if (getClass() != o.getClass()) {
			return false;
		}

		HighCfgEdge<L, E> otherEdge = (HighCfgEdge<L, E>) o;
		return (otherEdge.getStart().hashCode() == getStart().hashCode()
				&& otherEdge.getEnd().hashCode() == getEnd().hashCode());
	}
}

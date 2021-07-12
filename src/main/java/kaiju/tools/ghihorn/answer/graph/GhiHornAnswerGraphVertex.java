package kaiju.tools.ghihorn.answer.graph;

import ghidra.graph.GVertex;
import kaiju.tools.ghihorn.answer.GhiHornAnswerAttributes;

/**
 * A vertex for the {@link SampleGraphPlugin}
 */
public class GhiHornAnswerGraphVertex implements GVertex {
    private final GhiHornAnswerAttributes attributes;

    public GhiHornAnswerGraphVertex(final GhiHornAnswerAttributes attrs) {  
        this.attributes = attrs;
    }

    /**
     * Designate this vertex as the start
     */
    public void makeStart() {
        this.attributes.makeStart();
    }

    /**
     * Designate this vertex as the goal
     */
    public void makeGoal() {
        this.attributes.makeGoal();
    }

    /**
     * @return the name
     */
    public String getName() {
        if (attributes == null) {
            return "";
        }
        return attributes.getName();
    }

    /**
     * @return the attributes
     */
    public GhiHornAnswerAttributes getAttributes() {
        return attributes;
    }

    /* (non-Javadoc)
     * @see java.lang.Object#hashCode()
     */
    
    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((attributes == null) ? 0 : attributes.hashCode());
        return result;
    }

    /* (non-Javadoc)
     * @see java.lang.Object#equals(java.lang.Object)
     */
    
    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;
        if (getClass() != obj.getClass())
            return false;
        GhiHornAnswerGraphVertex other = (GhiHornAnswerGraphVertex) obj;
        if (attributes == null) {
            if (other.attributes != null)
                return false;
        } else if (!attributes.equals(other.attributes))
            return false;
        return true;
    }

    @Override
    public String toString() {
        return getName();
    }
    
}

package kaiju.tools.ghihorn.answer.graph;

import ghidra.graph.GVertex;
import kaiju.tools.ghihorn.answer.GhiHornAnswerAttributes;
import kaiju.tools.ghihorn.answer.format.GhiHornFormattableElement;
import kaiju.tools.ghihorn.answer.format.GhiHornOutputFormatter;

/**
 * A vertex for the {@link SampleGraphPlugin}
 */
public class GhiHornAnswerGraphVertex implements GVertex, GhiHornFormattableElement {
    private final GhiHornAnswerAttributes attributes;

    public GhiHornAnswerGraphVertex(final GhiHornAnswerAttributes attrs) {
        this.attributes = attrs;
    }

    /**
     * @return the name
     */
    public String getVertexName() {
        if (attributes == null) {
            return "";
        }
        return attributes.getVertexName();
    }

    /**
     * @return the attributes
     */
    public GhiHornAnswerAttributes getAttributes() {
        return attributes;
    }

    /*
     * (non-Javadoc)
     * 
     * @see java.lang.Object#hashCode()
     */

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((attributes == null) ? 0 : attributes.hashCode());
        return result;
    }

    /*
     * (non-Javadoc)
     * 
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
        return getVertexName();
    }

    @Override
    public String format(GhiHornOutputFormatter formatter) {
        return formatter.format(this);
    }
}

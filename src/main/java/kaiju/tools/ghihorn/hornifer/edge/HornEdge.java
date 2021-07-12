package kaiju.tools.ghihorn.hornifer.edge;

import kaiju.tools.ghihorn.hornifer.block.HornBlock;
import kaiju.tools.ghihorn.hornifer.horn.expression.HornExpression;

/**
 * A hornified, possibly constrained control flow edge
 */
public class HornEdge {

    private final HornBlock source;
    private final HornBlock target;
    private HornExpression constraint;

    public HornEdge(HornBlock s, HornBlock t) {
        this.source = s;
        this.target = t;
        this.constraint = null;
    }

    /**
     * 
     * @param c the constraint to add
     */
    public void addConstraint(HornExpression c) {
        this.constraint = c;
    }

    /**
     * 
     * @return the constraints
     */
    public HornExpression getConstraint() {
        return this.constraint;
    }

    /**
     * @return the source block
     */
    public HornBlock getSource() {
        return this.source;
    }

    /**
     * @return the target block
     */
    public HornBlock getTarget() {
        return this.target;
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
        result = prime * result + ((constraint == null) ? 0 : constraint.hashCode());
        result = prime * result + ((source == null) ? 0 : source.hashCode());
        result = prime * result + ((target == null) ? 0 : target.hashCode());
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
        HornEdge other = (HornEdge) obj;
        if (constraint == null) {
            if (other.constraint != null)
                return false;
        } else if (!constraint.equals(other.constraint))
            return false;
        if (source == null) {
            if (other.source != null)
                return false;
        } else if (!source.equals(other.source))
            return false;
        if (target == null) {
            if (other.target != null)
                return false;
        } else if (!target.equals(other.target))
            return false;
        return true;
    }

    /*
     * (non-Javadoc)
     * 
     * @see java.lang.Object#toString()
     */

    @Override
    public String toString() {

        //@formatter:off
        return new StringBuilder("HornEdge [source= ")
                   .append(source)
                   .append(", target=")
                   .append(target)
                   .append("]")
                   .toString();
        //@formatter:on
    }

}

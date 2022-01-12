package kaiju.tools.ghihorn.hornifer.horn.expression;

import com.microsoft.z3.Expr;
import kaiju.tools.ghihorn.z3.GhiHornContext;
import kaiju.tools.ghihorn.z3.GhiHornType;

/**
 * A copy expression is a strange P-code expression because it is really an assignment and that will
 * be handled by the equational nature of pcode: output = input. So, making this a proper class is
 * done to ensure that the components are properly handled.
 */
public class CopyExpression implements HornExpression {

    private final HornExpression rhs; // this is the assignee

    /**
     * 
     * @param rhs the asignee expression
     */
    public CopyExpression(HornExpression rhs) {
        this.rhs = rhs;
    }

    @Override
    public Expr<?> instantiate(GhiHornContext ctx) {

        return rhs.instantiate(ctx);
    }

    @Override
    public String toString() {
        return rhs.toString();
    }

    @Override
    public GhiHornType getType() {
        return this.rhs.getType();
    }

    @Override
    public HornExpression[] getComponents() {
        return new HornExpression[] {rhs};
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
        result = prime * result + ((rhs == null) ? 0 : rhs.hashCode());
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
        if (!(obj instanceof AddExpression))
            return false;

        CopyExpression other = (CopyExpression) obj;

        if (rhs == null) {
            if (other.rhs != null)
                return false;
        } else if (!rhs.equals(other.rhs))
            return false;

        return true;
    }
}

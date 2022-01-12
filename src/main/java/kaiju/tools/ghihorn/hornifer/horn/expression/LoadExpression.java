package kaiju.tools.ghihorn.hornifer.horn.expression;

import com.microsoft.z3.BitVecExpr;
import com.microsoft.z3.Expr;
import com.microsoft.z3.Sort;

import kaiju.tools.ghihorn.z3.GhiHornContext;
import kaiju.tools.ghihorn.z3.GhiHornType;

public class LoadExpression implements HornExpression {
    private final HornExpression index;

    @Override
    public Expr<? extends Sort> instantiate(GhiHornContext ctx) {

        // Include a constraint that makes pointer values more valid

        return ctx.mkSelect(ctx.getMemoryExpr(), (BitVecExpr) index.instantiate(ctx));
    }

    /**
     * @param lhs
     * @param rhs
     */
    public LoadExpression(HornExpression i) {
        this.index = i;
    }

    @Override
    public String toString() {
        return new StringBuilder("MEMORY[").append(index.toString()).append("]").toString();
    }

    @Override
    public GhiHornType getType() {
        return GhiHornType.Undefined;
    }

    @Override
    public HornExpression[] getComponents() {
        return new HornExpression[] {index};
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
        result = prime * result + ((index == null) ? 0 : index.hashCode());
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
        if (!(obj instanceof LoadExpression))
            return false;
        LoadExpression other = (LoadExpression) obj;
        if (index == null) {
            if (other.index != null)
                return false;
        } else if (!index.equals(other.index))
            return false;
        return true;
    }

}

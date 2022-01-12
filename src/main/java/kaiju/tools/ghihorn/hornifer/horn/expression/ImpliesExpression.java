package kaiju.tools.ghihorn.hornifer.horn.expression;

import com.microsoft.z3.BoolExpr;
import com.microsoft.z3.Z3Exception;
import kaiju.tools.ghihorn.z3.GhiHornContext;
import kaiju.tools.ghihorn.z3.GhiHornType;

public class ImpliesExpression implements HornExpression {
    private final HornExpression antecedent, consequence;

    @Override
    public BoolExpr instantiate(GhiHornContext ctx) throws Z3Exception {

        BoolExpr antExpr = (BoolExpr) antecedent.instantiate(ctx);
        BoolExpr conExpr = (BoolExpr) consequence.instantiate(ctx);

        return ctx.mkImplies(antExpr, conExpr);
    }

    /**
     * @param lhs
     * @param rhs
     */
    public ImpliesExpression(HornExpression a, HornExpression c) {
        this.antecedent = a;
        this.consequence = c;
    }

    @Override
    public String toString() {
        return new StringBuilder(antecedent.toString()).append(" -> ")
                .append(consequence.toString()).toString();
    }

    @Override
    public GhiHornType getType() {
        return GhiHornType.BitVec;
    }

    @Override
    public HornExpression[] getComponents() {
        return new HornExpression[] {antecedent, consequence};
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
        result = prime * result + ((antecedent == null) ? 0 : antecedent.hashCode());
        result = prime * result + ((consequence == null) ? 0 : consequence.hashCode());
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
        if (!(obj instanceof ImpliesExpression))
            return false;
        ImpliesExpression other = (ImpliesExpression) obj;
        if (antecedent == null) {
            if (other.antecedent != null)
                return false;
        } else if (!antecedent.equals(other.antecedent))
            return false;
        if (consequence == null) {
            if (other.consequence != null)
                return false;
        } else if (!consequence.equals(other.consequence))
            return false;
        return true;
    }
}

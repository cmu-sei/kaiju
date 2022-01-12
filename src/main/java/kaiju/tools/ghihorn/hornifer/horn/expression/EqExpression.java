package kaiju.tools.ghihorn.hornifer.horn.expression;

import com.google.common.base.Verify;
import com.microsoft.z3.BitVecExpr;
import com.microsoft.z3.BoolExpr;
import com.microsoft.z3.Expr;
import com.microsoft.z3.Z3Exception;
import kaiju.tools.ghihorn.hornifer.horn.variable.HornConstant;
import kaiju.tools.ghihorn.hornifer.horn.variable.HornVariable;
import kaiju.tools.ghihorn.z3.GhiHornContext;
import kaiju.tools.ghihorn.z3.GhiHornType;

public class EqExpression implements HornExpression {
    private final HornExpression lhs, rhs;

    /**
     * @param lhs
     * @param rhs
     */
    public EqExpression(HornExpression lhs, HornExpression rhs) {
        this.lhs = lhs;
        this.rhs = rhs;
    }

    @Override
    public BoolExpr instantiate(GhiHornContext ctx) throws Z3Exception {

        if (lhs.getType() != rhs.getType()) {

            // There is a type mismatch, which is not allowed to happen with an equals

            Expr<?> lhsExpr = null;
            Expr<?> rhsExpr = null;

            // A constant can either be a scalar or a boolean.
            if (lhs instanceof HornConstant) {
                // Key off the rhs type
                lhsExpr = ((HornConstant) lhs).instantiateAs(rhs.getType(), ctx);
                rhsExpr = rhs.instantiate(ctx);
            }
            if (rhs instanceof HornConstant) {

                // Key off the lhs type
                rhsExpr = ((HornConstant) rhs).instantiateAs(lhs.getType(), ctx);
                lhsExpr = lhs.instantiate(ctx);
            }
            else {
                if (rhs instanceof HornVariable && lhs instanceof HornVariable) {
                    HornVariable rhsVar = (HornVariable) rhs;
                    HornVariable lhsVar = (HornVariable) lhs;
                    if (rhsVar.hasHighVariable() && !lhsVar.hasHighVariable()) {
                        
                        // Favor the RHS because it has a variable defined
                        lhsExpr = lhsVar.instantiateAs(rhs.getType(), ctx);
                        rhsExpr = rhs.instantiate(ctx);
                            
                    }
                    if (!rhsVar.hasHighVariable() && lhsVar.hasHighVariable()) {

                        // Favor the LHS because it has a variable defined
                        rhsExpr =  rhsVar.instantiateAs(lhs.getType(), ctx);
                        lhsExpr = lhs.instantiate(ctx);

                    }

                }
            }


            if (lhsExpr != null && rhsExpr != null) {
                if (lhsExpr.isBool() && rhsExpr.isBool()) {
                    return ctx.mkEq((BoolExpr) lhsExpr, (BoolExpr) rhsExpr);
                }
                return ctx.mkEq((BitVecExpr) lhsExpr, (BitVecExpr) rhsExpr);
            }
        }

        // At this point things should match, if they don't it is a problem
        Verify.verify(lhs.getType() == rhs.getType(),
                "Eq requires term types match " + lhs.getType() + ", " + rhs.getType());

        if (lhs.getType() == GhiHornType.Bool) {
            return ctx.mkEq((BoolExpr) lhs.instantiate(ctx), (BoolExpr) rhs.instantiate(ctx));
        } else if (lhs.getType() == GhiHornType.BitVec) {
            return ctx.mkEq((BitVecExpr) lhs.instantiate(ctx), (BitVecExpr) rhs.instantiate(ctx));
        }
        return null;
    }

    @Override
    public String toString() {
        return new StringBuilder(lhs.toString()).append(" = ").append(rhs.toString()).toString();
    }

    @Override
    public GhiHornType getType() {
        return GhiHornType.Bool;
    }

    @Override
    public HornExpression[] getComponents() {
        return new HornExpression[] {lhs, rhs};
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
        result = prime * result + ((lhs == null) ? 0 : lhs.hashCode());
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
        if (!(obj instanceof EqExpression))
            return false;
        EqExpression other = (EqExpression) obj;
        if (lhs == null) {
            if (other.lhs != null)
                return false;
        } else if (!lhs.equals(other.lhs))
            return false;
        if (rhs == null) {
            if (other.rhs != null)
                return false;
        } else if (!rhs.equals(other.rhs))
            return false;
        return true;
    }


}

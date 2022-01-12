package kaiju.tools.ghihorn.hornifer.horn.expression;

import com.google.common.base.Verify;
import com.microsoft.z3.BitVecExpr;
import com.microsoft.z3.Expr;
import com.microsoft.z3.Sort;
import com.microsoft.z3.Z3Exception;
import kaiju.tools.ghihorn.hornifer.horn.variable.HornConstant;
import kaiju.tools.ghihorn.hornifer.horn.variable.HornVariable;
import kaiju.tools.ghihorn.z3.GhiHornContext;
import kaiju.tools.ghihorn.z3.GhiHornType;

public class BvNegExpression implements HornExpression {
    private final HornExpression exp;

    public BvNegExpression(HornExpression x) {
        this.exp = x;
    }

    public BitVecExpr instantiate(GhiHornContext ctx) throws Z3Exception {

        Expr<? extends Sort> argExpr = null;
        if (exp instanceof HornConstant) {
            // If this is a constant try to cast as BV
            argExpr =  ((HornConstant) exp).instantiateAs(GhiHornType.BitVec, ctx);
        }
        else if (exp instanceof HornVariable) {
             // Same deal with variables, cast to BV
            argExpr =  ((HornVariable) exp).instantiateAs(GhiHornType.BitVec, ctx);
        }
        Verify.verify(argExpr != null, "BvNeg cannot be cast: " + exp);
        
        return ctx.mkBVNeg((BitVecExpr) argExpr);
    }

    @Override
    public String toString() {
        return new StringBuilder("~").append(exp.toString()).toString();
    }

    @Override
    public GhiHornType getType() {
        return GhiHornType.BitVec;
    }

    @Override
    public HornExpression[] getComponents() {
        return new HornExpression[] { exp };
    }

    /* (non-Javadoc)
     * @see java.lang.Object#hashCode()
     */
    
    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((exp == null) ? 0 : exp.hashCode());
        return result;
    }

    /* (non-Javadoc)
     * @see java.lang.Object#equals(java.lang.Object)
     */
    
    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (!(obj instanceof BvNegExpression))
            return false;
        BvNegExpression other = (BvNegExpression) obj;
        if (exp == null) {
            if (other.exp != null)
                return false;
        } else if (!exp.equals(other.exp))
            return false;
        return true;
    }

    
}

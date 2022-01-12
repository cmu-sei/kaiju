package kaiju.tools.ghihorn.hornifer.horn.expression;

import com.google.common.base.Verify;
import com.microsoft.z3.BoolExpr;
import com.microsoft.z3.Z3Exception;

import kaiju.tools.ghihorn.z3.GhiHornContext;
import kaiju.tools.ghihorn.z3.GhiHornType;

/**
 * A way to represent a negated expression
 */
public class BoolNotExpression implements HornExpression {
    private final HornExpression exp;

    /**
     * Create
     * 
     * @param x
     * @param isNegated
     */
    public BoolNotExpression(HornExpression x) {
        this.exp = x;
    }

    public BoolExpr instantiate(GhiHornContext ctx) throws Z3Exception {

        try {
            
            Verify.verify(exp.getType() == GhiHornType.Bool, "Bool Not requires boolean term: " + exp);
            return ctx.mkNot((BoolExpr) exp.instantiate(ctx));
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    @Override
    public String toString() {
        return new StringBuilder("!").append(exp).toString();
    }

    @Override
    public GhiHornType getType() {
        return GhiHornType.Bool;
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
        if (!(obj instanceof BoolNotExpression))
            return false;
        BoolNotExpression other = (BoolNotExpression) obj;
        if (exp == null) {
            if (other.exp != null)
                return false;
        } else if (!exp.equals(other.exp))
            return false;
        return true;
    }

    
}

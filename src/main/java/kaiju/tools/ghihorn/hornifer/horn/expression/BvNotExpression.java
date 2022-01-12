package kaiju.tools.ghihorn.hornifer.horn.expression;

import com.google.common.base.Verify;
import com.microsoft.z3.BitVecExpr;
import com.microsoft.z3.Z3Exception;

import kaiju.tools.ghihorn.z3.GhiHornContext;
import kaiju.tools.ghihorn.z3.GhiHornType;

public class BvNotExpression implements HornExpression {
    private final HornExpression exp;

    public BvNotExpression(HornExpression x) {
        this.exp = x;
    }

    public BitVecExpr instantiate(GhiHornContext ctx) throws Z3Exception {

        Verify.verify(exp.getType() == GhiHornType.BitVec,
                "BvNot operation expects bitvector term");

        return ctx.mkBVNot((BitVecExpr) exp.instantiate(ctx));
    }

    public GhiHornType getType() {
        return GhiHornType.BitVec;
    }

    @Override
    public String toString() {
        return new StringBuilder("!").append(exp.toString()).toString();
    }

    @Override
    public HornExpression[] getComponents() {
        return new HornExpression[] {exp};
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
        result = prime * result + ((exp == null) ? 0 : exp.hashCode());
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
        if (!(obj instanceof BvNotExpression))
            return false;
        BvNotExpression other = (BvNotExpression) obj;
        if (exp == null) {
            if (other.exp != null)
                return false;
        } else if (!exp.equals(other.exp))
            return false;
        return true;
    }
}

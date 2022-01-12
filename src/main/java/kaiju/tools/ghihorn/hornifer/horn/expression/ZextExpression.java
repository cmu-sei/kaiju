package kaiju.tools.ghihorn.hornifer.horn.expression;

import com.google.common.base.Verify;
import com.microsoft.z3.BitVecExpr;
import com.microsoft.z3.Z3Exception;

import kaiju.tools.ghihorn.z3.GhiHornContext;
import kaiju.tools.ghihorn.z3.GhiHornDataType;
import kaiju.tools.ghihorn.z3.GhiHornType;

public class ZextExpression implements HornExpression {
    private final HornExpression in, out;

    @Override
    public BitVecExpr instantiate(GhiHornContext ctx) throws Z3Exception {

        Verify.verify(in.getType() == GhiHornType.BitVec, "Zext requires bitvector term: " + in);
        Verify.verify(out.getType() == GhiHornType.BitVec, "Zext requires bitvector term: " + out);

        // Because bit vectors are 64 bit, this operation is moot

        BitVecExpr inExpr = (BitVecExpr) in.instantiate(ctx);
        BitVecExpr outExpr = (BitVecExpr) out.instantiate(ctx);

        int i = GhiHornDataType.BYTE_WIDTH * (outExpr.getSortSize() - inExpr.getSortSize());

        return ctx.mkZeroExt(i, inExpr);

    }

    /**
     * @param lhs
     * @param rhs
     */
    public ZextExpression(HornExpression out, HornExpression in) {

        this.out = out;
        this.in = in;
    }

    @Override
    public String toString() {
        return new StringBuilder("ZX[").append(in.toString()).append("]").toString();
    }

    @Override
    public GhiHornType getType() {
        return GhiHornType.BitVec;
    }

    @Override
    public HornExpression[] getComponents() {
        return new HornExpression[] { in, out };
    }

    /* (non-Javadoc)
     * @see java.lang.Object#hashCode()
     */
    
    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((in == null) ? 0 : in.hashCode());
        result = prime * result + ((out == null) ? 0 : out.hashCode());
        return result;
    }

    /* (non-Javadoc)
     * @see java.lang.Object#equals(java.lang.Object)
     */
    
    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (!(obj instanceof ZextExpression))
            return false;
        ZextExpression other = (ZextExpression) obj;
        if (in == null) {
            if (other.in != null)
                return false;
        } else if (!in.equals(other.in))
            return false;
        if (out == null) {
            if (other.out != null)
                return false;
        } else if (!out.equals(other.out))
            return false;
        return true;
    }
}
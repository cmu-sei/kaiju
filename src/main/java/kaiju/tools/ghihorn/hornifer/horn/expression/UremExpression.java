package kaiju.tools.ghihorn.hornifer.horn.expression;

import com.google.common.base.Verify;
import com.microsoft.z3.BitVecExpr;
import com.microsoft.z3.Z3Exception;

import kaiju.tools.ghihorn.z3.GhiHornContext;
import kaiju.tools.ghihorn.z3.GhiHornType;

public class UremExpression implements HornExpression {
    private final HornExpression lhs, rhs;

    @Override
    public BitVecExpr instantiate(GhiHornContext ctx) throws Z3Exception {

        Verify.verify(lhs.getType() == GhiHornType.BitVec, "Urem requires bitvector term: " + lhs);
        Verify.verify(rhs.getType() == GhiHornType.BitVec, "Urem requires bitvector term: " + rhs);

        BitVecExpr lhsExpr = (BitVecExpr) lhs.instantiate(ctx);
        BitVecExpr rhsExpr = (BitVecExpr) rhs.instantiate(ctx);

        return ctx.mkBVURem(lhsExpr, rhsExpr);
    }

    /**
     * @param lhs
     * @param rhs
     */
    public UremExpression(HornExpression lhs, HornExpression rhs) {

        this.lhs = lhs;
        this.rhs = rhs;
    }

    @Override
    public String toString() {
        return new StringBuilder(lhs.toString()).append(" % ").append(rhs.toString()).toString();
    }

    @Override
    public GhiHornType getType() {
        return GhiHornType.BitVec;
    }

    @Override
    public HornExpression[] getComponents() {
        return new HornExpression[] { lhs, rhs };
    }
}

package kaiju.tools.ghihorn.hornifer.horn.expression;

import com.google.common.base.Verify;
import com.microsoft.z3.BitVecExpr;
import com.microsoft.z3.BoolExpr;

import kaiju.tools.ghihorn.z3.GhiHornContext;
import kaiju.tools.ghihorn.z3.GhiHornType;

public class SleExpression implements HornExpression {
    private final HornExpression lhs, rhs;

    @Override
    public BoolExpr instantiate(GhiHornContext ctx) {

        Verify.verify(lhs.getType() == GhiHornType.BitVec, "Sle requires bitvector term: " + lhs);
        Verify.verify(rhs.getType() == GhiHornType.BitVec, "Sle requires bitvector term: " + rhs);

        BitVecExpr lhsExpr = (BitVecExpr) lhs.instantiate(ctx);
        BitVecExpr rhsExpr = (BitVecExpr) rhs.instantiate(ctx);

        return ctx.mkBVSLE(lhsExpr, rhsExpr);
    }

    /**
     * @param lhs
     * @param rhs
     */
    public SleExpression(HornExpression lhs, HornExpression rhs) {

        this.lhs = lhs;
        this.rhs = rhs;
    }

    @Override
    public String toString() {
        return new StringBuilder(lhs.toString()).append(" (S)<= ").append(rhs.toString()).toString();
    }

    @Override
    public GhiHornType getType() {
        return GhiHornType.Bool;
    }

    @Override
    public HornExpression[] getComponents() {
        return new HornExpression[] { lhs, rhs };
    }
}

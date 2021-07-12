package kaiju.tools.ghihorn.hornifer.horn.expression;

import com.google.common.base.Verify;
import com.microsoft.z3.BitVecExpr;
import com.microsoft.z3.BoolExpr;
import com.microsoft.z3.Z3Exception;

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

        // equality can be either boolean or bitvector but they must match
        Verify.verify(lhs.getType() == rhs.getType(), "Eq requires term types match " + lhs + ", " + rhs);

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
        return new HornExpression[] { lhs, rhs };
    }
}

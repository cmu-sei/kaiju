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

        Verify.verify(exp.getType() == GhiHornType.BitVec, "BvNot operation expects bitvector term");

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
        return new HornExpression[] { exp };
    }
}

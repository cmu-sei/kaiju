package kaiju.tools.ghihorn.hornifer.horn.expression;

import com.google.common.base.Verify;
import com.microsoft.z3.BitVecExpr;
import com.microsoft.z3.Z3Exception;

import kaiju.tools.ghihorn.z3.GhiHornContext;
import kaiju.tools.ghihorn.z3.GhiHornType;

public class BvNegExpression implements HornExpression {
    private final HornExpression exp;

    public BvNegExpression(HornExpression x) {
        this.exp = x;
    }

    public BitVecExpr instantiate(GhiHornContext ctx) throws Z3Exception {
        Verify.verify(exp.getType() == GhiHornType.BitVec, "And requires bitvector term: " + exp);
        return ctx.mkBVNeg((BitVecExpr) exp.instantiate(ctx));
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
}

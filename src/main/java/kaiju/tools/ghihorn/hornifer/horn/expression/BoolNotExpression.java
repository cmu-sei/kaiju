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

        Verify.verify(exp.getType() == GhiHornType.Bool, "Bool Not requires boolean term: " + exp);

        return ctx.mkNot((BoolExpr) exp.instantiate(ctx));
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
}

package kaiju.tools.ghihorn.hornifer.horn.expression;

import com.microsoft.z3.BoolExpr;
import com.microsoft.z3.Z3Exception;

import kaiju.tools.ghihorn.z3.GhiHornContext;
import kaiju.tools.ghihorn.z3.GhiHornType;

/**
 * Not equal expression. Note that any other expressed as a Not equal
 */
public class NeExpression implements HornExpression {
    private final HornExpression lhs, rhs;

    @Override
    public BoolExpr instantiate(GhiHornContext ctx) throws Z3Exception {
        // Not equal is a negation of an equals
        return ctx.mkNot(new EqExpression(lhs, rhs).instantiate(ctx));
    }

    /**
     * @param lhs
     * @param rhs
     */
    public NeExpression(HornExpression lhs, HornExpression rhs) {

        this.lhs = lhs;
        this.rhs = rhs;
    }

    @Override
    public String toString() {
        return new StringBuilder(lhs.toString()).append(" != ").append(rhs.toString()).toString();
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

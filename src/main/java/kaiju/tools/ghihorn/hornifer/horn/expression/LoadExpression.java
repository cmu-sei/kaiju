package kaiju.tools.ghihorn.hornifer.horn.expression;

import com.microsoft.z3.BitVecExpr;
import com.microsoft.z3.Expr;
import com.microsoft.z3.Sort;

import kaiju.tools.ghihorn.z3.GhiHornContext;
import kaiju.tools.ghihorn.z3.GhiHornType;

public class LoadExpression implements HornExpression {
    private final HornExpression index;

    @Override
    public Expr<? extends Sort> instantiate(GhiHornContext ctx) {
        return ctx.mkSelect(ctx.getMemoryExpr(), (BitVecExpr) index.instantiate(ctx));
    }

    /**
     * @param lhs
     * @param rhs
     */
    public LoadExpression(HornExpression i) {
        this.index = i;
    }

    @Override
    public String toString() {
        return new StringBuilder("MEMORY[").append(index.toString()).append("]").toString();
    }

    @Override
    public GhiHornType getType() {
        return GhiHornType.Undefined;
    }

    @Override
    public HornExpression[] getComponents() {
        return new HornExpression[] { index };
    }
}

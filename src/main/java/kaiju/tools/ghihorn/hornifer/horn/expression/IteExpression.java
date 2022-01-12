package kaiju.tools.ghihorn.hornifer.horn.expression;

import com.google.common.base.Verify;
import com.microsoft.z3.BitVecExpr;
import com.microsoft.z3.BoolExpr;
import com.microsoft.z3.Expr;
import com.microsoft.z3.Sort;

import kaiju.tools.ghihorn.z3.GhiHornContext;
import kaiju.tools.ghihorn.z3.GhiHornType;

/**
 * An if-then-else expression
 */
public class IteExpression implements HornExpression {
    private final HornExpression cond;
    private final HornExpression trueBranch;
    private final HornExpression falseBranch;

    /**
     * @param cond
     * @param trueBranch
     * @param falseBranch
     */
    public IteExpression(HornExpression cond, HornExpression trueBranch,
            HornExpression falseBranch) {

        this.cond = cond;
        this.trueBranch = trueBranch;
        this.falseBranch = falseBranch;
    }

    @Override
    public Expr<? extends Sort> instantiate(GhiHornContext ctx) {

        Verify.verify(trueBranch.getType() == falseBranch.getType(),
                "ITE requires true/false terms match " + trueBranch + ", " + falseBranch);

        BoolExpr condExpr = (BoolExpr) cond.instantiate(ctx);
        if (trueBranch.getType() == GhiHornType.Bool) {

            BoolExpr trueExpr = (BoolExpr) trueBranch.instantiate(ctx);
            BoolExpr falseExpr = (BoolExpr) falseBranch.instantiate(ctx);

            return ctx.mkITE(condExpr, trueExpr, falseExpr);
        }

        BitVecExpr trueExpr = (BitVecExpr) trueBranch.instantiate(ctx);
        BitVecExpr falseExpr = (BitVecExpr) falseBranch.instantiate(ctx);

        return ctx.mkITE(condExpr, trueExpr, falseExpr);

    }

    @Override
    public String toString() {
        return new StringBuilder("if: ").append(cond.toString()).append(" then: ")
                .append(trueBranch.toString())
                .append(" else: ").append(falseBranch.toString()).toString();
    }

    @Override
    public GhiHornType getType() {
        return GhiHornType.Undefined;
    }

    @Override
    public HornExpression[] getComponents() {
        return new HornExpression[] {cond, trueBranch, falseBranch};
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
        result = prime * result + ((cond == null) ? 0 : cond.hashCode());
        result = prime * result + ((falseBranch == null) ? 0 : falseBranch.hashCode());
        result = prime * result + ((trueBranch == null) ? 0 : trueBranch.hashCode());
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
        if (!(obj instanceof IteExpression))
            return false;
        IteExpression other = (IteExpression) obj;
        if (cond == null) {
            if (other.cond != null)
                return false;
        } else if (!cond.equals(other.cond))
            return false;
        if (falseBranch == null) {
            if (other.falseBranch != null)
                return false;
        } else if (!falseBranch.equals(other.falseBranch))
            return false;
        if (trueBranch == null) {
            if (other.trueBranch != null)
                return false;
        } else if (!trueBranch.equals(other.trueBranch))
            return false;
        return true;
    }
}

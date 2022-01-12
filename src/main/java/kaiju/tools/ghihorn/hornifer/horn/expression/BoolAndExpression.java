package kaiju.tools.ghihorn.hornifer.horn.expression;

import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;
import com.google.common.base.Verify;
import com.microsoft.z3.BoolExpr;
import com.microsoft.z3.Z3Exception;
import kaiju.tools.ghihorn.z3.GhiHornContext;
import kaiju.tools.ghihorn.z3.GhiHornType;

public class BoolAndExpression implements HornExpression {
    private final List<HornExpression> terms;

    @Override
    public BoolExpr instantiate(GhiHornContext ctx) throws Z3Exception {

        if (terms.isEmpty()) {
            return null;
        }
        long countOfNonBoolTypes =
                terms.stream().filter(t -> t.getType() != GhiHornType.Bool).count();

        Verify.verify(countOfNonBoolTypes == 0, "And requires boolean types for terms");

        final List<BoolExpr> termExprs = terms.stream()
                .map(t -> (BoolExpr) t.instantiate(ctx))
                .collect(Collectors.toList());

        return ctx.mkAnd(termExprs.toArray(new BoolExpr[0]));
    }

    /**
     * @param lhs
     * @param rhs
     */
    public BoolAndExpression(List<? extends HornExpression> terms) {
        this.terms = new ArrayList<>();
        this.terms.addAll(terms);
    }

    @Override
    public String toString() {
        final StringBuilder sb = new StringBuilder();
        int i = 0;
        for (HornExpression x : terms) {
            sb.append(x);
            if (i + 1 < terms.size()) {
                sb.append(" && ");
            }
            ++i;
        }
        return sb.toString();
    }

    @Override
    public GhiHornType getType() {
        return GhiHornType.Bool;
    }

    @Override
    public HornExpression[] getComponents() {
        return terms.toArray(new HornExpression[0]);
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
        result = prime * result + ((terms == null) ? 0 : terms.hashCode());
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
        if (!(obj instanceof BoolAndExpression))
            return false;
        BoolAndExpression other = (BoolAndExpression) obj;
        if (terms == null) {
            if (other.terms != null)
                return false;
        } else if (!terms.equals(other.terms))
            return false;
        return true;
    }


}

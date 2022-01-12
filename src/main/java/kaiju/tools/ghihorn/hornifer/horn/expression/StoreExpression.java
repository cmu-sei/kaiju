package kaiju.tools.ghihorn.hornifer.horn.expression;

import com.google.common.base.Verify;
import com.microsoft.z3.ArrayExpr;
import com.microsoft.z3.BitVecExpr;
import com.microsoft.z3.BitVecSort;
import com.microsoft.z3.Expr;
import com.microsoft.z3.Sort;

import kaiju.tools.ghihorn.z3.GhiHornContext;
import kaiju.tools.ghihorn.z3.GhiHornType;

public class StoreExpression implements HornExpression {
    private final HornExpression index;
    private final HornExpression value;

    @Override
    public Expr<? extends Sort> instantiate(GhiHornContext ctx) {

        Verify.verify(index.getType() == GhiHornType.BitVec, "Store requires bitvector index term: " + index);
        Verify.verify(value.getType() == GhiHornType.BitVec, "Store requires bitvector value term: " + value);

        BitVecExpr iExpr = (BitVecExpr) index.instantiate(ctx);
        BitVecExpr vExpr = (BitVecExpr) value.instantiate(ctx);

        ArrayExpr<BitVecSort, BitVecSort> memory = ctx.getMemoryExpr();

        // z3's store command return a new array expression
        ArrayExpr<BitVecSort, BitVecSort> updatedArrayExpr = ctx.mkStore(memory, iExpr, vExpr);

        return ctx.mkEq(memory, updatedArrayExpr);
    }

    /**
     * @param lhs
     * @param rhs
     */
    public StoreExpression(HornExpression i, HornExpression v) {
        this.index = i;
        this.value = v;
    }

    @Override
    public String toString() {
        return new StringBuilder("MEMORY[").append(index.toString()).append("] = ").append(value.toString()).toString();
    }

    @Override
    public GhiHornType getType() {
        return GhiHornType.Bool;
    }

    @Override
    public HornExpression[] getComponents() {
        return new HornExpression[] { index, value };
    }

    /* (non-Javadoc)
     * @see java.lang.Object#hashCode()
     */
    
    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((index == null) ? 0 : index.hashCode());
        result = prime * result + ((value == null) ? 0 : value.hashCode());
        return result;
    }

    /* (non-Javadoc)
     * @see java.lang.Object#equals(java.lang.Object)
     */
    
    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (!(obj instanceof StoreExpression))
            return false;
        StoreExpression other = (StoreExpression) obj;
        if (index == null) {
            if (other.index != null)
                return false;
        } else if (!index.equals(other.index))
            return false;
        if (value == null) {
            if (other.value != null)
                return false;
        } else if (!value.equals(other.value))
            return false;
        return true;
    }
}

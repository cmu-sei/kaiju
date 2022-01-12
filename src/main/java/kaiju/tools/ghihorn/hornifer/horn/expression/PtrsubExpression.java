package kaiju.tools.ghihorn.hornifer.horn.expression;

import com.google.common.base.Verify;
import com.microsoft.z3.BitVecExpr;
import com.microsoft.z3.Expr;
import com.microsoft.z3.Sort;

import kaiju.tools.ghihorn.z3.GhiHornContext;
import kaiju.tools.ghihorn.z3.GhiHornType;

public class PtrsubExpression implements HornExpression {

    private final HornExpression pointer;
    private final HornExpression offset;

    @Override
    public Expr<? extends Sort> instantiate(GhiHornContext ctx) {

        Verify.verify(offset.getType() == GhiHornType.BitVec,
                "Ptrsub requires bitvector offset term: " + offset);
        Verify.verify(pointer.getType() == GhiHornType.BitVec,
                "Ptrsub requires bitvector pointer term: " + pointer);

        BitVecExpr oExpr = (BitVecExpr) offset.instantiate(ctx);
        BitVecExpr pExpr = (BitVecExpr) pointer.instantiate(ctx);

        // A PTRSUB performs the simple pointer calculation, input0 + input1, but also
        // indicates explicitly that input0 is a reference to a structured data-type and
        // one of its subcomponents is being accessed. Input0 is a pointer to the
        // beginning of the structure, and input1 is a byte offset to the subcomponent.
        // As an operation, PTRSUB produces a pointer to the subcomponent and stores it
        // in output.

        return ctx.mkBVAdd(pExpr, oExpr);
    }

    /**
     * @param lhs
     * @param rhs
     */
    public PtrsubExpression(HornExpression p, HornExpression i) {
        this.pointer = p;
        this.offset = i;
    }

    @Override
    public String toString() {
        return new StringBuilder("PTRSUB[").append(pointer.toString()).append("+")
                .append(offset.toString()).append("]")
                .toString();
    }

    @Override
    public GhiHornType getType() {
        return GhiHornType.Undefined;
    }

    @Override
    public HornExpression[] getComponents() {
        return new HornExpression[] {pointer, offset};
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
        result = prime * result + ((offset == null) ? 0 : offset.hashCode());
        result = prime * result + ((pointer == null) ? 0 : pointer.hashCode());
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
        if (!(obj instanceof PtrsubExpression))
            return false;
        PtrsubExpression other = (PtrsubExpression) obj;
        if (offset == null) {
            if (other.offset != null)
                return false;
        } else if (!offset.equals(other.offset))
            return false;
        if (pointer == null) {
            if (other.pointer != null)
                return false;
        } else if (!pointer.equals(other.pointer))
            return false;
        return true;
    }
}

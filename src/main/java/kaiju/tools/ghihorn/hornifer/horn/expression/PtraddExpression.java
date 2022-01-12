package kaiju.tools.ghihorn.hornifer.horn.expression;

import com.google.common.base.Verify;
import com.microsoft.z3.BitVecExpr;
import com.microsoft.z3.Expr;
import com.microsoft.z3.Sort;

import kaiju.tools.ghihorn.hornifer.horn.variable.HornConstant;
import kaiju.tools.ghihorn.z3.GhiHornContext;
import kaiju.tools.ghihorn.z3.GhiHornType;

public class PtraddExpression implements HornExpression {

    private final HornExpression index;
    private final HornConstant size;

    @Override
    public Expr<? extends Sort> instantiate(GhiHornContext ctx) {

        Verify.verify(index.getType() == GhiHornType.BitVec,
                "Ptradd requires bitvector index term: " + index);

        BitVecExpr sizeExpr = size.instantiate(ctx);
        BitVecExpr indexExpr = (BitVecExpr) index.instantiate(ctx);

        // This operator serves as a more compact representation of the pointer
        // calculation, input0 + input1 * input2, but also indicates explicitly that
        // input0 is a reference to an array data-type. Input0 is a pointer to the
        // beginning of the array, input1 is an index into the array, and input2 is a
        // constant indicating the size of an element in the array. As an
        // operation, PTRADD produces the pointer value of the element at the indicated
        // index in the array and stores it in output.

        return ctx.mkBVMul(indexExpr, sizeExpr);

    }

    /**
     * @param lhs
     * @param rhs
     */
    public PtraddExpression(HornExpression i, HornConstant s) {
        this.size = s;
        this.index = i;
    }

    @Override
    public String toString() {
        return new StringBuilder("PTRADD[").append(index.toString()).append("*")
                .append(size.toString()).append("]")
                .toString();
    }

    @Override
    public GhiHornType getType() {
        return GhiHornType.Undefined;
    }

    @Override
    public HornExpression[] getComponents() {
        return new HornExpression[] {index, size};
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
        result = prime * result + ((index == null) ? 0 : index.hashCode());
        result = prime * result + ((size == null) ? 0 : size.hashCode());
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
        if (!(obj instanceof PtraddExpression))
            return false;
        PtraddExpression other = (PtraddExpression) obj;
        if (index == null) {
            if (other.index != null)
                return false;
        } else if (!index.equals(other.index))
            return false;
        if (size == null) {
            if (other.size != null)
                return false;
        } else if (!size.equals(other.size))
            return false;
        return true;
    }
}

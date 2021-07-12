package kaiju.tools.ghihorn.hornifer.horn.expression;

import com.google.common.base.Verify;
import com.microsoft.z3.ArrayExpr;
import com.microsoft.z3.BitVecExpr;
import com.microsoft.z3.BitVecSort;
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

        Verify.verify(index.getType() == GhiHornType.BitVec, "Ptradd requires bitvector index term: " + index);

        BitVecExpr sizeExpr = size.instantiate(ctx);
        BitVecExpr indexExpr = (BitVecExpr) index.instantiate(ctx);

        // This operator serves as a more compact representation of the pointer
        // calculation, input0
        // + input1 * input2, but also indicates explicitly that input0 is a reference
        // to an array
        // data-type. Input0 is a pointer to the beginning of the array, input1 is an
        // index into the
        // array, and input2 is a constant indicating the size of an element in the
        // array. As an
        // operation, PTRADD produces the pointer value of the element at the indicated
        // index in the
        // array and stores it in output.

        BitVecExpr i = ctx.mkBVMul(indexExpr, sizeExpr);
        ArrayExpr<BitVecSort, BitVecSort> memory = ctx.getMemoryExpr();
        return ctx.mkSelect(memory, i);
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
        return new StringBuilder("PTRADD[").append(index.toString()).append("*").append(size.toString()).append("]")
                .toString();
    }

    @Override
    public GhiHornType getType() {
        return GhiHornType.Undefined;
    }

    @Override
    public HornExpression[] getComponents() {
        return new HornExpression[] { index, size };
    }
}

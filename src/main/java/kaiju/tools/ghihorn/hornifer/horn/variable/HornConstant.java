package kaiju.tools.ghihorn.hornifer.horn.variable;

import com.microsoft.z3.BitVecExpr;
import com.microsoft.z3.Expr;
import com.microsoft.z3.Sort;
import ghidra.program.model.pcode.HighConstant;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.pcode.VarnodeAST;
import ghidra.program.model.scalar.Scalar;
import kaiju.tools.ghihorn.z3.GhiHornBitVectorType;
import kaiju.tools.ghihorn.z3.GhiHornContext;
import kaiju.tools.ghihorn.z3.GhiHornType;

public class HornConstant extends HornVariable {
    private Scalar value;

    public HornConstant(HornConstant other) {

        this.value = other.value;
        this.type = other.type;
        this.scope = Scope.Unknown;

        // Scope and name mean nothing in a constant
    }

    /**
     * Make a horn constant from a high constant
     * 
     * @param highConst
     */
    public HornConstant(HighConstant highConst) {

        this.value = highConst.getScalar();
        this.type = new GhiHornBitVectorType();
        this.scope = Scope.Unknown;
    }

    public HornConstant(Varnode vn) {

        if (vn.getAddress().getAddressSpace().isConstantSpace()
                || vn.getAddress().getAddressSpace().isMemorySpace()) {
            value = new Scalar(vn.getSize(), vn.getOffset());
        }

        if (vn instanceof VarnodeAST) {
            name = new HornVariableName("const" + ((VarnodeAST) vn).getUniqueId());
        }

        type = new GhiHornBitVectorType();
        scope = Scope.Unknown;
    }

    public HornConstant(long val) {
        super(new HornVariableName("const"), new GhiHornBitVectorType(), Scope.Unknown);
        value = new Scalar(Long.SIZE, val);
    }

    public HornConstant(int val) {
        super(new HornVariableName("const"), new GhiHornBitVectorType(), Scope.Unknown);
        value = new Scalar(Integer.SIZE, val);
    }

    public HornConstant(byte val) {
        super(new HornVariableName("const"), new GhiHornBitVectorType(), Scope.Unknown);

        // widening should be fine
        value = new Scalar(Byte.SIZE, val);
    }

    /**
     * Default to instantiate as a bitvector
     */
    @Override
    public BitVecExpr instantiate(GhiHornContext ctx) {
        return ctx.mkBV64(value.getValue());
    }

    /**
     * Instantiate as a preferred type. Currently only boolean is checked
     */
    @Override
    public Expr<? extends Sort> instantiateAs(GhiHornType preferredType, GhiHornContext ctx) {
        if (preferredType == GhiHornType.Bool) {

            // Boolean types are sometimes typedef'd to scalar types, in this case
            // assume that 1 and 0 will be used to represent true and false respectively
            
            if (value.getValue() == 1) {
                return ctx.mkTrue();

            } else if (value.getValue() == 0) {
                return ctx.mkFalse();
            }
        } // Are other types possible? Such as array types?

        // The default is to revert to a bitvector, which may yield a mixed type when
        // a type error when added to an operation, such as equals
        return instantiate(ctx);
    }

    /**
     * @return the value
     */
    public Long getValue() {
        return value.getValue();
    }

    @Override
    public String toString() {
        return super.toString() + "=" + Long.toHexString(value.getValue());
    }

    /**
     * The name is the string representation of the variable value
     */
    public String getName() {
        return toString();
    }

    /*
     * (non-Javadoc)
     * 
     * @see java.lang.Object#hashCode()
     */

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = super.hashCode();
        result = prime * result + ((value == null) ? 0 : value.hashCode());
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
        if (!super.equals(obj))
            return false;
        if (!(obj instanceof HornConstant))
            return false;
        HornConstant other = (HornConstant) obj;
        if (value == null) {
            if (other.value != null)
                return false;
        } else if (!value.equals(other.value))
            return false;
        return true;
    }
}

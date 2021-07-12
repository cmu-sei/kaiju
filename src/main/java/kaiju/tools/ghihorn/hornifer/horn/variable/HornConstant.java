package kaiju.tools.ghihorn.hornifer.horn.variable;

import com.microsoft.z3.BitVecExpr;

import ghidra.program.model.pcode.HighConstant;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.pcode.VarnodeAST;
import ghidra.program.model.scalar.Scalar;
import kaiju.tools.ghihorn.z3.GhiHornBitVectorType;
import kaiju.tools.ghihorn.z3.GhiHornContext;

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

        if (vn.getAddress().getAddressSpace().isConstantSpace() || vn.getAddress().getAddressSpace().isMemorySpace()) {
            value = new Scalar(Long.SIZE, vn.getOffset());
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

    /**
     * Currently constants are all bitvectors
     */
    @Override
    public BitVecExpr instantiate(GhiHornContext ctx) {
        return ctx.mkBV64(value.getValue());
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
}

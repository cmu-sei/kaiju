package kaiju.tools.ghihorn.hornifer.horn.expression;

import java.util.ArrayList;
import java.util.List;
import com.microsoft.z3.BitVecExpr;
import com.microsoft.z3.BoolExpr;
import com.microsoft.z3.Expr;
import com.microsoft.z3.Sort;
import ghidra.program.model.address.Address;
import ghidra.program.model.pcode.HighVariable;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import ghidra.util.Msg;
import kaiju.tools.ghihorn.exception.GhiHornException;
import kaiju.tools.ghihorn.hornifer.horn.variable.HornConstant;
import kaiju.tools.ghihorn.hornifer.horn.variable.HornVariable;
import kaiju.tools.ghihorn.hornifer.horn.variable.HornVariable.Scope;
import kaiju.tools.ghihorn.hornifer.horn.variable.HornVariableName;
import kaiju.tools.ghihorn.z3.GhiHornBitVectorType;
import kaiju.tools.ghihorn.z3.GhiHornContext;
import kaiju.tools.ghihorn.z3.GhiHornType;

/**
 * Expressions that represent a p-code operation. They basically have the form:
 * 
 * out = OP(in...)
 */
public class PcodeExpression implements HornExpression {

    private final List<HornVariable> defVariables;
    private final List<HornVariable> useVariables;
    private final List<HornVariable> inVariables;
    private HornVariable outVariable;
    private HornExpression operation;
    private final PcodeOp pcode;
    private Address address;

    /**
     * @param defVariables
     * @param useVariables
     * @param inVariables
     * @param outVariable
     */

    public PcodeExpression(PcodeOp pcode, Address address) {
        this(pcode);
        this.address = address;
    }

    public PcodeExpression(PcodeOp pcode) {

        this.defVariables = new ArrayList<>();
        this.useVariables = new ArrayList<>();
        this.inVariables = new ArrayList<>();
        this.outVariable = null;
        this.operation = null;
        this.pcode = pcode;
        this.address = pcode.getSeqnum().getTarget();

        if (pcode.getOpcode() == PcodeOp.INDIRECT) {
            // INDIRECT pcodes are ignored by makeOperation(), but can still
            // raise an exception when the input is a constant larger than 64
            // bits.  Ideally we should move the call to computeIOVariables into
            // makeOperation, but for now we'll just exit early when we see
            // INDIRECT.
            return;
        }

        // First the I/O variables must be computed
        try {
            computeIOVariables();
        } catch (Exception e) {
            StringBuilder errorMessage = new StringBuilder("Failed to generate variables for p-code");
            if (this.address != null) {
                errorMessage.append(" at address " + this.address.toString() + ": ");
            } else {
                errorMessage.append(":");
            }
            errorMessage.append(pcode);
            errorMessage.append(", exception: " + e.getMessage());
            errorMessage.append(". This is an issue with Ghidra's HighConstant class.");
            Msg.error(this, errorMessage);
            throw new GhiHornException(errorMessage.toString());
        }

        // Second the operations need to be generated from the I/O variables. This will
        // in effect identify the def/use variables because p-code has an equational
        // format where output = OP(inputs ...). The def variable is the output and the
        // use variables are the inputs

        makeOperation();

        computeDefUseVariables();
    }

    @Override
    public HornExpression[] getComponents() {
        if (operation != null) {
            return operation.getComponents();
        }
        return new HornExpression[0];
    }

    /**
     * generate input/output variables
     */
    private void computeIOVariables() {

        for (int i = 0; i < pcode.getNumInputs(); i++) {

            Varnode vin = pcode.getInput(i);
            HighVariable highVar = vin.getHigh();

            if (highVar != null) {
                HornVariable v = HornVariable.mkVariable(highVar);
                inVariables.add(v);
            } else {
                if (vin.isConstant()) {
                    inVariables.add(new HornConstant(vin));
                } else {
                    // We have a varnode that has no high variable backing it. Create an empty
                    // variable
                    inVariables.add(
                            new HornVariable(new HornVariableName(String.valueOf(vin.getOffset())),
                                    new GhiHornBitVectorType(), Scope.Unknown));
                }
            }
        }

        Varnode vout = pcode.getOutput();
        if (vout != null) {
            HighVariable outHighVar = vout.getHigh();
            if (outHighVar != null) {
                outVariable = HornVariable.mkVariable(outHighVar);
            } else {
                // No high variable, take a similar approach as for inputs
                if (vout.isConstant()) {
                    outVariable = new HornConstant(vout);
                } else {
                    outVariable =
                            new HornVariable(new HornVariableName(String.valueOf(vout.getOffset())),
                                    new GhiHornBitVectorType(), Scope.Unknown);
                }
            }
        }
    }

    private void makeOperation() {
        try {
            if (pcode.getOpcode() == PcodeOp.INT_LESSEQUAL) {
                operation = new UleExpression(inVariables.get(0), inVariables.get(1));
            } else if (pcode.getOpcode() == PcodeOp.INT_LESS) {
                operation = new UltExpression(inVariables.get(0), inVariables.get(1));
            } else if (pcode.getOpcode() == PcodeOp.INT_SLESS) {
                operation = new SltExpression(inVariables.get(0), inVariables.get(1));
            } else if (pcode.getOpcode() == PcodeOp.INT_SLESSEQUAL) {
                operation = new SleExpression(inVariables.get(0), inVariables.get(1));
            } else if (pcode.getOpcode() == PcodeOp.INT_ADD) {
                operation = new AddExpression(inVariables.get(0), inVariables.get(1));
            } else if (pcode.getOpcode() == PcodeOp.INT_ZEXT) {
                if (!inVariables.isEmpty() && outVariable != null) {
                    HornVariable inVar = inVariables.get(0);
                    if (outVariable.getType() == GhiHornType.BitVec
                            && inVar.getType() == GhiHornType.BitVec) {
                        operation = new ZextExpression(outVariable, inVariables.get(0));
                    }
                }
            } else if (pcode.getOpcode() == PcodeOp.INT_SEXT) {
                if (!inVariables.isEmpty() && outVariable != null) {
                    HornVariable inVar = inVariables.get(0);
                    if (outVariable.getType() == GhiHornType.BitVec
                            && inVar.getType() == GhiHornType.BitVec) {
                        operation = new SextExpression(outVariable, inVariables.get(0));
                    }
                }
            } else if (pcode.getOpcode() == PcodeOp.INT_SUB) {
                operation = new SubExpression(inVariables.get(0), inVariables.get(1));
            } else if (pcode.getOpcode() == PcodeOp.INT_MULT) {
                operation = new MulExpression(inVariables.get(0), inVariables.get(1));
            } else if (pcode.getOpcode() == PcodeOp.INT_DIV) {
                operation = new UdivExpression(inVariables.get(0), inVariables.get(1));
            } else if (pcode.getOpcode() == PcodeOp.INT_SDIV) {
                operation = new SdivExpression(inVariables.get(0), inVariables.get(1));
            } else if (pcode.getOpcode() == PcodeOp.INT_AND) {
                operation = new AndExpression(inVariables.get(0), inVariables.get(1));
            } else if (pcode.getOpcode() == PcodeOp.BOOL_AND) {
                operation = new BoolAndExpression(inVariables);
            } else if (pcode.getOpcode() == PcodeOp.INT_OR) {
                operation = new BvOrExpression(inVariables.get(0), inVariables.get(1));
            } else if (pcode.getOpcode() == PcodeOp.BOOL_OR) {
                operation = new BoolOrExpression(inVariables);
            }

            // Treating XOR the same for INT and BOOL versions seems wrong, but
            // more evidence is needed to figure out the proper way to do this.

            else if (pcode.getOpcode() == PcodeOp.INT_XOR
                    || pcode.getOpcode() == PcodeOp.BOOL_XOR) {
                operation = new XorExpression(inVariables.get(0), inVariables.get(1));
            }

            else if (pcode.getOpcode() == PcodeOp.INT_NOTEQUAL) {
                operation = new NeExpression(inVariables.get(0), inVariables.get(1));
            } else if (pcode.getOpcode() == PcodeOp.INT_EQUAL) {
                operation = new EqExpression(inVariables.get(0), inVariables.get(1));
            } else if (pcode.getOpcode() == PcodeOp.INT_LEFT) {
                operation = new ShlExpression(inVariables.get(0), inVariables.get(1));
            } else if (pcode.getOpcode() == PcodeOp.INT_SRIGHT) {
                operation = new AshrExpression(inVariables.get(0), inVariables.get(1));
            } else if (pcode.getOpcode() == PcodeOp.INT_RIGHT) {
                operation = new ShrExpression(inVariables.get(0), inVariables.get(1));
            } else if (pcode.getOpcode() == PcodeOp.INT_NEGATE) {
                operation = new BvNotExpression(inVariables.get(0));
            } else if (pcode.getOpcode() == PcodeOp.BOOL_NEGATE) {
                operation = new BoolNotExpression(inVariables.get(0));
            } else if (pcode.getOpcode() == PcodeOp.INT_2COMP) {
                operation = new BvNegExpression(inVariables.get(0));
            } else if (pcode.getOpcode() == PcodeOp.INT_SREM) {
                operation = new SremExpression(inVariables.get(0), inVariables.get(1));
            } else if (pcode.getOpcode() == PcodeOp.INT_REM) {
                operation = new UremExpression(inVariables.get(0), inVariables.get(1));
            } else if (pcode.getOpcode() == PcodeOp.CAST || pcode.getOpcode() == PcodeOp.COPY) {
                // For now JSG is treating CAST like a copy. I need to really
                // think about how to do this right.
                if (!inVariables.isEmpty() && outVariable != null) {
                    operation = new CopyExpression(inVariables.get(0));
                }
            } else if (pcode.getOpcode() == PcodeOp.LOAD) {
                operation = new LoadExpression(inVariables.get(1));
            } else if (pcode.getOpcode() == PcodeOp.STORE) {
                operation = new StoreExpression(inVariables.get(1), inVariables.get(2));
            } else if (pcode.getOpcode() == PcodeOp.PTRSUB) {
                operation = new PtrsubExpression(inVariables.get(0), inVariables.get(1));
            } else if (pcode.getOpcode() == PcodeOp.PTRADD) {
                operation =
                        new PtraddExpression(inVariables.get(1), (HornConstant) inVariables.get(2));
            }
        } catch (VerifyError vx) {
            Msg.error(this, vx.getMessage());
            operation = null;
        }
    }

    /**
     * Determine the def/use variables based on operation structure
     */
    private void computeDefUseVariables() {

        if (this.operation != null) {
            for (HornExpression x : this.operation.getComponents()) {
                if (x instanceof HornVariable) {
                    if (!(x instanceof HornConstant)) { // do not save constants as use variables
                        this.useVariables.add((HornVariable) x);
                    }
                }
            }
        }
        if (this.outVariable != null) {
            this.defVariables.add(this.outVariable);
        }
    }

    /**
     * @return the pcode
     */
    public HornExpression getOperation() {
        return this.operation;
    }

    /**
     * @return the defVariables
     */
    public List<HornVariable> getDefVariables() {
        return defVariables;
    }

    /**
     * @return the useVariables
     */
    public List<HornVariable> getUseVariables() {
        return useVariables;
    }

    /**
     * @return the inVariables
     */
    public List<HornVariable> getInVariables() {
        return inVariables;
    }

    public int getArity() {
        return inVariables.size();
    }

    /**
     * @return the outVariable
     */
    public HornVariable getOutVariable() {
        return outVariable;
    }

    public boolean hasOutputVariable() {
        // if the output variable is not null, then this will be an equality
        return (outVariable != null);
    }

    @Override
    public BoolExpr instantiate(GhiHornContext ctx) {

        try {
            if (operation != null) {

                if (outVariable != null) {

                    // All exprs have an equational format (= output input)
                    // The only concern is what to do when there is no output

                    if (operation.getType() == GhiHornType.Bool) {

                        // If the operation type is boolean, then make sure the
                        // output variable is a boolean

                        BoolExpr outExpr =
                                (BoolExpr) outVariable.instantiateAs(GhiHornType.Bool, ctx);
                        Expr<? extends Sort> pcodeExpr = operation.instantiate(ctx);
                        if (!pcodeExpr.isBool()) {
                            Msg.error(this, "Error: Cannot instantiate " + toString());
                        }

                        return ctx.mkEq(outExpr, (BoolExpr) pcodeExpr);
                    }

                    BitVecExpr outExpr =
                            (BitVecExpr) outVariable.instantiateAs(GhiHornType.BitVec, ctx);
                    BitVecExpr pcodeExpr = (BitVecExpr) operation.instantiate(ctx);
                    return ctx.mkEq(outExpr, pcodeExpr);
                }

                // There is no output but there is a pcode expression. If this expression is a
                // boolean, then accept it

                if (operation.getType() == GhiHornType.Bool) {
                    return (BoolExpr) operation.instantiate(ctx);
                }
            }
        } catch (Exception z3x) {
            Msg.error(this, "Failed to make expression for P-Code: " + this);
            // z3x.printStackTrace();
        }
        // This p-code operation cannot be instantiated
        return null;
    }

    @Override
    public GhiHornType getType() {
        // all P-code operations are boolean because they are equalities
        return GhiHornType.Bool;
    }

    @Override
    public String toString() {

        StringBuilder sb = new StringBuilder("PCODE=");
        sb.append(pcode).append(", EXPR=");
        if (hasOutputVariable()) {
            sb.append(outVariable).append("=");
        }
        if (operation != null) {
            sb.append(operation);
        }

        return sb.toString();
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
        result = prime * result + ((defVariables == null) ? 0 : defVariables.hashCode());
        result = prime * result + ((inVariables == null) ? 0 : inVariables.hashCode());
        result = prime * result + ((operation == null) ? 0 : operation.hashCode());
        result = prime * result + ((outVariable == null) ? 0 : outVariable.hashCode());
        result = prime * result + ((pcode == null) ? 0 : pcode.hashCode());
        result = prime * result + ((useVariables == null) ? 0 : useVariables.hashCode());
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
        if (!(obj instanceof PcodeExpression))
            return false;
        PcodeExpression other = (PcodeExpression) obj;
        if (defVariables == null) {
            if (other.defVariables != null)
                return false;
        } else if (!defVariables.equals(other.defVariables))
            return false;
        if (inVariables == null) {
            if (other.inVariables != null)
                return false;
        } else if (!inVariables.equals(other.inVariables))
            return false;
        if (operation == null) {
            if (other.operation != null)
                return false;
        } else if (!operation.equals(other.operation))
            return false;
        if (outVariable == null) {
            if (other.outVariable != null)
                return false;
        } else if (!outVariable.equals(other.outVariable))
            return false;
        if (pcode == null) {
            if (other.pcode != null)
                return false;
        } else if (!pcode.equals(other.pcode))
            return false;
        if (useVariables == null) {
            if (other.useVariables != null)
                return false;
        } else if (!useVariables.equals(other.useVariables))
            return false;
        return true;
    }
}

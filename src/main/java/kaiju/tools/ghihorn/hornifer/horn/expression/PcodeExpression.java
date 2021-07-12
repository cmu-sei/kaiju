package kaiju.tools.ghihorn.hornifer.horn.expression;

import java.util.ArrayList;
import java.util.List;

import com.microsoft.z3.BitVecExpr;
import com.microsoft.z3.BoolExpr;
import com.microsoft.z3.Expr;
import com.microsoft.z3.Sort;
import com.microsoft.z3.Z3Exception;

import ghidra.program.model.pcode.HighVariable;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import ghidra.util.Msg;
import kaiju.tools.ghihorn.hornifer.horn.variable.HornConstant;
import kaiju.tools.ghihorn.hornifer.horn.variable.HornVariable;
import kaiju.tools.ghihorn.z3.GhiHornBitVectorType;
import kaiju.tools.ghihorn.z3.GhiHornBooleanType;
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

    /**
     * @param defVariables
     * @param useVariables
     * @param inVariables
     * @param outVariable
     */
    public PcodeExpression(PcodeOp pcode) {

        this.defVariables = new ArrayList<>();
        this.useVariables = new ArrayList<>();
        this.inVariables = new ArrayList<>();
        this.outVariable = null;
        this.operation = null;
        this.pcode = pcode;

        computeIOVariables();
        computeDefUseVariables();
        makeOperation();
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
                inVariables.add(new HornConstant(vin));
            }
        }

        Varnode vout = pcode.getOutput();
        if (vout != null) {
            HighVariable outHighVar = vout.getHigh();
            outVariable = HornVariable.mkVariable(outHighVar);
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
                    if (outVariable.getType() == GhiHornType.BitVec && inVar.getType() == GhiHornType.BitVec) {
                        operation = new ZextExpression(outVariable, inVariables.get(0));
                    }
                }
            } else if (pcode.getOpcode() == PcodeOp.INT_SEXT) {
                if (!inVariables.isEmpty() && outVariable != null) {
                    HornVariable inVar = inVariables.get(0);
                    if (outVariable.getType() == GhiHornType.BitVec && inVar.getType() == GhiHornType.BitVec) {
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
            } else if (pcode.getOpcode() == PcodeOp.INT_AND || pcode.getOpcode() == PcodeOp.BOOL_AND) {
                operation = new AndExpression(inVariables.get(0), inVariables.get(1));
            } else if (pcode.getOpcode() == PcodeOp.INT_OR || pcode.getOpcode() == PcodeOp.BOOL_OR) {
                operation = new OrExpression(inVariables.get(0), inVariables.get(1));
            } else if (pcode.getOpcode() == PcodeOp.INT_XOR || pcode.getOpcode() == PcodeOp.BOOL_XOR) {
                operation = new XorExpression(inVariables.get(0), inVariables.get(1));
            } else if (pcode.getOpcode() == PcodeOp.INT_NOTEQUAL) {
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
                operation = inVariables.get(0);
            } else if (pcode.getOpcode() == PcodeOp.LOAD) {
                operation = new LoadExpression(inVariables.get(1));
            } else if (pcode.getOpcode() == PcodeOp.STORE) {
                operation = new StoreExpression(inVariables.get(1), inVariables.get(2));
            } else if (pcode.getOpcode() == PcodeOp.PTRSUB) {
                operation = new PtrsubExpression(inVariables.get(0), inVariables.get(1));
            } else if (pcode.getOpcode() == PcodeOp.PTRADD) {
                operation = new PtraddExpression(inVariables.get(1), (HornConstant) inVariables.get(2));
            }
        } catch (VerifyError vx) {
            Msg.error(this, vx.getMessage());
            vx.getStackTrace();
            operation = null;
        }
    }

    /**
     * Determine the def/use variables based on operation
     */
    private void computeDefUseVariables() {
        if (!inVariables.isEmpty()) {

            switch (this.pcode.getOpcode()) {
            // Operations with two use inputs
            case PcodeOp.INT_LESSEQUAL:
            case PcodeOp.INT_SLESSEQUAL:
            case PcodeOp.INT_SLESS:
            case PcodeOp.INT_LESS:
            case PcodeOp.INT_ADD:
            case PcodeOp.INT_SUB:
            case PcodeOp.INT_MULT:
            case PcodeOp.INT_DIV:
            case PcodeOp.INT_SDIV:
            case PcodeOp.INT_AND:
            case PcodeOp.BOOL_AND:
            case PcodeOp.INT_OR:
            case PcodeOp.BOOL_OR:
            case PcodeOp.INT_XOR:
            case PcodeOp.BOOL_XOR:
            case PcodeOp.INT_NOTEQUAL:
            case PcodeOp.INT_EQUAL:
            case PcodeOp.INT_LEFT:
            case PcodeOp.INT_RIGHT:
            case PcodeOp.INT_SRIGHT:
            case PcodeOp.INT_REM:
            case PcodeOp.INT_SREM:
                useVariables.add(inVariables.get(0));
                useVariables.add(inVariables.get(1));
                break;
            // Operations with one use variable
            case PcodeOp.INT_ZEXT:
            case PcodeOp.INT_SEXT:
            case PcodeOp.INT_NEGATE:
            case PcodeOp.BOOL_NEGATE:
            case PcodeOp.INT_2COMP:
            case PcodeOp.CAST:
            case PcodeOp.COPY:
                useVariables.add(inVariables.get(0));
                break;
            // CBRANCH's last input
            case PcodeOp.CBRANCH:
            case PcodeOp.LOAD:
            case PcodeOp.PTRSUB:
                useVariables.add(inVariables.get(1));
                break;
            case PcodeOp.STORE:
            case PcodeOp.PTRADD:
                useVariables.add(inVariables.get(1));
                useVariables.add(inVariables.get(2));
            default:
                break;
            }
        }

        if (outVariable != null) {
            defVariables.add(outVariable);
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

                        BoolExpr outExpr = (BoolExpr) outVariable.instantiateAs(ctx, new GhiHornBooleanType());
                        Expr<? extends Sort> pcodeExpr = operation.instantiate(ctx);
                        if (!pcodeExpr.isBool()) {
                            Msg.info(this, "Error");
                        }
                        // BoolExpr pcodeExpr = (BoolExpr) operation.instantiate(ctx);
                        return ctx.mkEq(outExpr, (BoolExpr) pcodeExpr);
                    }

                    BitVecExpr outExpr = (BitVecExpr) outVariable.instantiateAs(ctx, new GhiHornBitVectorType());
                    BitVecExpr pcodeExpr = (BitVecExpr) operation.instantiate(ctx);
                    return ctx.mkEq(outExpr, pcodeExpr);
                }

                // There is no output but there is a pcode expression. If this expression is a
                // boolean, then accept it

                if (operation.getType() == GhiHornType.Bool) {
                    return (BoolExpr) operation.instantiate(ctx);
                }
            }
        } catch (Z3Exception z3x) {
            Msg.error(this, "Failed to make expression for P-Code: " + this);
            z3x.printStackTrace();
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
}

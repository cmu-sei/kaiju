package kaiju.tools.ghihorn.z3;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import com.microsoft.z3.ArrayExpr;
import com.microsoft.z3.ArraySort;
import com.microsoft.z3.BitVecExpr;
import com.microsoft.z3.BitVecSort;
import com.microsoft.z3.BoolExpr;
import com.microsoft.z3.BoolSort;
import com.microsoft.z3.Context;
import com.microsoft.z3.Expr;
import com.microsoft.z3.FPExpr;
import com.microsoft.z3.FuncDecl;
import com.microsoft.z3.Quantifier;
import com.microsoft.z3.Sort;

import ghidra.program.model.pcode.HighConstant;
import ghidra.program.model.pcode.Varnode;
import ghidra.util.Msg;
import kaiju.tools.ghihorn.hornifer.horn.variable.HornVariable;


public class GhiHornContext extends Context {
    public static String MEMORY_NAME = "Memory";
    
    private ArrayExpr<BitVecSort, BitVecSort> memoryArrayExpr = null;

    /**
     * Create a unconfigured Z3
     */
    public GhiHornContext() {
        super();
    }

    /**
     * Create a configured Z3
     *
     * @param settings
     */
    public GhiHornContext(Map<String, String> settings) {
        super(settings);
    }

    /**
     * Make a 64bit bitvector expression.
     * 
     * @param val
     * @return
     */
    public BitVecExpr mkBV64(long val) {
        return mkBV(val, GhiHornDataType.SIZE_64BIT);
    }

    public BitVecExpr mk64bBVConst(final String name) {
        return mkBVConst(name, GhiHornDataType.SIZE_64BIT);
    }

    public Expr<ArraySort<? extends Sort, ? extends Sort>> mkArrayVariableExpr(final String name, GhiHornDataType indexType,
            GhiHornDataType valueType) {
        Sort indexSort = indexType.mkSort(this);
        Sort valueSort = valueType.mkSort(this);
        if (indexSort != null && valueSort != null) {
            ArraySort<? extends Sort, ? extends Sort> arrayType = mkArraySort(indexSort, valueSort);
            return mkConst(name, arrayType);
        }
        return null;
    }

    public Expr<? extends Sort> mkStructVariable(String name) {
        throw new RuntimeException("mkStructVariable unimplemented");
    }

    /**
     * Determine the type of this expression
     * 
     * @param expr
     * @return
     */
    public GhiHornType getExprType(Expr<?> expr) {

        if (expr.isInt()) {
            return GhiHornType.Int;
        } else if (expr instanceof FPExpr) {
            return GhiHornType.Float;
        } else if (expr.isBool()) {
            return GhiHornType.Bool;
        } else if (expr.isBV()) {
            return GhiHornType.BitVec;
        } else if (expr.isString()) {
            return GhiHornType.String;
        } else if (expr.isArray()) {
            return GhiHornType.Array;
        }
        return GhiHornType.Undefined;
    }

    /**
     * 
     * @param v
     * @return
     */
    public Sort mkVariableSort(final HornVariable v) {

        // Arrays are special
        if (v.getType() == GhiHornType.Array) {
            final GhiHornArrayType arrayType = (GhiHornArrayType) v.getDataType();

            Sort idxSort = arrayType.getIndexDataType().mkSort(this);
            Sort valSort = arrayType.getValueDataType().mkSort(this); // mkSortForType(va.getValueType());
            if (idxSort != null || valSort != null) {
                return mkArraySort(idxSort, valSort);
            }
            return null;
        }
        return v.getDataType().mkSort(this);

    }

    /**
     * Check to make sure that this is actually a variable use (i.e. not a
     * numeric/literal access)
     * 
     * @param expr
     * @return
     */
    public boolean isExprValidVariable(Expr<?> expr) {
        // TODO: Possible check isConst
        return (expr != null && !expr.isNumeral() && !expr.toString().equals("true")
                && !expr.toString().equals("false"));
    }

    public Expr<? extends Sort> mkIntVariableExpr(final String name) {
        return mkIntConst(name);
    }

    public Expr<? extends Sort> mkBoolVariableExpr(final String name) {
        return mkBoolConst(name);
    }

    public Expr<? extends Sort> mkBitvecVariableExpr(final String name, int size) {
        // the size is in bytes, but the BV is in bits
        // return mk64bBVConst(name);
        return mkBVConst(name, size);
    }

    public Expr<? extends Sort> mkStringVariableExpr(final String name) {
        return mkString(name);
    }

    public Expr<? extends Sort> mkFloatVariableExpr(final String name) {
        return mkConst(name, mkFPSort(GhiHornDataType.FLOAT_EBITS, GhiHornDataType.FLOAT_SBITS));
    }

    /**
     * 
     */
    public BitVecExpr mkConstantExpr(final Varnode vn) {
        // Sometimes the high variable is null for constant space or memory
        // space
        if (vn.getAddress().getAddressSpace().isConstantSpace() || vn.getAddress().getAddressSpace().isMemorySpace()) {
            return mkBV64(Long.valueOf(vn.getOffset()).intValue());
        }
        return null;
    }

    /**
     * 
     * @param highConst
     * @return
     */
    public BitVecExpr mkConstantExpr(final HighConstant highConst) {

        Varnode vConst = highConst.getRepresentative();
        long value = vConst.getOffset();
        if (highConst.getSize() * GhiHornDataType.BYTE_WIDTH <= GhiHornDataType.SIZE_64BIT) {
            return mkBV(highConst.getScalar().getValue(), GhiHornDataType.SIZE_64BIT);
        } else if (value == -1) {
            return mkBV64(-1);
        }

        try {

            byte[] longBytes = ByteBuffer.allocate(vConst.getSize()).putLong(value).array();
            BigInteger biValue = new BigInteger(longBytes, 0, vConst.getSize());

            return mkBV64(biValue.longValueExact());

        } catch (ArithmeticException ax) {
            Msg.warn(this, "Data lost when converting value that is wider than 64 bits. Varnode: " + vConst);
        }
        return null;
    }

    public FuncDecl<BoolSort> mkRelation(final String name) {
        return mkFact(name);
    }

    /**
     * Create a new relation for fixed point analysis. The created relation must be
     * added separately
     * 
     * @param name tgoalExprhe name of the relation
     * @param vars the variables for the relation
     * @return the created relation
     */
    public FuncDecl<? extends Sort> mkRelation(final String name, final Expr<Sort>[] vars) {

        if (vars != null && vars.length > 0) {
            final Sort[] varSorts = new Sort[vars.length];
            for (int i = 0; i < vars.length; i++) {
                varSorts[i] = vars[i].getSort();
            }
            return this.mkFuncDecl(name, varSorts, this.mkBoolSort());
        }
        // without any variables, this is a fact
        return mkFact(name);
    }

    /**
     * Create a new relation
     * 
     * @param name
     * @param varSorts
     * @return
     */
    public FuncDecl<BoolSort> mkRelation(final String name, final Sort[] varSorts) {

        if (varSorts != null && varSorts.length > 0) {
           
            return this.mkFuncDecl(name, varSorts, this.mkBoolSort());
        }
        // without any variables, this is a fact
        return mkFact(name);
    }

    public FuncDecl<BoolSort> mkFact(final String name) {
        return this.mkConstDecl(name, this.mkBoolSort());
    }

    /**
     * Create a rule of the form body => head
     * 
     * @param name
     * @param body
     * @param head
     * @return
     */
    public BoolExpr mkRule(final String name, final BoolExpr body, final BoolExpr head) {

        Set<Expr<? extends Sort>> freeVars = new HashSet<Expr<? extends Sort>>();
        freeVars.addAll(extractFreeVariablesHead(head));

        // If the body contains arguments (i.e. it is not a constant), then scan
        // and add those variables. This is more or less taken from Jayhorn
        if (!body.isConst()) {
            freeVars.addAll(extractFreeVariables(body));
        }
        var symName = mkSymbol(name);

        BoolExpr rule = null;
        if (!freeVars.isEmpty()) {
            rule = mkForall(freeVars.toArray(new Expr[freeVars.size()]), mkImplies(body, head), 1, null, null, symName,
                    symName);

        } else {
            rule = mkImplies(body, head);
        }

        return rule;
    }

    /**
     * Taken from Jayhorn
     * 
     * @param e
     * @return
     */
    public Set<Expr<? extends Sort>> extractFreeVariables(Expr<? extends Sort> e) {
        try {
            Set<Expr<? extends Sort>> result = new HashSet<>();
            if (e.isConst() && !e.equals(mkTrue()) && !e.equals(mkFalse())) {
                result.add(e);
            } else if (e.isQuantifier()) {
                Quantifier q = (Quantifier) e;

                q.getBoundVariableNames();
                extractFreeVariables(((Quantifier) e).getBody());
                throw new RuntimeException("not implemented");
            } else if (e.isApp()) {
                for (Expr<? extends Sort> child : e.getArgs()) {
                    result.addAll(extractFreeVariables(child));
                }
            } else if (e.isNumeral()) {
                // ignore
            } else {
                throw new RuntimeException("not implemented " + e.getClass().toString());
            }

            return result;
        } catch (Exception ex) {
            throw new RuntimeException(ex.getMessage());
        }
    }

    private Set<Expr<? extends Sort>> extractFreeVariablesHead(final Expr<? extends Sort> e) {
        try {
            Set<Expr<? extends Sort>> result = new HashSet<Expr<? extends Sort>>();
            if (e.isQuantifier()) {
                Quantifier q = (Quantifier) e;
                q.getBoundVariableNames();
                extractFreeVariables(((Quantifier) e).getBody());
                throw new RuntimeException("not implemented");
            } else if (e.isApp()) {

                for (Expr<? extends Sort> child : e.getArgs()) {
                    result.addAll(extractFreeVariables(child));
                }
            } else if (e.isNumeral()) {
                // ignore
            } else {
                throw new RuntimeException("not implemented " + e.getClass().toString());
            }

            return result;
        } catch (Exception ex) {
            throw new RuntimeException(ex.getMessage());
        }
    }

    /**
     * Set the memory array
     * 
     * @param mem
     */
    public ArrayExpr<BitVecSort, BitVecSort> getMemoryExpr() {
        if (this.memoryArrayExpr == null) {
            this.memoryArrayExpr = mkArrayConst(MEMORY_NAME, mkBitVecSort(GhiHornDataType.SIZE_64BIT),
                    mkBitVecSort(GhiHornDataType.SIZE_64BIT));
        }
        return this.memoryArrayExpr;
    }
}

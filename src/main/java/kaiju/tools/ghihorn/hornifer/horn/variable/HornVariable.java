package kaiju.tools.ghihorn.hornifer.horn.variable;

import com.microsoft.z3.Expr;
import com.microsoft.z3.Sort;
import com.microsoft.z3.Z3Exception;
import ghidra.program.model.data.BooleanDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.TypeDef;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.pcode.HighConstant;
import ghidra.program.model.pcode.HighGlobal;
import ghidra.program.model.pcode.HighParam;
import ghidra.program.model.pcode.HighVariable;
import kaiju.tools.ghihorn.hornifer.horn.HornFunctionInstance;
import kaiju.tools.ghihorn.hornifer.horn.expression.HornExpression;
import kaiju.tools.ghihorn.z3.GhiHornBitVectorType;
import kaiju.tools.ghihorn.z3.GhiHornBooleanType;
import kaiju.tools.ghihorn.z3.GhiHornContext;
import kaiju.tools.ghihorn.z3.GhiHornDataType;
import kaiju.tools.ghihorn.z3.GhiHornType;

/**
 * A variable in a horn clause. Variables have a name, type and scope they can be independent
 * expressions or bound to a horn expression. This is more or less the component pattern at work
 */
public class HornVariable implements HornExpression {

    protected HornVariableName name;
    protected GhiHornDataType type;
    protected Scope scope;

    protected HornFunctionInstance definingFuncInst;
    protected HighVariable highVariable;

    // Scope is based on what ghidra thinks
    public enum Scope {
        // True global variables
        Global,

        // Function-level variables, such as parameters
        Function,

        // local variables
        Local,

        // Default unknown state
        Unknown
    }

    @Override
    public HornExpression[] getComponents() {
        return new HornExpression[0];
    }

    /**
     * @param n
     * @param type
     */
    public HornVariable(HornVariableName n, GhiHornDataType t, Scope s) {
        this.name = n;
        this.type = t;
        this.scope = s;
        this.highVariable = null;
        this.definingFuncInst = null;
    }

    public HornVariable(HornVariableName n, GhiHornDataType t, Scope s, HighVariable hv) {
        this.name = n;
        this.type = t;
        this.scope = s;
        this.highVariable = hv;
        this.definingFuncInst = null;
    }

    public HornVariable() {
        this.name = HornVariableName.NO_NAME;
        this.type = null;
        this.scope = Scope.Unknown;
        this.highVariable = null;
        this.definingFuncInst = null;
    }

    /**
     * Copy constructor
     * 
     * @param other
     */
    public HornVariable(HornVariable other) {
        this.name = other.name;
        this.type = other.type;
        this.scope = other.scope;
        this.highVariable = other.highVariable;
        this.definingFuncInst = other.definingFuncInst;
    }

    /**
     * Create a horn variable from a high variable
     * 
     * @param highVariable
     */
    public HornVariable(final HighVariable highVariable) {

        this.highVariable = highVariable;
        this.scope = HornVariable.Scope.Local;
        this.name = HornVariableName.make(highVariable);

        if (highVariable instanceof HighGlobal) {
            scope = HornVariable.Scope.Global;
        } 
        // Unclear what we will do with function scope variables at this time
        // else if (highVariable instanceof HighParam) {
        //     scope = HornVariable.Scope.Function;
        // }

        this.type = null;
        DataType dt = highVariable.getDataType();

        if (dt instanceof BooleanDataType) {
            this.type = new GhiHornBooleanType();
        } 

        // Arrays are interesting cases when they are used in PCODE
        // else if (dt instanceof ArrayDataType) {
        //     // In an array , the type length is the number of elements
        //     // TODO: diagnose the type of the array elements

        //     this.type =
        //             new GhiHornArrayType(new GhiHornBitVectorType(), new GhiHornBitVectorType());
        // }

        // In some systems (e.g. Windows) BOOL is typedef'd from int. There may be other such
        // typedefs
        else if (dt instanceof TypeDef) {

            String typedefName = ((TypeDef) highVariable.getDataType()).getName();
            if (typedefName.equalsIgnoreCase("bool") || typedefName.equalsIgnoreCase("boolean")) {
                this.type = new GhiHornBooleanType();
            }
        }

        // No type decided, default to bitvector
        if (this.type == null) {
            this.type = new GhiHornBitVectorType();
        }
    }

    /**
     * Variable factory method
     * 
     * @param highVariable
     * @return
     */
    public static HornVariable mkVariable(final HighVariable highVariable) {

        if (highVariable instanceof HighConstant) {
            HighConstant hc = (HighConstant) highVariable;
            Long value = hc.getScalar().getValue();
            return new HornConstant(value);
        }

        return new HornVariable(highVariable);

    }

    /**
     * Build a new HornVariable from a parameter
     * 
     * @param param
     * @return
     */
    public static HornVariable mkVariable(final Parameter param) {

        final HornVariableName paramName = HornVariableName.make(param);
        return new HornVariable(paramName, new GhiHornBitVectorType(), Scope.Function);
    }

    /**
     * @param definingFunctionInstance the definingFunctionInstance to set
     */
    public void setDefiningFunctionInstance(HornFunctionInstance definingFunctionInstance) {
        this.definingFuncInst = definingFunctionInstance;
    }

    /**
     * @return the definingFunctionInstance
     */
    public HornFunctionInstance getDefiningFunctionInstance() {
        return definingFuncInst;
    }

    /**
     * Create a variable instance string
     * 
     * @param instanceId
     * @return
     */
    public String formatVariableInstance(final String instanceId) {
        return new StringBuilder().append(name).append("_").append(instanceId).toString();
    }

    /**
     * Instantiate as a specific type
     */
    public Expr<? extends Sort> instantiateAs(GhiHornType preferredType, GhiHornContext ctx)
            throws Z3Exception {
        try {
            return GhiHornType.create(preferredType).mkConst(ctx, name.getFullName());
        } catch (NullPointerException npe) {
            npe.printStackTrace();
        }
        return null;
    }

    /**
     * 
     */
    @Override
    public Expr<? extends Sort> instantiate(GhiHornContext ctx) throws Z3Exception {
        return type.mkConst(ctx, name.getFullName());
    }

    /**
     * @return the expr type
     */
    @Override
    public GhiHornType getType() {
        return type.getType();
    }

    public GhiHornDataType getDataType() {
        return type;
    }

    /**
     * Create a fresh variable with the same type as the input variable and a new name
     * 
     * @param hv the variable
     * @param newName the new name
     * @return the fresh, renamed variable
     */
    public static HornVariable createWithNewName(final HornVariable hv, HornVariableName newName) {
        return new HornVariable(hv) {
            {
                setName(newName);
            }
        };
    }

    /**
     * @return the scope
     */
    public Scope getScope() {
        return this.scope;
    }

    /**
     * @param scope the scope to set
     */
    public void setScope(Scope scope) {
        this.scope = scope;
    }

    /**
     * @return the highVariable
     */
    public HighVariable getHighVariable() {
        return highVariable;
    }

    /**
     * @return the true if there is a high variable
     */
    public boolean hasHighVariable() {

        if (this.highVariable != null) {

            // If this variable has a symbol, then show it because it will be in
            // the decompilation. This will eliminate temporary variables
            //
            // TODO: reivisit this and possibly make it a configurable setting

            if (this.highVariable.getSymbol() != null) {
                return true;
            }
        }
        return false;
    }

    public void setDataType(GhiHornDataType t) {
        this.type = t;
    }

    /**
     * @return the name
     */
    public HornVariableName getVariableName() {
        return name;
    }

    /**
     * Format the full name for this variable
     * 
     * @return
     */
    public String getName() {
        return name.getFullName();
    }

    /**
     * @param name the name to set
     */
    public void setName(HornVariableName name) {
        this.name = name;
    }

    @Override
    public String toString() {
        return this.name.getFullName();
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
        return prime * result + ((name == null) ? 0 : name.getFullName().hashCode());
    }

    /*
     * (non-Javadoc)
     * 
     * @see java.lang.Object#equals(java.lang.Object)
     */

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof HornVariable)) {
            return false;
        }

        HornVariable other = (HornVariable) obj;
        if (name == null) {
            if (other.name != null) {
                return false;
            }
        }
        // Variable equality is based on name
        if (!name.getFullName().equals(other.name.getFullName())) {
            return false;
        }

        return true;
    }

    public void setHighVariable(final HighParam hv) {
        this.highVariable = hv;
    }

    public boolean isConstant() {
        return (this instanceof HornConstant);
    }
}

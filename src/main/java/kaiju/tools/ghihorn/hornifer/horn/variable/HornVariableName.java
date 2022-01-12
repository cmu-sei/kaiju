package kaiju.tools.ghihorn.hornifer.horn.variable;

import com.google.common.base.Verify;
import com.google.common.base.VerifyException;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.HighConstant;
import ghidra.program.model.pcode.HighGlobal;
import ghidra.program.model.pcode.HighSymbol;
import ghidra.program.model.pcode.HighVariable;
import ghidra.program.model.pcode.VarnodeAST;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;

public class HornVariableName implements Comparable<HornVariableName> {
    private String nameId, funcId, programId;
    public static final HornVariableName NO_NAME = new HornVariableName();

    private HornVariableName() {
        nameId = "";
        funcId = "";
        programId = "";
    }

    public HornVariableName(String n) {
        nameId = n;
        funcId = "";
        programId = "";
    }

    public HornVariableName(String n, String f) {
        nameId = n;
        funcId = f;
        programId = "";
    }

    public HornVariableName(String n, String f, String p) {
        nameId = n;
        funcId = f;
        programId = p;
    }

    /**
     * Any name that isn't blank is valid
     * @return
     */
    public boolean isValid() {
        return !nameId.isBlank();
    }

    /**
     * Copy ctor
     * @param other
     */
    public HornVariableName(final HornVariable other) {
        if (other != null) {
            HornVariableName otherName = other.getVariableName();
            if (otherName != null) {
                this.nameId = otherName.nameId;
                this.funcId = otherName.funcId;
                this.programId = otherName.programId;
            }
        }
    }

    /**
     * Make a variable name from a parameter.
     * 
     * @param param
     */
    public static HornVariableName make(Parameter param) throws VerifyException {

        final HornVariableName hvn = new HornVariableName();
        String name = param.getName();

        
        Verify.verify(!name.isBlank() && !name.equals(Parameter.RETURN_NAME),
                "Could not create horn variable for parameter: " + param);

        hvn.nameId = name;
        hvn.funcId = param.getFunction().getName();
        hvn.programId = param.getFunction().getProgram().getName();

        return hvn;
    }

    /**
     * Make a horn variable name from a high variable
     * 
     * @param highVar
     * @return
     */
    public static HornVariableName make(final HighVariable highVar) {

        if (highVar == null) {
            return null;
        }

        final Program program = highVar.getHighFunction().getFunction().getProgram();
        
        if (highVar instanceof HighGlobal) {
            // For global variables

            HighSymbol globalSym = ((HighGlobal) highVar).getSymbol();
            if (globalSym != null) {

                // prefer the global symbol

                HornVariableName globalName = new HornVariableName();
                globalName.setName(globalSym.getName());

                // There is no function ID for global variables
                
                globalName.setProgramId(program.getName());

                return globalName;
            }

            // just in case the symbol is missing attempt to look it up directly
            Address addr = highVar.getRepresentative().getAddress();
            SymbolTable symTable = program.getSymbolTable();
            Symbol sym = symTable.getPrimarySymbol(addr);
            if (sym != null) {

                HornVariableName symName = new HornVariableName();
                symName.setName(sym.getName());
                symName.setFuncId(highVar.getHighFunction().getFunction().getName());
                symName.setProgramId(program.getName());
                
                return symName;

            }
        }

        HornVariableName variableName = new HornVariableName();

        variableName.funcId = highVar.getHighFunction().getFunction().getName();
        variableName.programId = program.getName();

        // Attempt to use the high variable symbol as the basis for the name
        if (!(highVar instanceof HighConstant)) {

            // Not a global variable, so include a function part
            variableName.nameId = highVar.getName();

            // Starting after Ghidra 9.1.2 anonymous variables are named "UNNAMED"
            if (variableName.nameId != null && !variableName.nameId.isEmpty()
                    && !variableName.nameId.equals("UNNAMED")) {
                return variableName;
            }

            HighSymbol sym = highVar.getSymbol();
            if (sym != null) {
                variableName.nameId = sym.getName();
                return variableName;
            }
        }

        // Name is still empty or a constant, so generate a name based on the varnode ID
        // & datatype
        StringBuilder nameBuf = new StringBuilder();

        // Some high variables are unnamed and there are no symbols.
        DataType dt = highVar.getDataType();
        if (dt instanceof PointerDataType) {
            nameBuf.append("p");
        }
        String typeName = dt.getName();

        VarnodeAST repVarNode = (VarnodeAST) highVar.getRepresentative();

        // Crummy attempt at hungarian notation
        // TODO: replace with proper naming scheme
        
        if (typeName.equals("DWORD")) {
            typeName = "dw";
        } else {
            typeName = typeName.toLowerCase().substring(0, 1);
        }
        variableName.nameId = nameBuf.append(typeName.toLowerCase().charAt(0)).append("Var")
                .append(repVarNode.getUniqueId()).toString();

        return variableName;
    }

    /**
     * @return the name without function or program IDs
     */
    public String getName() {
        return nameId;
    }

    /**
     * @return The complete formatted name, including function ID
     */
    public String getFullName() {

        final StringBuilder buf = new StringBuilder(nameId);

        if (!funcId.isEmpty()) {
            buf.append("@").append(funcId);
        }
        if (!programId.isEmpty()) {
            buf.append("!").append(programId);
        }
        return buf.toString();
    }

    /**
     * @param name the name to set
     */
    public void setName(String name) {
        this.nameId = name;
    }

    /**
     * @return the funcId
     */
    public String getFuncId() {
        return funcId;
    }

    /**
     * @return the programId
     */
    public String getProgramId() {
        return programId;
    }

    /**
     * @param programId the programId to set
     */
    public void setProgramId(String programId) {
        this.programId = programId;
    }

    /**
     * @param funcId the funcId to set
     */
    public void setFuncId(String funcId) {
        this.funcId = funcId;
    }

    @Override
    public int compareTo(HornVariableName o) {
        return getFullName().compareTo(o.getFullName());
    }

    @Override
    public String toString() {
        return this.getFullName();
    }

    /* (non-Javadoc)
     * @see java.lang.Object#hashCode()
     */
    
    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((funcId == null) ? 0 : funcId.hashCode());
        result = prime * result + ((nameId == null) ? 0 : nameId.hashCode());
        result = prime * result + ((programId == null) ? 0 : programId.hashCode());
        return result;
    }

    /* (non-Javadoc)
     * @see java.lang.Object#equals(java.lang.Object)
     */
    
    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (!(obj instanceof HornVariableName))
            return false;
        HornVariableName other = (HornVariableName) obj;
        if (funcId == null) {
            if (other.funcId != null)
                return false;
        } else if (!funcId.equals(other.funcId))
            return false;
        if (nameId == null) {
            if (other.nameId != null)
                return false;
        } else if (!nameId.equals(other.nameId))
            return false;
        if (programId == null) {
            if (other.programId != null)
                return false;
        } else if (!programId.equals(other.programId))
            return false;
        return true;
    }

    

}

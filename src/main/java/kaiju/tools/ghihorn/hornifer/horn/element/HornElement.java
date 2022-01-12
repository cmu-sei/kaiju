package kaiju.tools.ghihorn.hornifer.horn.element;

import java.util.SortedSet;

import com.microsoft.z3.BoolSort;
import com.microsoft.z3.Expr;
import com.microsoft.z3.FuncDecl;

import ghidra.program.util.ProgramLocation;
import kaiju.tools.ghihorn.hornifer.horn.variable.HornVariable;
import kaiju.tools.ghihorn.hornifer.horn.variable.HornVariableExpression;
import kaiju.tools.ghihorn.z3.GhiHornContext;

/**
 * Unifying interface for predicates and facts
 */

public interface HornElement {
    
    public static final String NO_ID = "";

    public FuncDecl<BoolSort> declare(final GhiHornContext ctx);

    public Expr<BoolSort> instantiate(final GhiHornContext ctx, HornVariableExpression... vars);

    public String getName();

    public SortedSet<HornVariable> getVariables();

    public ProgramLocation getLocator();

    public String getInstanceId();

    public boolean isExternal();

    public boolean isImported();
}

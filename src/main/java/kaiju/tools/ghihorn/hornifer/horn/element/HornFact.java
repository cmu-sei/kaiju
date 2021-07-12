package kaiju.tools.ghihorn.hornifer.horn.element;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.SortedSet;
import java.util.TreeSet;
import java.util.stream.Collectors;

import com.google.common.base.Verify;
import com.microsoft.z3.BoolExpr;
import com.microsoft.z3.BoolSort;
import com.microsoft.z3.Expr;
import com.microsoft.z3.FuncDecl;
import com.microsoft.z3.Sort;

import ghidra.program.util.ProgramLocation;
import kaiju.tools.ghihorn.hornifer.horn.variable.HornConstant;
import kaiju.tools.ghihorn.hornifer.horn.variable.HornVariable;
import kaiju.tools.ghihorn.hornifer.horn.variable.HornVariableExpression;
import kaiju.tools.ghihorn.z3.GhiHornContext;

public class HornFact implements HornElement {
    private final String name;
    private final TreeSet<HornVariableExpression> factVarInstances;
    private final ProgramLocation locator;
    
    /**
     * @param name
     * @param vars
     */
    public HornFact(final String name, ProgramLocation loc, final HornVariable[] vars, final HornConstant[] vals) {

        this.name = name;
        this.locator = loc;

        // Sort by variable name
        this.factVarInstances = new TreeSet<>(
                Comparator.comparing(HornVariableExpression::getName, Comparator.nullsFirst(String::compareTo)));

        if (vars != null && vals != null) {
            if (vars.length == vals.length) {
                for (int i = 0; i < vars.length; i++) {
                    this.factVarInstances.add(new HornVariableExpression(vars[i], vals[i]));
                }
            }
        }
    }

    /**
     * Declare the relation/function for this prediate
     * 
     * @param ctx
     * @param vars
     * @return
     */
    @Override
    public FuncDecl<BoolSort> declare(final GhiHornContext ctx) {

        List<Sort> sorts = this.factVarInstances.stream()
                // .map(v -> ctx.mkVariableSort(v.getVariable()))
                .map(v -> v.getVariable().getDataType().mkSort(ctx))
                .filter(s -> s != null)
                .collect(Collectors.toList());

        if (sorts != null && !sorts.isEmpty()) {
            return ctx.mkRelation(name, sorts.toArray(new Sort[0]));
        }
        return ctx.mkRelation(name);
    }

    /**
     * Instantiate this fact for a list of variables
     * 
     * @param ctx
     * @param vars
     * @return
     */
    @Override
    public BoolExpr instantiate(final GhiHornContext ctx, HornVariableExpression... vars) {

        Verify.verify(this.factVarInstances.size() == vars.length);

        List<Expr<? extends Sort>> varExprs = new ArrayList<>(vars.length);
        for (int i = 0; i < vars.length; i++) {
            varExprs.add(i, vars[i].instantiate(ctx));
        }
        return (BoolExpr) declare(ctx).apply(varExprs.toArray(new Expr[0]));
    }

    /**
     * @return the name
     */
    @Override
    public String getName() {
        return name;
    }

    /**
     * Variables are stored in the fact
     */
    @Override
    public SortedSet<HornVariable> getVariables() {

        final TreeSet<HornVariable> vars = new TreeSet<>(
                Comparator.comparing(HornVariable::formatName, Comparator.nullsFirst(String::compareTo)));

        this.factVarInstances.stream().sequential().map(v -> v.getVariable())
                .collect(Collectors.toCollection(() -> vars));
        return vars;
    }

    /**
     * Variables are stored in the fact
     */
    public SortedSet<HornVariableExpression> getVariableInstances() {
        return this.factVarInstances;
    }

    @Override
    public String toString() {
        final StringBuilder sb = new StringBuilder(this.name);

        sb.append("(");
        this.factVarInstances.forEach(v -> sb.append(v).append(","));
        if (sb.charAt(sb.length() - 1) == ',') {
            sb.delete(sb.length() - 1, sb.length());
        }
        sb.append(")");

        return sb.toString();
    }

    @Override
    public ProgramLocation getLocator() {
        return this.locator;
    }

    @Override
    public boolean isExternal() {
        return false;
    }

    @Override
    public boolean isImported() {
        return false;
    }

    @Override
    public String getInstanceId() {
        return NO_ID;
    }
}

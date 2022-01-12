package kaiju.tools.ghihorn.hornifer.horn.element;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.SortedMap;
import java.util.SortedSet;
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.stream.Collectors;
import com.google.common.base.Verify;
import com.microsoft.z3.BoolExpr;
import com.microsoft.z3.BoolSort;
import com.microsoft.z3.Expr;
import com.microsoft.z3.FuncDecl;
import com.microsoft.z3.Sort;
import ghidra.program.util.ProgramLocation;
import kaiju.tools.ghihorn.hornifer.horn.expression.HornExpression;
import kaiju.tools.ghihorn.hornifer.horn.variable.HornConstant;
import kaiju.tools.ghihorn.hornifer.horn.variable.HornVariable;
import kaiju.tools.ghihorn.hornifer.horn.variable.HornVariableExpression;
import kaiju.tools.ghihorn.z3.GhiHornContext;

/**
 * Facts are more or less true statements that can initialize values
 */
public class HornFact implements HornElement {

    private final String name;

    // In facts, variables are mapped to actual expressions that can be values
    private final SortedMap<HornVariable, HornExpression> variables;
    private final ProgramLocation locator;

    /**
     * Copy constructor
     * 
     * @param other
     */
    public HornFact(HornFact other) {
        name = other.getName();
        locator = other.getLocator();

        // Sort by variable name to maintain consistency
        this.variables = new TreeMap<>(
                Comparator.comparing(HornVariable::getName,
                        Comparator.nullsFirst(String::compareTo)));

        for (Map.Entry<HornVariable, HornExpression> entry : other.variables.entrySet()) {
            HornVariable variable = entry.getKey();
            HornExpression value = entry.getValue();
            this.variables.put(variable, value);

        }
    }

    /**
     * @param name
     * @param vars
     */
    public HornFact(final String name, ProgramLocation loc, final HornVariable[] vars,
            final HornConstant[] vals) {

        this.name = name;
        this.locator = loc;

        // Sort by variable name to maintain consistency
        this.variables = new TreeMap<>(
                Comparator.comparing(HornVariable::getName,
                        Comparator.nullsFirst(String::compareTo)));

        if (vars != null && vals != null) {
            if (vars.length == vals.length) {
                for (int i = 0; i < vars.length; i++) {
                    this.variables.put(vars[i], vals[i]);
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

        final List<Sort> sorts =
                this.variables.keySet().stream().map(v -> v.getDataType().mkSort(ctx))
                        .filter(s -> s != null).collect(Collectors.toList());

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

        Verify.verify(this.variables.size() == vars.length);

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
                Comparator.comparing(HornVariable::getName,
                        Comparator.nullsFirst(String::compareTo)));

        this.variables.keySet().stream().sequential().collect(Collectors.toCollection(() -> vars));

        return vars;
    }

    /**
     * Variables are stored in the fact
     */
    public SortedMap<HornVariable, HornExpression> getVariableInstances() {
        return this.variables;
    }

    @Override
    public String toString() {
        final StringBuilder sb = new StringBuilder(this.name);

        sb.append("(");
        this.variables.forEach((variable, value) -> sb.append(variable).append("=")
                .append((value != null) ? value : "NONE").append(","));
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

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null) {
            return false;
        }
        if (getClass() != obj.getClass()) {
            return false;
        }
        final HornFact other = (HornFact) obj;

        // With all the object parts being equal, check the locator

        if (locator.compareTo(other.locator) != 0) {
            return false;
        }
        return true;
    }
}

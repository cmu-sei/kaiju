package kaiju.tools.ghihorn.hornifer.horn;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.SortedSet;
import java.util.TreeSet;
import java.util.stream.Collectors;

import com.microsoft.z3.BoolExpr;
import com.microsoft.z3.BoolSort;
import com.microsoft.z3.Expr;
import com.microsoft.z3.Sort;
import kaiju.tools.ghihorn.hornifer.horn.element.HornElement;
import kaiju.tools.ghihorn.hornifer.horn.element.HornPredicate;
import kaiju.tools.ghihorn.hornifer.horn.expression.HornExpression;
import kaiju.tools.ghihorn.hornifer.horn.expression.PcodeExpression;
import kaiju.tools.ghihorn.hornifer.horn.variable.HornVariableExpression;
import kaiju.tools.ghihorn.z3.GhiHornContext;

/**
 * (body && constraints) => head
 */
public class HornClause {
    private final String name;
    private final HornElement head;
    private final HornElement body;
    // private HornRuleExpr ruleExpression;

    // Head/Body variables are the actual variables to use in the clause. They
    // are instances, which can set their own representation
    private final SortedSet<HornVariableExpression> bodyVars;
    private final SortedSet<HornVariableExpression> headVars;
    private final List<HornExpression> constraintList;

    /**
     * body && cons => head
     * 
     * @param n
     * @param body
     * @param head
     * @param cons
     */
    public HornClause(final String n, final HornElement body, final HornElement head,
            final HornExpression[] cons) {

        this(n, body, head);

        if (cons != null && cons.length > 0) {
            for (int i = 0; i < cons.length; i++) {
                if (cons[i] != null) {
                    this.constraintList.add(cons[i]);
                }
            }
        }
    }

    /**
     * Create an unconstrained horn clause with variables sorted lexographically by name
     * 
     * @param name
     * @param body
     * @param head
     */
    public HornClause(final String name, final HornElement body, final HornElement head) {

        this.name = name;
        this.head = head;
        this.body = body;
        this.constraintList = new ArrayList<>();
        // this.ruleExpression = null;

        this.bodyVars = new TreeSet<>(
                Comparator.comparing(HornVariableExpression::getName,
                        Comparator.nullsFirst(String::compareTo)));

        this.headVars = new TreeSet<>(
                Comparator.comparing(HornVariableExpression::getName,
                        Comparator.nullsFirst(String::compareTo)));

        syncVariables();
    }

    /**
     * Update the mapping from predicates to expressions
     */
    public void syncVariables() {

        final Set<HornVariableExpression> bodyVariables =
                body.getVariables().stream().map(v -> new HornVariableExpression(v))
                        .collect(Collectors.toSet());

        final Set<HornVariableExpression> headVariables =
                head.getVariables().stream().map(v -> new HornVariableExpression(v))
                        .collect(Collectors.toSet());

        setHeadVars(headVariables.toArray(new HornVariableExpression[0]));
        setBodyVars(bodyVariables.toArray(new HornVariableExpression[0]));
    }

    /**
     * @return the name
     */
    public String getName() {
        return name;
    }

    /**
     * 
     * @return the head
     */
    public HornElement getHead() {
        return this.head;
    }

    /**
     * 
     * @return The body
     */
    public HornElement getBody() {
        return this.body;
    }

    /**
     * 
     * @return the list of constraints
     */
    public List<HornExpression> getConstraints() {
        return this.constraintList;
    }

    /**
     * Add a constraint
     * 
     * @param con the new constraint
     */
    public void addConstraint(final PcodeExpression con) {
        this.constraintList.add(con);
    }

    @Override
    public String toString() {
        final StringBuilder sb = new StringBuilder();

        sb.append(this.body.toString());
        if (!this.constraintList.isEmpty()) {
            for (HornExpression c : this.constraintList) {
                sb.append(" && ");
                sb.append(c);
            }
        }
        sb.append(" -> ").append(this.head.toString());
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
        result = prime * result + ((body == null) ? 0 : body.hashCode());
        result = prime * result + ((head == null) ? 0 : head.hashCode());
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
        if (obj == null)
            return false;
        if (getClass() != obj.getClass())
            return false;
        HornClause other = (HornClause) obj;
        if (body == null) {
            if (other.body != null)
                return false;
        } else if (!body.equals(other.body))
            return false;
        if (head == null) {
            if (other.head != null)
                return false;
        } else if (!head.equals(other.head))
            return false;
        if (name == null) {
            if (other.name != null)
                return false;
        } else if (!name.equals(other.name))
            return false;
        return true;
    }

    /**
     * Set/replace the head vars
     * 
     * @param vars the variables for the head
     */
    public void setHeadVars(HornVariableExpression... vars) {
        this.headVars.clear();
        if (vars != null && vars.length > 0) {
            for (HornVariableExpression v : vars) {
                this.headVars.add(v);
            }
        }
    }

    /**
     * Set/replace the body vars
     * 
     * @param vars the variables for the body
     */
    public void setBodyVars(HornVariableExpression... vars) {
        this.bodyVars.clear();
        if (vars != null && vars.length > 0) {
            for (HornVariableExpression v : vars) {
                this.bodyVars.add(v);
            }
        }
    }

    /**
     * Create a deep copy of the head variables
     * 
     * @return the head variables
     */
    public HornVariableExpression[] getHeadVars() {
        return this.headVars.toArray(new HornVariableExpression[0]);
    }

    /**
     * Create a deep copy of the body variables
     * 
     * @return the body variables
     */
    public HornVariableExpression[] getBodyVars() {
        return this.bodyVars.toArray(new HornVariableExpression[0]);
    }

    /**
     * Instantiate the rule of the form body && constraints => head based on the computed state.
     * 
     * @param context The context on which to instantiate this rule
     */
    public HornRuleExpr instantiate(GhiHornContext context) {

        // Map the head vars to the body output state (if it exists)

        final BoolExpr bodyExpr = (BoolExpr) body.instantiate(context,
                bodyVars.toArray(new HornVariableExpression[0]));

        List<Expr<? extends Sort>> outHeadVarsExprs = new ArrayList<>(headVars.size());

        Map<Expr<? extends Sort>, Expr<? extends Sort>> bodyState = null;
        if (body instanceof HornPredicate) {

            // If body is a predicate, then there may be state that translates
            // body to head, so infer this states

            bodyState = ((HornPredicate) body).computeState(context);
            for (HornVariableExpression headVar : headVars) {
                Expr<? extends Sort> inX = headVar.instantiate(context);
                Expr<? extends Sort> outX = bodyState.getOrDefault(inX, inX);
                outHeadVarsExprs.add(outX);
            }
        } else {

            // If it is not a predicate, then there is no state

            for (HornVariableExpression headVar : headVars) {
                outHeadVarsExprs.add(headVar.instantiate(context));
            }
        }

        final BoolExpr headExpr =
                (BoolExpr) head.declare(context).apply(outHeadVarsExprs.toArray(new Expr[0]));

        // there are basically two cases where clauses are constrained:
        //
        // 1. at a decision point in a function. In this case the computed state
        // will likely be present in the head assuming the variable is live
        //
        // 2. at a function call to relate arguments from the caller perspective
        // to the parameters of the callee perspective. In this case we need
        // to lookup the caller instantiation in the bodyState and apply it
        // to the constraint


        Expr<BoolSort> constraintExpr = context.mkTrue();

        // If there are constraints, then conjoin them
        if (this.constraintList != null && !this.constraintList.isEmpty()) {

            List<Expr<? extends Sort>> constraintExprList = new ArrayList<>();

            // Propogate body state through constraint expressions
            for (HornExpression hornExpr : this.constraintList) {
                if (hornExpr != null) {
                    Expr<? extends Sort> conExpr = hornExpr.instantiate(context);

                    if (conExpr != null) {

                        // Propogate the state thru this constraint
                        for (Map.Entry<Expr<? extends Sort>, Expr<? extends Sort>> stateEntry : bodyState
                                .entrySet()) {

                            Expr<? extends Sort> inExpr = stateEntry.getKey();
                            Expr<? extends Sort> outExpr = stateEntry.getValue();
                            conExpr = conExpr.substitute(inExpr, outExpr);
                        }
                        constraintExprList.add(conExpr);
                    }
                }
            }

            // Conjoining a sigle entry seems like a problem but it's a nice way
            // to handl ethe type conversion stuff
            constraintExpr =
                    context.mkAnd(constraintExprList.toArray(new BoolExpr[0]));

            // substitute the constrain values per item 2 above.
            for (Map.Entry<Expr<? extends Sort>, Expr<? extends Sort>> entry : bodyState
                    .entrySet()) {
                Expr<? extends Sort> bv = entry.getKey();
                Expr<? extends Sort> bx = entry.getValue();
                constraintExpr = constraintExpr.substitute(bv, bx);
            }
        }

        return new HornRuleExpr(this.name, context, bodyExpr, headExpr, constraintExpr);
    }
}

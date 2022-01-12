package kaiju.tools.ghihorn.hornifer.horn;

import java.util.Collection;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import com.google.common.base.Verify;
import com.google.common.base.VerifyException;
import com.microsoft.z3.BoolSort;
import com.microsoft.z3.Fixedpoint;
import com.microsoft.z3.FuncDecl;
import com.microsoft.z3.Params;
import ghidra.util.Msg;
import ghidra.util.task.TaskMonitor;
import kaiju.tools.ghihorn.hornifer.GhiHornifier;
import kaiju.tools.ghihorn.hornifer.horn.element.HornFact;
import kaiju.tools.ghihorn.hornifer.horn.element.HornPredicate;
import kaiju.tools.ghihorn.hornifer.horn.variable.HornConstant;
import kaiju.tools.ghihorn.z3.GhiHornContext;
import kaiju.tools.ghihorn.z3.GhiHornZ3Parameters;

/**
 * A representation of the fixed point
 */
public class GhiHornFixedPoint {
    private final Set<HornClause> rules;
    private final Set<HornFact> facts;
    private HornPredicate goal;
    private GhiHornZ3Parameters z3Params;

    public GhiHornFixedPoint(GhiHornZ3Parameters params) {
        goal = null;
        rules = ConcurrentHashMap.newKeySet();
        facts = ConcurrentHashMap.newKeySet();
        this.z3Params = params;
    }

    public boolean addFact(final HornFact p) {
        return this.facts.add(p);
    }

    public boolean addFacts(final Collection<HornFact> p) {
        return this.facts.addAll(p);
    }

    /**
     * 
     * @param c
     * @return
     */
    public boolean addRules(final Collection<HornClause> c) {

        return this.rules.addAll(c);
    }


    /**
     * @return the goal
     */
    public HornPredicate getGoalPredicate() {
        if (goal == null) {
            goal = (HornPredicate) rules.stream()
                    // The goal is always to head (consequence of the implication)
                    .map(r -> r.getHead())
                    .filter(r -> r.getName().equals(GhiHornifier.GOAL_FACT_NAME))
                    .findAny()
                    .orElse(null);
        }
        return goal;
    }

    /**
     * @param r the startClause to set
     */
    public boolean addRule(HornClause r) {
        return this.rules.add(r);
    }

    /**
     * @return the rules
     */
    public Set<HornClause> getRules() {
        return rules;
    }

    /**
     * @return the facts
     */
    public Set<HornFact> getFacts() {
        return facts;
    }

    public boolean verify(TaskMonitor mon) {
        try {
            Verify.verify(goal != null, "You must specify a goal!");
            Verify.verify(!this.rules.isEmpty(), "You must specify at least one rule!");
            Verify.verify(!this.rules.isEmpty(),
                    "You must specify at least one fact (such as the start fact)!");

            return true;
        } catch (VerifyException ve) {
            mon.setMessage(ve.getMessage());
        }

        return false;
    }

    public String printRuleNames() {
        final StringBuilder sb = new StringBuilder();
        this.rules.forEach(r -> {
            String bName = r.getBody().getName();
            String hName = r.getHead().getName();
            sb.append(bName).append(" -> ").append(hName).append("\n");
        });
        return sb.toString();

    }

    @Override
    public String toString() {
        final StringBuilder sb = new StringBuilder();
        this.rules.forEach(s -> sb.append(s).append("\n"));
        return sb.toString();
    }

    private Params makeZ3Parameters(final GhiHornContext context) {

        final Params parameters = context.mkParams();

        if (z3Params == null) {
            Msg.warn(this, "Cannot configure Z3 parameters, using defaults");
            parameters.add("fp.engine", "spacer");
            parameters.add("fp.xform.inline_eager", false);
            parameters.add("fp.xform.slice", false);
            parameters.add("fp.xform.inline_linear", false);
            parameters.add("fp.xform.subsumption_checker", false);
            parameters.add("fp.datalog.generate_explanations", true);

        } else {

            for (Map.Entry<String, Object> entry : z3Params.entrySet()) {
                String key = entry.getKey();
                Object value = entry.getValue();

                if (value instanceof Integer) {
                    parameters.add(key, (Integer) value);
                } else if (value instanceof Boolean) {
                    parameters.add(key, (Boolean) value);
                } else if (value instanceof String) {
                    parameters.add(key, (String) value);
                }
            }
        }

        return parameters;
    }

    /**
     * Create a fixed point out of created relations & rules
     * 
     * @return the createed Fixedpoint
     */
    public synchronized Fixedpoint instantiate(final GhiHornContext context) {

        final Params parameters = makeZ3Parameters(context);

        // Combine all the facts, rules and relations from the program
        final Fixedpoint fx = context.mkFixedpoint();
        synchronized (fx) {

            fx.setParameters(parameters);

            for (HornFact fact : facts) {
                final FuncDecl<BoolSort> factDecl = fact.declare(context);
                fx.registerRelation(factDecl);

                int varVals[] = fact.getVariableInstances().values().stream().sequential()
                        .filter(vi -> vi != null)
                        // This may not be necessary
                        .filter(x -> x instanceof HornConstant)
                        // Get the list of integers
                        .mapToInt(n -> ((HornConstant) n).getValue().intValue()).toArray();

                fx.addFact(factDecl, varVals);
            }

            // Actually make the rule by instantiating the variables
            for (final HornClause clause : rules) {

                HornRuleExpr rule = clause.instantiate(context);

                fx.registerRelation(rule.getBodyDecl());
                fx.registerRelation(rule.getHeadDecl());

                fx.addRule(rule.getRuleExpr(), rule.getNameSymbol());
            }
        }
        return fx;
    }

    public void removeRule(final HornClause rule) {

        this.rules.remove(rule);
    }
}

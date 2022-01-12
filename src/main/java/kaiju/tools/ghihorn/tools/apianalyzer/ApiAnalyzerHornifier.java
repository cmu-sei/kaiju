package kaiju.tools.ghihorn.tools.apianalyzer;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import kaiju.tools.ghihorn.exception.GhiHornException;
import kaiju.tools.ghihorn.hornifer.GhiHornifier;
import kaiju.tools.ghihorn.hornifer.horn.GhiHornArgument;
import kaiju.tools.ghihorn.hornifer.horn.GhiHornFixedPoint;
import kaiju.tools.ghihorn.hornifer.horn.HornClause;
import kaiju.tools.ghihorn.hornifer.horn.HornFunctionInstance;
import kaiju.tools.ghihorn.hornifer.horn.HornProgram;
import kaiju.tools.ghihorn.hornifer.horn.element.HornFact;
import kaiju.tools.ghihorn.hornifer.horn.element.HornPredicate;
import kaiju.tools.ghihorn.hornifer.horn.expression.AddExpression;
import kaiju.tools.ghihorn.hornifer.horn.expression.BoolAndExpression;
import kaiju.tools.ghihorn.hornifer.horn.expression.BoolOrExpression;
import kaiju.tools.ghihorn.hornifer.horn.expression.EqExpression;
import kaiju.tools.ghihorn.hornifer.horn.expression.HornExpression;
import kaiju.tools.ghihorn.hornifer.horn.variable.HornConstant;
import kaiju.tools.ghihorn.hornifer.horn.variable.HornVariable;
import kaiju.tools.ghihorn.hornifer.horn.variable.HornVariable.Scope;
import kaiju.tools.ghihorn.hornifer.horn.variable.HornVariableExpression;
import kaiju.tools.ghihorn.hornifer.horn.variable.HornVariableName;
import kaiju.tools.ghihorn.z3.GhiHornBitVectorType;

/**
 * Generate CHC encoding
 */
public class ApiAnalyzerHornifier extends GhiHornifier {

    private final ApiAnalyzerConfig configuration;
    private HornVariable apiCounterVariable;
    private ApiSignature signature;

    private class HornApiSigInfo {

        int sequence;
        Map<Integer, HornVariable> sigParams = new HashMap<>();
        HornVariable sigRetVar;

        public HornApiSigInfo() {

            this.sigRetVar = null;
            this.sequence = -1;
        }
    }
    // Utility class to hold call/return pairs that is a bit more explicit
    static class ApiCallRetnPair {

        HornClause callClause, retnClause;

        public static ApiCallRetnPair of(HornClause c, HornClause r) {
            ApiCallRetnPair p = new ApiCallRetnPair();
            p.callClause = c;
            p.retnClause = r;

            return p;
        }

        private ApiCallRetnPair() {
            callClause = null;
            retnClause = null;
        }

        public boolean contains(final HornClause c) {
            return c.equals(callClause) || c.equals(retnClause);
        }
    }

    // parameter and return constraints are bound to specific clauses
    private final Map<HornClause, HornExpression> callConstraint = new ConcurrentHashMap<>();
    private final Map<HornClause, HornExpression> returnConstraint = new ConcurrentHashMap<>();

    // Various maps to quickly look up horn signature parts
    private final Map<Integer, HornApiSigInfo> posToHornSigApiMap = new ConcurrentHashMap<>();
    private final Map<HornApiSigInfo, List<Integer>> hornSigApiToPosMap = new ConcurrentHashMap<>();
    private final Map<String, List<HornApiSigInfo>> nameToSigHornApiMap =
            new TreeMap<>(String.CASE_INSENSITIVE_ORDER);


    /**
     * Default constructor
     */
    public ApiAnalyzerHornifier() {
        super(ApiAnalyzerController.NAME);
        configuration = ApiAnalyzerController.class.getAnnotation(ApiAnalyzerConfig.class);
    }

    /**
     * Add elements, such as global variables to the model prior to encoding
     * 
     * @throws CancelledException
     */
    @Override
    public void initializeTool(final HornProgram hornProgram, final TaskMonitor mon) {

        checkSigElements(hornProgram.getProgram());

        // Create a new variable to count the matched APIs. This variable is
        // synthetic, but usful

        this.apiCounterVariable =
                new HornVariable(new HornVariableName("SEQ"), new GhiHornBitVectorType(),
                        Scope.Global);

        hornProgram.addGlobalVariable(this.apiCounterVariable);

        // Process the signature

        for (int pos = 0; pos < this.signature.getSequence().size(); pos++) {

            // Process the signature in horn terms, adding the parameters in the signature to the
            // program as global variables

            final HornApiSigInfo hornApi = new HornApiSigInfo();
            hornApi.sequence = pos;
            final ApiFunction sigApiFunc = signature.getSequence().get(pos);
            Map<Integer, String> params = sigApiFunc.getApiParameters();
            if (params != null && !params.isEmpty()) {
                params.forEach((ord, name) -> {
                    hornApi.sigParams.put(ord, new HornVariable(new HornVariableName(name),
                            new GhiHornBitVectorType(),
                            Scope.Global));
                });

                // Add the looking for parameters to the program, these will be global and carried
                // through all clauses

                hornApi.sigParams.values().forEach(hornProgram::addGlobalVariable);
            }

            String r = sigApiFunc.getApiRetnValue();
            if (r != null) {

                hornApi.sigRetVar =
                        new HornVariable(new HornVariableName(r),
                                new GhiHornBitVectorType(),
                                Scope.Global);

                // As with parameters, add the return value
                hornProgram.addGlobalVariable(hornApi.sigRetVar);
            }

            // Fill out maps for horn-i-fied signatures for easier processing
            this.posToHornSigApiMap.put(pos, hornApi);
            this.hornSigApiToPosMap.computeIfAbsent(hornApi, k -> new ArrayList<>()).add(pos);
            this.nameToSigHornApiMap
                    .computeIfAbsent(sigApiFunc.getApiName(), k -> new ArrayList<>()).add(hornApi);
        }
    }

    /**
     * Sanity check to ensure that the complete signature is present
     * 
     * @param sig
     * @param hornProgram
     * @return
     */
    private void checkSigElements(final Program program) {

        if (this.signature == null) {
            throw new GhiHornException("No signature provided");
        }

        final Set<Function> allFuncs = new HashSet<>();
        program.getFunctionManager().getExternalFunctions().forEach(allFuncs::add);
        program.getFunctionManager().getFunctions(true).forEach(allFuncs::add);

        final Set<String> allFuncNames = allFuncs.stream().map(f -> f.getName(true).toUpperCase())
                .collect(Collectors.toSet());

        List<String> sigFuncSeq =
                this.signature.getSequence()
                        .stream()
                        .map(s -> s.getApiName().toUpperCase())
                        .collect(Collectors.toList());

        Set<String> sigFuncSet = new HashSet<>(sigFuncSeq);

        // If the signature functions minus the functions in the program is not
        // empty, then there are required functions that are not present

        Set<String> missingFuncs = GhiHornifier.setMinus(sigFuncSet,
                GhiHornifier.setIntersect(allFuncNames, sigFuncSet));

        if (!missingFuncs.isEmpty()) {
            throw new GhiHornException(
                    "Unable to find all the components of the signature: "
                            + this.signature.getName() + ", missing: " + missingFuncs);
        }
    }

    /**
     * 
     * @param hornProgram
     * @param fx
     * @param apiCoord
     */
    private void addConstraints(final HornProgram hornProgram, final GhiHornFixedPoint fx,
            final ApiAnalyzerArgument apiCoord) {

        // If there are multiple possible starting point, then there must be two clauses for all
        // non-starting entries:
        //
        // 1. a constrained clause that is of the form API & SEQ=POS = next(SEQ+1)
        // 2. a fall through clause that is unconstrained by the API counter
        //
        // Depending on the starting coordinate one of these will be disabled
        // disable the fallthru clause for this start to force the search start to initialize the
        // counter. The disabling is done for this fixedpoint by removing the fallthru rule
        // If this starting clause is not the current start for the fixed point, then add a
        // fall thru

        final Set<HornClause> fallThrus = new HashSet<>();

        final HornFunctionInstance startPoint = apiCoord.getStart();
        final HornFunctionInstance goalPoint = apiCoord.getGoal();

        for (HornClause clause : fx.getRules()) {

            if (this.callConstraint.containsKey(clause)) {

                // If the call is not the starting point (pre and post), then add a fallthru
                if (!startPoint.getPrecondition().equals(clause.getBody()) &&
                        !startPoint.getPostcondition().equals(clause.getBody()) &&
                        !goalPoint.getPrecondition().equals(clause.getBody()) &&
                        !goalPoint.getPostcondition().equals(clause.getBody())) {

                    final HornClause fallThruClause = new HornClause(clause);
                    String newName = fallThruClause.getName() + "-CALL-FALLTHRU";
                    fallThruClause.setName(newName);

                    fallThrus.add(fallThruClause);
                }

                // The format for this clause will be: body && SEQ=POS [Call Constraints] ->
                // head(SEQ+1)
                clause.addConstraint(this.callConstraint.get(clause));

                // If the new constraint passes, then increment sequence in the consequence. To
                // do this we must override the variables for this clause in the
                // head (consequence) here so that the passed SEQUENCE variable is SEQUENCE+1
                //
                // need a deep copy here so as not to corrupt the variables in the clause

                final HornVariableExpression[] updatedHeadVars = clause.getHeadVarExpressions();
                if (updatedHeadVars != null) {
                    for (int index = 0; index < updatedHeadVars.length; index++) {
                        if (updatedHeadVars[index].getVariable().equals(this.apiCounterVariable)) {

                            // Must create a new variable with the same name,
                            // but a different representation
                            updatedHeadVars[index] =
                                    new HornVariableExpression(this.apiCounterVariable,
                                            new AddExpression(this.apiCounterVariable,
                                                    new HornConstant(1)));
                            break;
                        }
                    }
                    // Add the updated variables
                    clause.setHeadVars(updatedHeadVars);
                }

                String newName = clause.getName() + "-CALL-INCREMENT";
                clause.setName(newName);
            }

            //
            // Handle returns
            //

            else if (this.returnConstraint.containsKey(clause)) {

                // If the return is not a start point then add a fallthru

                if (!startPoint.getPrecondition().equals(clause.getBody()) &&
                        !startPoint.getPostcondition().equals(clause.getBody()) &&
                        !goalPoint.getPrecondition().equals(clause.getBody()) &&
                        !goalPoint.getPostcondition().equals(clause.getBody())) {

                    final HornClause fallThruClause = new HornClause(clause);
                    String newName = fallThruClause.getName() + "-RETN-FALLTHRU";
                    fallThruClause.setName(newName);

                    fallThrus.add(fallThruClause);
                }

                clause.addConstraint(this.returnConstraint.get(clause));
                String newName = clause.getName() + "-RETN-CONSTRAINT";
                clause.setName(newName);
            }
        }
        fx.addRules(fallThrus);
    }

    /**
     * instrument post encoding by updating the counter
     * 
     * @param ctx
     * @param hornProgram
     */
    @Override
    protected void finalizeTool(final HornProgram hornProgram, final TaskMonitor mon) {

        for (HornClause clause : hornProgram.getAllApiCallingClauses()) {

            final String bodyName = clause.getBody().getName();
            final String apiName = bodyName.substring(0, bodyName.lastIndexOf("_pre"));
            final List<HornApiSigInfo> hornApiList = nameToSigHornApiMap.get(apiName);
            if (hornApiList == null || hornApiList.isEmpty()) {

                // Not an API of interest
                continue;
            }

            HornPredicate callBody = (HornPredicate) clause.getBody();
            Set<HornExpression> allCallConstraints = new HashSet<>();

            // For each instance of the called API
            for (HornApiSigInfo hornApi : hornApiList) {

                List<HornExpression> oneCallConstraint = new ArrayList<>();
                var optFuncInstance = hornProgram.getInstanceByID(callBody.getInstanceId());
                if (optFuncInstance.isPresent() && hornApi.sigParams != null
                        && !hornApi.sigParams.isEmpty()) {

                    final List<HornVariable> instanceParams =
                            optFuncInstance.get().getInputParameters();

                    for (Integer ordinal : hornApi.sigParams.keySet()) {
                        if (ordinal < instanceParams.size()) {

                            HornVariable funcInstParam = instanceParams.get(ordinal);
                            HornVariable paramVar = hornApi.sigParams.get(ordinal);

                            oneCallConstraint.add(new EqExpression(funcInstParam, paramVar));
                        }
                    }
                }

                // Add the API constaint as the initial calling constraint
                oneCallConstraint.add(new EqExpression(this.apiCounterVariable,
                        new HornConstant(hornApi.sequence)));

                if (oneCallConstraint.size() > 1) {
                    allCallConstraints.add(new BoolAndExpression(oneCallConstraint));
                } else {
                    allCallConstraints.add(oneCallConstraint.get(0));
                }
            }

            if (allCallConstraints.size() > 1) {
                this.callConstraint.put(clause,
                        new BoolOrExpression(new ArrayList<>(allCallConstraints)));
            } else {
                this.callConstraint.put(clause, allCallConstraints.iterator().next());
            }
        }

        // ========================
        // Returns

        for (HornClause clause : hornProgram.getAllApiReturningClauses()) {

            final String bodyName = clause.getBody().getName();
            final String apiName = bodyName.substring(0, bodyName.lastIndexOf("_post"));
            final List<HornApiSigInfo> hornApiList = nameToSigHornApiMap.get(apiName);
            if (hornApiList == null || hornApiList.isEmpty()) {
                continue;
            }

            HornPredicate retnBody = (HornPredicate) clause.getBody();
            var optFuncInstance = hornProgram.getInstanceByID(retnBody.getInstanceId());
            if (optFuncInstance.isPresent()) {

                HornVariable funcInstRetVar = optFuncInstance.get().getResultVariable();
                Set<HornExpression> allRetnConstraints = new HashSet<>();

                hornApiList.stream().map(hornApi -> hornApi.sigRetVar)
                        .filter(sigRetVar -> sigRetVar != null)
                        .forEach(sigRetVar -> allRetnConstraints
                                .add(new EqExpression(funcInstRetVar, sigRetVar)));

                if (!allRetnConstraints.isEmpty()) {

                    // If there are mulitple constraints (the API is called multiple times),
                    // then disjoin them

                    if (allRetnConstraints.size() > 1) {
                        this.returnConstraint.put(clause,
                                new BoolOrExpression(new ArrayList<>(allRetnConstraints)));
                    } else {
                        this.returnConstraint.put(clause,
                                allRetnConstraints.iterator().next());
                    }
                }
            }
        }
    }

    /**
     * Compile a program & arguments to sets of facts and rules for a specific fixed point
     */
    @Override
    public synchronized GhiHornFixedPoint makeHornFixedPoint(final HornProgram hornProgram,
            final GhiHornArgument<?> arg, TaskMonitor monitor) {

        ApiAnalyzerArgument apiCoords = (ApiAnalyzerArgument) arg;
        final GhiHornFixedPoint fx = new GhiHornFixedPoint(getZ3Parameters());

        fx.addRules(
                hornProgram.getClauses().stream().map(HornClause::new).collect(Collectors.toSet()));
        fx.addFacts(hornProgram.getFacts().stream().map(HornFact::new).collect(Collectors.toSet()));

        addConstraints(hornProgram, fx, apiCoords);

        final HornPredicate entryPred = apiCoords.getEntry().getPrecondition();
        final HornPredicate endPred = apiCoords.getGoal().getPostcondition();

        // Need to create distinct fixedpoint for this query

        // Add initialized variables to the staring fact, including the sequence
        Map<HornVariable, HornConstant> initGlobals = hornProgram.initializedGlobals();
        HornVariable[] vars = new HornVariable[initGlobals.size() + 1];
        HornConstant[] vals = new HornConstant[initGlobals.size() + 1];

        // Initialize global variables, including the counter
        vars[0] = apiCounterVariable;
        vals[0] = new HornConstant(0);
        int i = 1;
        for (var entry : initGlobals.entrySet()) {
            vars[i] = entry.getKey();
            vals[i] = entry.getValue();
            ++i;
        }

        // Initialize the SEQUENCE to 0
        final HornFact startFact =
                new HornFact(START_FACT_NAME, entryPred.getLocator(), vars, vals);

        fx.addFact(startFact);
        // End setting up the start

        final String startRuleName =
                new StringBuilder(START_FACT_NAME).append("-").append(entryPred.getFullName())
                        .toString();

        fx.addRule(new HornClause(startRuleName, startFact, entryPred));

        // The goal condition will be the sequence count equaling the number of
        // APIs
        HornConstant goalCount = new HornConstant(signature.getSequence().size());
        HornExpression goalCond = new EqExpression(this.apiCounterVariable, goalCount);

        final String goalRuleName =
                new StringBuilder(endPred.getFullName()).append("-").append(GOAL_FACT_NAME)
                        .toString();

        HornPredicate goalPred = new HornPredicate(GOAL_FACT_NAME, endPred.getLocator());
        fx.addRule(
                new HornClause(goalRuleName, endPred, goalPred, new HornExpression[] {goalCond}));
        return fx;
    }

    /**
     * Fetch tool-specific configurations
     */
    @Override
    public boolean configureTool(Map<String, Object> settings) {

        this.signature = (ApiSignature) settings.get(configuration.signatures());
        return this.signature != null;
    }

    /**
     * Fetch the coordinates to use for this search
     */
    @Override
    public Set<GhiHornArgument<?>> getCoordinates(HornProgram hornProgram) {

        final String startApiName = this.signature.getSequence().get(0).getApiName();
        int last = this.signature.getSequence().size() - 1;
        final String lastApiName = this.signature.getSequence().get(last).getApiName();

        Set<GhiHornArgument<?>> arguments = new HashSet<>();

        final Set<HornFunctionInstance> endApiSet =
                hornProgram.getFunctionInstancesByName(lastApiName);
        final Set<HornFunctionInstance> startApiSet =
                hornProgram.getFunctionInstancesByName(startApiName);

        HornFunctionInstance entryPoint = hornProgram.getEntryPointFunctionInstance();
        if (entryPoint == null) {
            Msg.warn(this,
                    "Cannot find entry point to program, this sometimes occurs when startup code cannot be decompiled properly");
        }

        Msg.info(this, "Using entry point " + entryPoint.getHornFunction().getEntry() + ", with "
                + startApiSet.size() + " starting points, and " + endApiSet.size()
                + " end points. For a total of "
                + (startApiSet.size() * endApiSet.size()) + " queries");

        for (HornFunctionInstance startApiPoint : startApiSet) {
            for (HornFunctionInstance endApiPoint : endApiSet) {
                if (!entryPoint.getPrecondition().equals(endApiPoint.getPostcondition()))
                    arguments.add(new ApiAnalyzerArgument(this.signature, entryPoint,
                            startApiPoint, endApiPoint));
            }
        }

        return arguments;
    }
}

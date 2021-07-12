package kaiju.tools.ghihorn.tools.apianalyzer;

import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;
import com.google.common.base.Verify;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import kaiju.tools.ghihorn.hornifer.GhiHornifier;
import kaiju.tools.ghihorn.hornifer.horn.GhiHornArgument;
import kaiju.tools.ghihorn.hornifer.horn.GhiHornFixedPoint;
import kaiju.tools.ghihorn.hornifer.horn.HornClause;
import kaiju.tools.ghihorn.hornifer.horn.HornFunctionInstance;
import kaiju.tools.ghihorn.hornifer.horn.HornProgram;
import kaiju.tools.ghihorn.hornifer.horn.element.HornElement;
import kaiju.tools.ghihorn.hornifer.horn.element.HornFact;
import kaiju.tools.ghihorn.hornifer.horn.element.HornPredicate;
import kaiju.tools.ghihorn.hornifer.horn.expression.AddExpression;
import kaiju.tools.ghihorn.hornifer.horn.expression.EqExpression;
import kaiju.tools.ghihorn.hornifer.horn.expression.HornExpression;
import kaiju.tools.ghihorn.hornifer.horn.expression.IteExpression;
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
    private HornVariable sequenceVariable;
    private ApiSignature signature;
    private final HornVariableName SEQUENCE_NAME = new HornVariableName("SEQUENCE");

    /**
     * Default constructor
     */
    public ApiAnalyzerHornifier() {
        super(ApiAnalyzerFrontEnd.NAME);
        configuration =
                ApiAnalyzerFrontEnd.class.getAnnotation(ApiAnalyzerConfig.class);
    }

    /**
     * Add elements, such as variables to the model prior to encoding
     * 
     * @throws CancelledException
     */
    @Override
    public void initializeTool(final HornProgram hornProgram, final TaskMonitor mon)
            throws CancelledException {

        if (!containsAllSigElements(hornProgram.getProgram())) {
            // throw new CancelledException("Cound not find all necessary signature elements
            // in program");
        }
        // Create a new variable to count the matched APIs. This variable is
        // synthetic, but usful

        this.sequenceVariable =
                new HornVariable(SEQUENCE_NAME, new GhiHornBitVectorType(), Scope.Global);

        hornProgram.addGlobalVariable(this.sequenceVariable);
    }

    /**
     * Find the position of this apiName in the signature sequence
     * 
     * @param apiName
     * @return the position or -1 if not found
     */
    private int findInSig(String apiName) {

        if (apiName.endsWith("_pre")) {
            final String api = apiName.substring(0, apiName.lastIndexOf("_pre"));
            final List<String> seq = signature.getSequence();
            for (int i = 0; i < seq.size(); i++) {

                if (seq.get(i).equalsIgnoreCase(api)) {
                    return i;
                }
            }
        }
        return -1;
    }

    /**
     * Sanity check to ensure that the complete signature is present
     * 
     * @param sig
     * @param program
     * @return
     */
    private boolean containsAllSigElements(final Program program) {

        SymbolTable t = program.getSymbolTable();

        for (String api : signature.getSequence()) {
            String[] apiComps = api.split("::");
            List<Symbol> symbols = t.getGlobalSymbols(apiComps[1]);
            if (symbols.isEmpty()) {
                return false;
            }
        }
        return true;
    }

    /**
     * instrument post encoding by updating the counter
     * 
     * (or )
     * 
     * @param ctx
     * @param hornProgram
     */
    @Override
    protected void finalizeTool(final HornProgram hornProgram, final TaskMonitor mon) {

        for (HornClause clause : hornProgram.getClauses()) {

            final HornElement body = clause.getBody();

            int pos = findInSig(body.getName());
            if (pos != -1) {

                HornVariable posVar = new HornConstant(pos);
                HornExpression condX = new EqExpression(this.sequenceVariable, posVar);

                final HornExpression trueX =
                        new AddExpression(this.sequenceVariable, new HornConstant(1));

                HornExpression falseX = this.sequenceVariable;
                int limit = this.signature.getSequence().size() - 1;
                if (pos >= limit) {
                    falseX = new HornConstant(0);
                }

                IteExpression ite = new IteExpression(condX, trueX, falseX);

                // If the new constraint passes, then increment sequence in the consequence. To
                // do this we must override the variables for this clause in the
                // head (consequence) here so that the passed SEQUENCE variable is SEQUENCE+1
                //
                // need a deep copy here so as not to corrupt the variables

                final HornVariableExpression[] updatedHeadVars = clause.getHeadVars();
                if (updatedHeadVars != null) {
                    for (int index = 0; index < updatedHeadVars.length; index++) {
                        if (updatedHeadVars[index].getVariable().equals(this.sequenceVariable)) {

                            // Must create a new variable with the same name,
                            // but a different representations
                            updatedHeadVars[index] =
                                    new HornVariableExpression(this.sequenceVariable, ite);

                            break;
                        }
                    }
                    // Add the updated variables
                    clause.setHeadVars(updatedHeadVars);
                }
            }
        }
    }

    /**
     * Compile a program & arguments to sets of facts and rules into a fixed point
     */
    @Override
    public synchronized GhiHornFixedPoint makeHornFixedPoint(final HornProgram hornProgram,
            final GhiHornArgument<?> arg,
            final TaskMonitor monitor) {

        ApiAnalyzerArgument apiArg = (ApiAnalyzerArgument) arg;
        final GhiHornFixedPoint fx = new GhiHornFixedPoint(getZ3Parameters());

        fx.addRules(hornProgram.getClauses());
        fx.addFacts(hornProgram.getFacts());

        final HornPredicate startPred = apiArg.getStart();
        final HornPredicate endPred = apiArg.getEnd();

        // Need to create distinct fixedpoint for this query
        final String startFactName =
                new StringBuilder("start_").append(startPred.getFullName()).toString();

        // Initialize the SEQUENCE to 0
        final HornFact startFact = new HornFact(startFactName, startPred.getLocator(),
                new HornVariable[] {sequenceVariable}, new HornConstant[] {new HornConstant(0)});

        fx.addFact(startFact);
        // End setting up the start

        final String startRuleName =
                new StringBuilder(startFactName).append("-").append(startPred.getFullName())
                        .toString();

        fx.addRule(new HornClause(startRuleName, startFact, startPred));

        HornPredicate goalPred = new HornPredicate("goal", endPred.getLocator());
        fx.setGoal(goalPred);

        // The goal condition will be the sequence count equaling the number of
        // APIs
        HornConstant goalCount = new HornConstant(signature.getSequence().size());
        HornExpression goalCond = new EqExpression(this.sequenceVariable, goalCount);

        final String goalRuleName =
                new StringBuilder(endPred.getFullName()).append("-goal").toString();

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
     * 
     */
    @Override
    public Set<GhiHornArgument<?>> getArguments(HornProgram hornProgram) {

        final Program program = hornProgram.getProgram();

        // Find the
        Set<GhiHornArgument<?>> arguments = new HashSet<>();

        final Set<Function> allFuncs = new HashSet<>();
        program.getFunctionManager().getExternalFunctions().forEach(allFuncs::add);
        program.getFunctionManager().getFunctions(true).forEach(allFuncs::add);

        final Set<String> allFuncNames =
                allFuncs.stream().map(f -> f.getName(true).toUpperCase())
                        .collect(Collectors.toSet());

        List<String> sigFuncSeq = this.signature.getSequence().stream().map(String::toUpperCase)
                .collect(Collectors.toList());
        Set<String> sigFuncSet = new HashSet<>(sigFuncSeq);

        // If the signature functions minus the fiunctions in the program is not
        // empty, then there are required functions that are not present
        Set<String> missingFuncs = GhiHornifier.setMinus(sigFuncSet,
                GhiHornifier.setIntersect(allFuncNames, sigFuncSet));

        Verify.verify(
                missingFuncs.isEmpty(),
                "Unable to find all the components of the signature: " + this.signature.getName()
                        + ", missing: " + missingFuncs);

        final String lastApiName = sigFuncSeq.get(sigFuncSeq.size() - 1);
        // final String firstApiName = sigFuncSeq.get(0);

        // final Set<HornFunctionInstance> startApiSet =
        //         hornProgram.getFunctionInstancesByName(firstApiName);
        final Set<HornFunctionInstance> endApiSet =
                hornProgram.getFunctionInstancesByName(lastApiName);

        for (HornPredicate entryPred : hornProgram.getEntryPointPredicates()) {
            for (HornFunctionInstance end : endApiSet) {
                HornPredicate endPred = end.getPostcondition();
                if (entryPred != null && endPred != null && !entryPred.equals(endPred))
                    arguments.add(new ApiAnalyzerArgument(this.signature, entryPred, endPred));
            }
        }

        return arguments;
    }
}

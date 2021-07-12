package kaiju.tools.ghihorn.hornifer;

import java.beans.PropertyChangeListener;
import java.beans.PropertyChangeSupport;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;
import com.google.common.base.Preconditions;
import com.google.common.base.Verify;
import com.google.common.base.VerifyException;
import com.microsoft.z3.BoolExpr;
import com.microsoft.z3.Fixedpoint;
import com.microsoft.z3.Status;
import generic.concurrent.ConcurrentQ;
import generic.concurrent.ConcurrentQBuilder;
import generic.concurrent.GThreadPool;
import generic.concurrent.QCallback;
import generic.concurrent.QResult;
import ghidra.graph.GraphAlgorithms;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighParam;
import ghidra.program.model.pcode.HighSymbol;
import ghidra.program.model.pcode.HighVariable;
import ghidra.program.model.pcode.LocalSymbolMap;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolType;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import kaiju.tools.ghihorn.GhiHornPlugin;
import kaiju.tools.ghihorn.answer.GhiHornAnswerGraphBuilder;
import kaiju.tools.ghihorn.api.ApiDatabaseService;
import kaiju.tools.ghihorn.api.ApiEntry;
import kaiju.tools.ghihorn.cfg.HighCfgEdge;
import kaiju.tools.ghihorn.cfg.HighCfgEdgeGuard;
import kaiju.tools.ghihorn.cfg.VertexAttributes;
import kaiju.tools.ghihorn.hornifer.block.HornBlock;
import kaiju.tools.ghihorn.hornifer.block.HornBlockProperty;
import kaiju.tools.ghihorn.hornifer.block.HornCallProperty;
import kaiju.tools.ghihorn.hornifer.block.HornEntryProperty;
import kaiju.tools.ghihorn.hornifer.block.HornRetnProperty;
import kaiju.tools.ghihorn.hornifer.edge.HornEdge;
import kaiju.tools.ghihorn.hornifer.horn.GhiHornAnswer;
import kaiju.tools.ghihorn.hornifer.horn.GhiHornArgument;
import kaiju.tools.ghihorn.hornifer.horn.GhiHornFixedPoint;
import kaiju.tools.ghihorn.hornifer.horn.HornClause;
import kaiju.tools.ghihorn.hornifer.horn.HornFunction;
import kaiju.tools.ghihorn.hornifer.horn.HornFunctionInstance;
import kaiju.tools.ghihorn.hornifer.horn.HornProgram;
import kaiju.tools.ghihorn.hornifer.horn.LiveHornVariables;
import kaiju.tools.ghihorn.hornifer.horn.element.HornPredicate;
import kaiju.tools.ghihorn.hornifer.horn.expression.BoolNotExpression;
import kaiju.tools.ghihorn.hornifer.horn.expression.EqExpression;
import kaiju.tools.ghihorn.hornifer.horn.expression.HornExpression;
import kaiju.tools.ghihorn.hornifer.horn.expression.PcodeExpression;
import kaiju.tools.ghihorn.hornifer.horn.variable.HornConstant;
import kaiju.tools.ghihorn.hornifer.horn.variable.HornVariable;
import kaiju.tools.ghihorn.hornifer.horn.variable.HornVariable.Scope;
import kaiju.tools.ghihorn.hornifer.horn.variable.HornVariableName;
import kaiju.tools.ghihorn.z3.GhiHornArrayType;
import kaiju.tools.ghihorn.z3.GhiHornBitVectorType;
import kaiju.tools.ghihorn.z3.GhiHornContext;
import kaiju.tools.ghihorn.z3.GhiHornFixedpointStatus;
import kaiju.tools.ghihorn.z3.GhiHornType;
import kaiju.tools.ghihorn.z3.GhiHornZ3Parameters;

/**
 * Generic class for a hornifier.
 */
public abstract class GhiHornifier {
    protected final String toolName;
    protected ApiDatabaseService apiDatabaseService;

    private GhiHornZ3Parameters z3Parameters;
    private PropertyChangeSupport pcs;
    private String statusUpdatePropertyID;
    private String terminatePropertyID;
    private String resultPropertyID;
    private boolean isCancelled;

    public enum TerminateReason {
        Cancelled, Completed;
    }

    protected GhiHornifier(final String n) {
        this.toolName = n;
        this.isCancelled = false;

    }

    /**
     * Connect the display with an encoder
     * 
     * @param listener
     * @param update
     * @param complete
     */
    public void registerListener(final PropertyChangeListener listener,
            Map<GhiHornEvent, String> eventConfig) {

        this.pcs = new PropertyChangeSupport(this);

        this.statusUpdatePropertyID = eventConfig.get(GhiHornEvent.StatusMessage);
        this.pcs.addPropertyChangeListener(statusUpdatePropertyID, listener);

        this.terminatePropertyID = eventConfig.get(GhiHornEvent.TerminateMessage);
        this.pcs.addPropertyChangeListener(terminatePropertyID, listener);

        this.resultPropertyID = eventConfig.get(GhiHornEvent.ResultMessage);
        this.pcs.addPropertyChangeListener(resultPropertyID, listener);
    }

    /**
     * Signal completion without error
     */
    public void complete() {
        if (pcs != null) {
            pcs.firePropertyChange(terminatePropertyID, null, TerminateReason.Completed);
        }
    }

    /**
     * Signal cancellation without error
     */
    public void cancel() {
        if (!isCancelled) {
            Msg.info(this, "Cancelled analysis");
            isCancelled = true;

            if (pcs != null) {
                pcs.firePropertyChange(terminatePropertyID, null, TerminateReason.Cancelled);
            }
        }
    }

    /**
     * @return the z3Parameters
     */
    public GhiHornZ3Parameters getZ3Parameters() {
        return z3Parameters;
    }

    /**
     * 
     * @param update
     */
    public void statusUpdate(final String update) {
        synchronized (pcs) {
            if (pcs != null) {
                pcs.firePropertyChange(statusUpdatePropertyID, null, update);
            }
        }
    }

    /**
     * Incrementally update the results
     * 
     * @param result
     */
    public synchronized void updateResults(final GhiHornAnswer result) {

        synchronized (pcs) {
            if (pcs != null && result != null) {
                pcs.firePropertyChange(resultPropertyID, null, result);
            }
        }
    }

    public String getName() {
        return toolName;
    }

    /**
     * Make the horn program
     * 
     * @param context the z3 context
     * @param program the underlying ghidra program
     * @param functions the decompiled function
     * @return
     */
    private HornProgram makeHornProgram(final Program program, final List<HighFunction> functions) {

        final HornProgram hornProgram = new HornProgram(program);

        for (HighFunction highFunc : functions) {
            try {
                if (highFunc != null) {
                    HornFunction hornFunc = new HornFunction(highFunc);
                    hornProgram.addFunction(hornFunc);
                } else {
                    statusUpdate(
                            "Encountered invalid decompiled function, analysis may be inaccurate");
                }
            } catch (NullPointerException e) {
            }
        }

        // For the sake of simplicity, just assume everything is a bit vector.
        // This could have a negative impact on performance but it makes things
        // much easier
        GhiHornArrayType arrayType =
                new GhiHornArrayType(new GhiHornBitVectorType(), new GhiHornBitVectorType());

        HornVariableName memName = new HornVariableName(GhiHornContext.MEMORY_NAME);
        HornVariable memVar = new HornVariable(memName, arrayType, HornVariable.Scope.Global);

        hornProgram.addGlobalVariable(memVar);

        addExternalFunctions(hornProgram);

        return hornProgram;
    }

    /**
     * Add API/External functions. This function uses the API service to import implementations if
     * they exist
     * 
     * @param hornProgram
     */
    private void addExternalFunctions(final HornProgram hornProgram) {

        final Program program = hornProgram.getProgram();
        Map<Function, List<Address>> extFunctions = new HashMap<>();
        if (program != null) {
            // Add API (external) functions as empty functions
            for (Symbol sym : program.getSymbolTable().getExternalSymbols()) {
                if (sym != null && sym.getSymbolType() == SymbolType.FUNCTION) {
                    Function extFunc = program.getListing().getFunctionAt(sym.getAddress());
                    if (extFunc != null) {
                        List<Address> xrefs = new ArrayList<>();
                        for (Reference ref : sym.getReferences()) {
                            if (ref.getReferenceType().isCall()) {
                                xrefs.add(ref.getFromAddress());
                            }
                        }
                        extFunctions.put(extFunc, xrefs);

                    }
                }
            }
        }

        // There is at least one empty function. Attempt to add in a body via
        // the API Database service

        if (!extFunctions.isEmpty()) {
            try {
                apiDatabaseService.loadApiLibraries();
            } catch (CancelledException e) {
                Msg.error(this, "Cancelled API service");
            }
            for (Entry<Function, List<Address>> entry : extFunctions.entrySet()) {

                Function func = entry.getKey();
                List<Address> xrefs = entry.getValue();

                final ApiEntry api = ApiEntry.create(func);

                // Attempt to find the implementation of this API
                Optional<HighFunction> optHf =
                        apiDatabaseService.getApiFunction(api.getLibName(), api.getApiName());

                optHf.ifPresentOrElse((apiFunc) -> {

                    HornFunction horn = new HornFunction(apiFunc);
                    horn.setImported(true);
                    horn.addXrefs(xrefs);
                    horn.setName(api.formatApiName());

                    hornProgram.addFunction(horn);

                }, () -> {

                    // The external function was not found in the API database

                    if (!xrefs.isEmpty()) {

                        statusUpdate("A referenced external function: " + api
                                + " was NOT found in the API database. As a result analysis may be inaccurate. Perhaps consider updating the API database");

                        // If the external function is referenced from
                        // somewhere, then include it in the program

                        HornFunction horn = new HornFunction(func);
                        horn.addXrefs(xrefs);
                        horn.setName(api.formatApiName());

                        hornProgram.addFunction(horn);

                    } else {
                        statusUpdate("An un-referenced external function: " + api
                                + " was NOT found in the API database. This function will be skipped");
                    }
                });
            }
        }
    }

    /**
     * Implement the encoding lifecycle
     * 
     * @param hornProgram
     * @param monitor
     * @throws Exception
     */
    public HornProgram hornify(final List<HighFunction> funcList,
            TaskMonitor monitor) throws Exception {

        Program program = funcList.get(0).getFunction().getProgram();

        final HornProgram hornProgram = makeHornProgram(program, funcList);


        // Initialize the specific tool
        initializeTool(hornProgram, monitor);

        final Set<HornFunction> hornFuncSet = hornProgram.getHornFunctions();

        monitor.initialize(hornFuncSet.size());

        for (var hornFunction : hornFuncSet) {

            // Hornify this function, which means generating the relevant
            // rules/relations for each function. Calls will be connected in
            // subseqent steps

            hornifyFunction(hornProgram, hornFunction, monitor);

            monitor.setMessage("Completed hornification of function " + hornFunction.getName());
            monitor.incrementProgress(1);
        }

        Msg.info(this, "Hornification completed");

        // Encoding the function instances makes the call connections

        for (HornFunctionInstance instance : hornProgram.getFunctionInstances().values()) {

            if (instance.getHornFunction().isExternal()) {
                encodeEmptyFunctionInstance(hornProgram, instance);
            } else {
                encodeFunctionInstance(hornProgram, instance);
            }

            if (monitor.isCancelled()) {
                monitor.setMessage("Cancelled during generation");
                throw new CancelledException();
            }
        }

        Msg.info(this, "Encoding completed");

        // Once all the connections have been made propgate the state based on calls
        propagateStateThruCalls(hornProgram);

        // Any post-encoding. By default set the variables used in the final clause to
        // what was gathered during predicate generation. Override this method and call super to
        // customize the post encoding
        finalizeTool(hornProgram, monitor);

        monitor.setMessage("Completed hornification of " + hornProgram.getName());

        return hornProgram;
    }

    /**
     * Propagate the state through calls for the purpose of connecting the state thereby ensuring
     * the analysis is accurate
     * 
     * @param hornProgram
     */
    private void propagateStateThruCalls(final HornProgram hornProgram) {

        for (var instance : hornProgram.getFunctionInstances().values()) {

            for (HornBlock callerBlk : instance.getHornFunction().getCallBlocks()) {

                // Compute the variables the must be propogated through
                // subsequent calls

                Set<HornVariable> descendantVars =
                        instance.getHornFunction().computeDescendants(callerBlk);

                if (!descendantVars.isEmpty()) {

                    Set<HornPredicate> callerBlkDescendants =
                            GraphAlgorithms.getDescendants(hornProgram.getCallGraph(),
                                    Arrays.asList(instance.getPrecondition()));

                    for (HornPredicate callPredicate : callerBlkDescendants) {

                        if (!callPredicate.equals(instance.getPrecondition())) {

                            Set<HornPredicate> callPreds = hornProgram
                                    .getPredicatesByInstanceId(callPredicate.getInstanceId());

                            callPreds.forEach(cp -> cp.addVariables(descendantVars));
                        }
                    }
                }
            }
        }

        // We've changed the definition of the predicates so we must
        // re-synchronize the variable expressions in the associated clauses
        hornProgram.getClauses().forEach(c -> c.syncVariables());
    }

    // These create new sets, and so are non-destructive. More or less taken
    // from Soot
    public static <T> Set<T> setIntersect(Set<T> s1, Set<T> s2) {
        Set<T> intersection = new HashSet<T>(s1);
        intersection.retainAll(s2);
        return intersection;
    }

    public static <T> Set<T> setUnion(Set<T> s1, Set<T> s2) {
        Set<T> rval = new HashSet<T>(s1);
        rval.addAll(s2);
        return rval;
    }

    public static <T> Set<T> setMinus(Set<T> s1, Set<T> s2) {
        Set<T> rval = new HashSet<T>(s1);
        rval.removeAll(s2);
        return rval;
    }
    // End from Soot

    /**
     * 
     * @param context
     * @param hornProgram
     * @param hornFunction
     * @param id this is either the entry address (if not called) or the xref caller address
     */
    private void encodeEmptyFunctionInstance(final HornProgram hornProgram,
            final HornFunctionInstance instance) {

        // entry => exit
        Preconditions.checkNotNull(instance, "Must supply a valid function instance");

        HornPredicate precondition = instance.getPrecondition();
        HornPredicate postcondition = instance.getPostcondition();
        if (precondition == null || postcondition == null) {
            return;
        }

        final String externalFunctionRuleName =
                new StringBuilder(precondition.getFullName()).append("-")
                        .append(postcondition.getFullName()).toString();

        hornProgram
                .addClause(new HornClause(externalFunctionRuleName, precondition, postcondition));
    }

    /**
     * Convenience function
     * 
     * @param liveVars
     */
    @SuppressWarnings("unused")
    private String printLiveVars(LiveHornVariables<HornBlock> liveVars) {

        StringBuilder out = new StringBuilder();
        for (Map.Entry<HornBlock, Set<HornVariable>> entry : liveVars.liveIn.entrySet()) {
            out.append("  LiveIn for ").append(entry.getKey().toString()).append(":");
            for (HornVariable e : entry.getValue()) {
                out.append(e).append(", ");
            }
            out.append("\n");
        }
        for (Map.Entry<HornBlock, Set<HornVariable>> entry : liveVars.liveOut.entrySet()) {
            StringBuilder b = new StringBuilder("  LiveOut for ").append(entry.getKey().toString())
                    .append(":");
            for (HornVariable e : entry.getValue()) {
                b.append(e).append(", ");
            }
            out.append("\n");
        }
        return out.toString();
    }

    /**
     * encode a call
     * 
     * @param context
     * @param hornFunction
     * @param callerBlk
     */
    private void encodeCall(final HornProgram hornProgram,
            final HornFunctionInstance callerInstance,
            final HornBlock callerBlk) throws VerifyException {

        final HornCallProperty callProp =
                (HornCallProperty) callerBlk.getProperty(HornBlockProperty.Property.Call);

        final Function calledFunction = callProp.getCalledFunction();

        Verify.verifyNotNull(calledFunction,
                "Cannot find called function in block + " + callerBlk.getStartAddress()
                        + ", skipping call");

        final Address calledFromAddress = callProp.getCalledFromAddress();
        final String id = HornPredicate.addressToId(calledFromAddress);
        final HornFunctionInstance calledInstance = hornProgram.getInstanceByID(id);

        Verify.verifyNotNull(calledInstance,
                "Cannot find called function instance for call at " + calledFromAddress
                        + ", skipping call");

        // add the call graph edge for this new call. This represents a
        // function-to-function call chain
        hornProgram.addCallTreeEdge(callerInstance.getPrecondition(),
                calledInstance.getPrecondition());

        final LiveHornVariables<HornBlock> liveVars =
                callerInstance.getHornFunction().computeLiveVariables();

        final HornPredicate callerPred =
                hornProgram.makeHornBlockPredicate(callerInstance, callerBlk,
                        liveVars.liveOut.get(callerBlk));

        // Make the rule callerBlk => called_pre
        String callToPreName = new StringBuilder(callerBlk.toString()).append("-")
                .append(calledInstance.getPrecondition().getFullName()).toString();

        // This maps inputs across function calls by creating a number of
        // equalities of the form argX == paramX
        List<HornExpression> argConstraints = new ArrayList<>();
        Map<Integer, HornVariable> argVars = callProp.getCallArguments();
        final List<HornVariable> calledParams = calledInstance.getInputParameters();
        for (int ord = 0; ord < calledParams.size(); ord++) {

            // This argument is a general expression. Needs to be mapped to
            // predicate instance variable that must exist. This is currently looked
            // up by name. Perhaps in the future we can cache this somewhere

            final HornVariable callerArg = argVars.get(ord);
            final HornVariable calledParam = calledParams.get(ord);
            if (callerArg instanceof HornConstant) {
                // Handle a constant argument mapping
                argConstraints.add(new EqExpression(callerArg, calledParam));
            } else {
                HornVariableName callerArgName = new HornVariableName(argVars.get(ord));

                callerPred.getVariables().stream()
                        .filter(v -> v.getVariableName().equals(callerArgName))
                        .findFirst()
                        .ifPresent(argVar -> argConstraints
                                .add(new EqExpression(argVar, calledParam)));
            }
        }

        HornClause callToPreClause =
                new HornClause(callToPreName, callerPred, calledInstance.getPrecondition(),
                        argConstraints.toArray(new EqExpression[0]));

        hornProgram.addClause(callToPreClause);

        Set<HornBlock> successors = callerInstance.getHornFunction().getSuccessors(callerBlk);
        if (successors.isEmpty()) {

            // This function terminates in a call (there are no successors) ...
            // callerBlk => called_pre
            // ...
            // called_post => post

            final String xid = HornPredicate.addressToId(calledFromAddress);
            final HornFunctionInstance callerContract = hornProgram.getInstanceByID(xid);
            if (callerContract != null) {

                Msg.info(this, "Call terminates function @ " + callerBlk.toString());

                final String postRuleName =
                        new StringBuilder(calledInstance.getPostcondition().getFullName())
                                .append("-").append(callerContract.getPostcondition().getFullName())
                                .toString();

                hornProgram
                        .addClause(
                                new HornClause(postRuleName, calledInstance.getPostcondition(),
                                        callerContract.getPostcondition()));
                return;
            }
        }

        // There are sucecssors, so connect the successors
        // called_post => successorBlk
        for (HornBlock succBlk : successors) {

            final HornPredicate succPred =
                    hornProgram.makeHornBlockPredicate(callerInstance, succBlk,
                            liveVars.liveIn.get(succBlk));

            // Make the rule post => after
            String postToAfterName =
                    new StringBuilder(calledInstance.getPostcondition().getFullName()).append("-")
                            .append(succBlk.toString()).toString();

            HornExpression returnConstraint = null;
            HornVariable calledResult = calledInstance.getResultVariable();
            HornVariable callerResulVar = callProp.getRetVal();

            if (calledResult != null && callerResulVar != null) {

                HornVariableName retXName = new HornVariableName(callerResulVar);

                // The returned variable will/should be in the variable set of
                // the caller predicate
                HornVariable retVar = callerPred.getVariables().stream()
                        .filter(v -> v.getVariableName().equals(retXName)).findFirst().orElse(null);

                if (retVar != null) {
                    returnConstraint = new EqExpression(retVar, calledResult);
                }
            }

            hornProgram.addClause(
                    new HornClause(postToAfterName, calledInstance.getPostcondition(), succPred,
                            new HornExpression[] {returnConstraint}));
        }
    }

    /**
     * Worklist algorithm to encode the internal function
     * 
     * @param context z3 context
     * @param hornProgram the overall program
     * @param instance the instance
     */
    private void encodeFunctionInstance(final HornProgram hornProgram,
            final HornFunctionInstance instance) {

        final HornFunction hornFunction = instance.getHornFunction();
        final HornPredicate precondition = instance.getPrecondition();
        final HornPredicate postcondition = instance.getPostcondition();
        // Compute the live variables for this function. These variables will be
        // the template for the instances to come.
        final LiveHornVariables<HornBlock> liveVars = hornFunction.computeLiveVariables();

        final List<HornBlock> todo = new ArrayList<HornBlock>();
        final Set<HornBlock> done = new HashSet<>();

        // All blocks must be processed
        todo.addAll(hornFunction.getBlocks());

        while (!todo.isEmpty()) {

            final HornBlock curBlk = todo.remove(0);
            done.add(curBlk);

            final HornPredicate curPred = hornProgram.makeHornBlockPredicate(instance, curBlk,
                    liveVars.liveOut.get(curBlk));

            // pre => entry
            if (curBlk.hasProperty(HornBlockProperty.Property.Entry)) {

                final String preRuleName = new StringBuilder(precondition.getFullName()).append("-")
                        .append(curBlk.toString()).toString();

                hornProgram.addClause(new HornClause(preRuleName, precondition, curPred));
            }

            Set<HornBlock> successors = hornFunction.getSuccessors(curBlk);
            if (successors.isEmpty()) {

                // No successors means this block is terminal, for one reason or
                // another. Attach the post condition:
                //
                // curExpr => post

                // If the block returns in a call, then that call must be encoded
                if (curBlk.hasProperty(HornBlockProperty.Property.Call)) {
                    try {
                        encodeCall(hornProgram, instance, curBlk);
                    } catch (VerifyException ve) {
                        Msg.warn(this, ve.getMessage());
                    }

                } else {

                    // A truly terminal block

                    final String postRuleName = new StringBuilder(curBlk.toString()).append("-")
                            .append(postcondition.getFullName()).toString();

                    // If there are no successors, then just add the expressions
                    // to this clause
                    hornProgram.addClause(new HornClause(postRuleName, curPred, postcondition));
                }
            } else {

                // cur => called_pre
                // ...
                // called_post => suc (if the method doesn't end in a call)

                // Not a terminal node, connect successors
                for (final HornEdge edge : hornFunction.getOutEdges(curBlk)) {

                    final HornBlock sucBlk = edge.getTarget();
                    if (!todo.contains(sucBlk) && !done.contains(sucBlk)) {
                        todo.add(sucBlk);
                    }

                    // If the block terminates in a call, then encode the call
                    if (curBlk.hasProperty(HornBlockProperty.Property.Call)) {
                        // cur => called_pre
                        // ...
                        // called_post => suc (if method doesn't end in call)
                        try {
                            encodeCall(hornProgram, instance, curBlk);
                        } catch (VerifyException ve) {
                            Msg.warn(this, ve.getMessage());
                        }

                    } else {

                        // Not a call so connect the successor and constraints
                        final HornPredicate sucPred =
                                hornProgram.makeHornBlockPredicate(instance, sucBlk,
                                        liveVars.liveIn.get(sucBlk));

                        final String clauseName = new StringBuilder(curBlk.toString()).append("-")
                                .append(sucBlk.toString()).toString();

                        HornExpression guard = edge.getConstraint();
                        if (guard != null) {

                            // If there is a guard, then the guard becomes a
                            // constraint on this clause
                            hornProgram.addClause(
                                    new HornClause(clauseName, curPred, sucPred,
                                            new HornExpression[] {guard}));
                        } else {
                            // This edge is unguarded
                            hornProgram.addClause(new HornClause(clauseName, curPred, sucPred));
                        }
                    }
                }
            }
        }
    }

    /**
     * 
     * @param hornFunction
     * @param context
     * @param monitor
     */
    protected void hornifyCfg(final HornProgram hornProgram, final HornFunction hornFunction,
            TaskMonitor monitor) {

        var highCfg = hornFunction.getHighCfg();
        if (highCfg == null) {
            return;
        }

        var entryVertex = highCfg.getEntryVertex();

        monitor.initialize(highCfg.getVertexCount());

        for (var vertex : highCfg.getVertices()) {

            // First convert each p-code to to a Z3 expression, gathering
            // variabless we go
            final HornBlock newBlock = new HornBlock(hornFunction, vertex);

            // Go through each pcode operation and add it as an expression for
            // this block
            for (final PcodeOp pcode : vertex.getEntity().getPcode()) {
                PcodeExpression pcX = new PcodeExpression(pcode);
                pcX.getUseVariables().forEach(newBlock::addUseVariable);
                pcX.getDefVariables().forEach(newBlock::addDefVariable);
                newBlock.addExpression(pcode, pcX);
            }

            // Handle entry vertices, which means mapping the callee parameters
            // to z3 expressions
            final HighFunction highFunction = hornFunction.getHighFunction();
            final LocalSymbolMap lsm = highFunction.getLocalSymbolMap();

            if (vertex.equals(entryVertex)) {
                HornEntryProperty entryProperty = new HornEntryProperty();
                for (int i = 0; i < lsm.getNumParams(); i++) {

                    // Sometimes these variables are not in the pcode
                    HornVariable phv = null;
                    HighVariable paramHighVar = lsm.getParam(i);
                    if (paramHighVar != null) {
                        phv = HornVariable.mkVariable(paramHighVar);
                    } else {

                        // There is no high variable backing this parameter,
                        // check for a proper symbol

                        HighSymbol paramHighSym = lsm.getParamSymbol(i);
                        phv = new HornVariable(new HornVariableName(paramHighSym.getName()),
                                new GhiHornBitVectorType(), Scope.Function);
                    }

                    entryProperty.addParameter(i, phv);

                    // The variable should also be added as a definining
                    // variable assuming that it is defined on entry
                    if (!(phv instanceof HornConstant)) {
                        newBlock.addDefVariable(phv);
                    }
                }
                newBlock.addProperty(entryProperty);
            }

            // If this is a call vertex, then add arguments and return value
            // from the caller perpsective as call properties
            VertexAttributes vtxAttrs = vertex.getEntity();

            if (vtxAttrs.endsInCall()) {

                final HornCallProperty callProperty = new HornCallProperty();

                // Set the attributes for this vertex to indicate that it
                // terminates in a call to something.
                PcodeOp endPcode = vtxAttrs.getLastPcode();
                if (endPcode == null) {
                    continue;
                }
                Varnode calledAddrVarnode = endPcode.getInput(0);
                Address calledAddr = calledAddrVarnode.getAddress();

                final Program program = hornProgram.getProgram();
                if (calledAddr != null) {
                    Listing listing = program.getListing();

                    // Attempt to fiind a function
                    Function calledFunc = listing.getFunctionAt(calledAddr);

                    // If this is not a internal function, then check for an
                    // (external) API
                    if (calledFunc == null) {
                        CodeUnit cu = listing.getCodeUnitAt(calledAddr);
                        Reference ref = cu.getPrimaryReference(0);
                        if (ref != null) {
                            Symbol s = cu.getProgram().getSymbolTable()
                                    .getPrimarySymbol(ref.getToAddress());
                            if (s != null && s.getSymbolType() == SymbolType.FUNCTION) {
                                calledFunc = program.getListing().getFunctionAt(s.getAddress());
                                callProperty.isExternal(true);

                            }
                        }
                    }

                    // This is the address of the call instruction
                    Address calledFromAddr = endPcode.getSeqnum().getTarget();

                    if (calledFunc != null && calledFromAddr != null) {

                        callProperty.setCalledFromAddr(calledFromAddr);
                        callProperty.setCalledFunction(calledFunc);

                        // Collect the parameters and return variables
                        if (endPcode.getNumInputs() > 0) {

                            // The 0th input is the call target. The inputs
                            // start at index 1
                            for (Integer pi = 1; pi < endPcode.getNumInputs(); pi++) {
                                Varnode inVarnode = endPcode.getInput(pi);
                                HighVariable argVar = inVarnode.getHigh();

                                HornVariable ahv = HornVariable.mkVariable(argVar);
                                newBlock.addUseVariable(ahv);
                                callProperty.addCallArgument(pi - 1, ahv);
                            }
                        }

                        // Look for the return value from the high variable from
                        // the caller perspective in the output of the last
                        // p-code, which is a call operation. Technically the
                        // call should not have an output, but this is not true
                        // for high p-code

                        final Varnode retVarnode = endPcode.getOutput();
                        if (retVarnode != null) {
                            final HighVariable retHighVar = retVarnode.getHigh();
                            if (retHighVar != null) {
                                HornVariable rhv = HornVariable.mkVariable(retHighVar);
                                callProperty.addRetVal(rhv);
                                newBlock.addDefVariable(rhv);

                            }
                        }
                    }
                }

                newBlock.addProperty(callProperty);
            }

            // If this vertex is a return vertex then fetch the return value
            // from the pcode
            if (vtxAttrs.endsInReturn()) {
                List<PcodeOp> pcode = vtxAttrs.getPcode();

                // Set the attributes for this vertex to indicate that it
                // terminates in a call to something.
                final HornRetnProperty retnProperty = new HornRetnProperty();
                PcodeOp endPcode = pcode.get(pcode.size() - 1);
                if (endPcode.getNumInputs() == 2) {
                    // Parameters Description for Retrun p-code
                    // input0 Varnode containing offset of next instruction.
                    // [input1] Value returned from call (never present in raw p-code)

                    Varnode retVarnode = endPcode.getInput(1);
                    if (retVarnode != null) {
                        final HighVariable retHighVar = retVarnode.getHigh();

                        if (retHighVar != null) {
                            retnProperty.setReturnValueHighVariable(retHighVar);
                            HornVariable rhv = HornVariable.mkVariable(retHighVar);
                            retnProperty.setReturnValue(rhv);
                        }
                    }
                }
                newBlock.addProperty(retnProperty);
            }

            hornFunction.addHornBlock(newBlock);

            // At this point all the variables have been computed from the pcode so
            // collect the globals and add them to the program
            newBlock.getVariables().stream().filter(hv -> hv.getScope() == Scope.Global)
                    .forEach(g -> hornProgram.addGlobalVariable(g));

            monitor.incrementProgress(1);
        }

        monitor.initialize(highCfg.getEdgeCount());

        // Reason through all the edge constraints
        for (HighCfgEdge<Address, VertexAttributes> edge : highCfg.getEdges()) {

            final HornBlock sourceBlock =
                    hornFunction.getBlockByAddress(edge.getStart().getLocator());
            final HornBlock targetBlock =
                    hornFunction.getBlockByAddress(edge.getEnd().getLocator());
            if (sourceBlock == null || targetBlock == null) {
                continue;
            }

            final HornEdge hornEdge = new HornEdge(sourceBlock, targetBlock);

            // If the edge is guarded, then add the guard
            HighCfgEdgeGuard guard = edge.getGuard();
            if (guard.isGuarded()) {

                PcodeExpression pcodeX = sourceBlock.getExpressions().get(guard.getGuardOp());
                HornExpression guardX = pcodeX;

                if (pcodeX != null) {

                    final HornExpression opX = pcodeX.getOperation();

                    if (opX != null) {
                        // There is a valid guard
                        if (pcodeX.hasOutputVariable()) {

                            // Discard the boolean output variable for this
                            // guard. That is if the expression is of the form
                            // BOOL1 = BOOL2, then discard BOOL1

                            if (opX.getType() == GhiHornType.Bool
                                    && pcodeX.getOutVariable().getType() == GhiHornType.Bool) {
                                guardX = opX;
                            }
                        }

                        if (!guard.getState()) {
                            hornEdge.addConstraint(new BoolNotExpression(guardX));
                        } else {
                            hornEdge.addConstraint(guardX);
                        }
                    } else {
                        Msg.error(this, "Could not find guard operation for edge: " + hornEdge);
                    }
                }
            }

            hornFunction.addHornEdge(hornEdge);

            monitor.incrementProgress(1);
        }
    }

    /**
     * 
     * Create the function instances, distinct blocks and contracts for each function instance
     * 
     * @param hornProgram
     * @param hornFunction
     * @param context
     * @param monitor
     */
    protected void hornifyFunction(final HornProgram hornProgram, final HornFunction hornFunction,
            TaskMonitor monitor) {

        if (!hornFunction.isExternal()) {
            hornifyCfg(hornProgram, hornFunction, monitor);
        }

        // Parameters are the same for internal or external functions
        final Function function = hornFunction.getFunction();

        HighFunction highFunc = hornFunction.getHighFunction();
        LocalSymbolMap lsm = null;
        if (highFunc != null) {
            lsm = highFunc.getLocalSymbolMap();
        }

        for (int p = 0; p < function.getParameterCount(); p++) {
            Parameter param = function.getParameter(p);
            HornVariableName paramName = HornVariableName.make(param);
            HornVariable hvp =
                    new HornVariable(paramName, new GhiHornBitVectorType(), Scope.Local);
            // If there is a high parameter, then prefer it
            if (lsm != null) {
                HighParam highParam = lsm.getParam(p);

                // For some reason creating the parameter from the high variable
                // breaks the connection
                hvp.setHighVariable(highParam);
            }
            hornFunction.addParameter(p, hvp);
        }

        if (hornFunction.isExternal()) {

            // Most of the time the return from an external function are
            // nameless. If the function is external then the best we can do
            HornVariableName retName = null;
            Parameter retParam = function.getReturn();
            if (retParam.getName() != null) {
                try {
                    retName = HornVariableName.make(retParam);
                } catch (VerifyException vx) {
                    retName = new HornVariableName("ret", function.getName());
                    Msg.warn(this,
                            "found nameless return, using default name: " + retName.getFullName());
                }

                HornVariable hvr =
                        new HornVariable(retName, new GhiHornBitVectorType(), Scope.Local);

                hornFunction.setResultVariable(hvr);
            }

        } else {

            // The meaningful return values for internal functions are found
            // in the last p-code of the return block: Specifically, the retrun p-code
            // input1 is the value returned from call (never present in raw p-code).

            List<HornBlock> retBlocks = hornFunction.getReturnBlocks();
            if (!retBlocks.isEmpty()) {
                if (retBlocks.size() > 1) {
                    Msg.warn(this, "There are >1 return values from function " + function.getName()
                            + ", taking the first value possibly impacting accuracy");
                }
                HornBlock retBlock = retBlocks.get(0);
                HornRetnProperty retProp =
                        (HornRetnProperty) retBlock.getProperty(HornBlockProperty.Property.Return);

                HornVariable retValVar = retProp.getReturnValue();
                hornFunction.setResultVariable(retValVar);
            }
        }

        // a contract must be created for each called function. The ID will be
        // the caller location for this function. If the function is not called
        // then use the entrypoint for the ID

        Set<Address> callAddrList = hornFunction.getCallXrefsTo().stream().filter(x -> x != null)
                .collect(Collectors.toSet());

        if (callAddrList.isEmpty()) {
            hornProgram.addHornFunctionInstance(
                    HornFunctionInstance.createInstance(hornProgram, hornFunction,
                            Address.NO_ADDRESS));
        } else {
            // There are >= 1 caller
            for (Address xref : callAddrList) {

                // Add the instance to the program, one per call
                hornProgram.addHornFunctionInstance(
                        HornFunctionInstance.createInstance(hornProgram, hornFunction,
                                xref));
            }
        }
    }

    /**
     * Evaluate the encoded horn program
     * 
     * @param hornProgram
     * @param monitor
     */
    public void evaluate(HornProgram hornProgram, TaskMonitor monitor) {

        Set<GhiHornArgument<?>> arguments = getArguments(hornProgram);

        // Create a thread pool to run the queries. Need to revisit this because
        // the context is a shared object
        final GThreadPool pool = GThreadPool.getSharedThreadPool("GH");

        ConcurrentQ<GhiHornArgument<?>, GhiHornAnswer> queue =
                new ConcurrentQBuilder<GhiHornArgument<?>, GhiHornAnswer>()
                        .setThreadPool(pool).setMaxInProgress(1).setMonitor(monitor)
                        .setCollectResults(true)
                        .build(new QCallback<GhiHornArgument<?>, GhiHornAnswer>() {

                            @Override
                            public GhiHornAnswer process(GhiHornArgument<?> arg, TaskMonitor mon)
                                    throws Exception {

                                final GhiHornFixedPoint hornFx =
                                        makeHornFixedPoint(hornProgram, arg, mon);

                                final GhiHornContext ctx = new GhiHornContext();
                                final GhiHornAnswer result = new GhiHornAnswer();
                                final Fixedpoint fx = hornFx.instantiate(ctx);
                                final BoolExpr goal = hornFx.getGoal().instantiate(ctx);

                                result.fxString = fx.toString();
                                result.arguments = arg;

                                try {

                                    Status status = fx.query(goal);
                                    result.status = GhiHornFixedpointStatus.translate(status);

                                    Msg.info(null, "Completed query: " + arg.toString());

                                    if (result.status != GhiHornFixedpointStatus.Unknown) {
                                        result.answerGraph =
                                                new GhiHornAnswerGraphBuilder(hornProgram,
                                                        result.status, hornFx,
                                                        fx.getAnswer()).getGraph();
                                    } else {
                                        result.errorMessage = fx.getReasonUnknown();
                                    }
                                    return result;
                                } catch (Exception e) {
                                    result.status = GhiHornFixedpointStatus.Error;
                                    result.errorMessage = e.getMessage();
                                    return result;
                                } finally {
                                    ctx.close();
                                }
                            }
                        });

        queue.add(arguments);

        int expected = arguments.size();
        int progress = 0;

        try {
            while (!queue.isEmpty() && !isCancelled) {

                Collection<QResult<GhiHornArgument<?>, GhiHornAnswer>> results =
                        queue.waitForResults(5,
                                TimeUnit.SECONDS);

                progress += results.size();

                Msg.info(GhiHornifier.class, "Completed " + progress + "/" + expected + " tasks");

                results.forEach(r -> {
                    try {
                        updateResults(r.getResult());
                    } catch (Exception e) {
                        e.printStackTrace();
                    }
                });
            }

            if (isCancelled) {
                Msg.info(this, "Cancelled with " + (expected - progress) + " tasks not completed");
                queue.cancelAllTasks(true);
            }


        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            isCancelled = false;
            queue.dispose();
        }
    }

    ///////////////////////////////////////////////////////////////////////////////////////////////
    ////
    //// The API that specifc tools must implement
    ////
    ///////////////////////////////////////////////////////////////////////////////////////////////

    /**
     * Configure the encoder
     * 
     * @param settings
     * @return true if successfully configured; false otherwise
     */

    public boolean configure(Map<String, Object> settings) {

        this.apiDatabaseService = (ApiDatabaseService) settings.get(GhiHornPlugin.API_DB);
        this.z3Parameters = (GhiHornZ3Parameters) settings.get(GhiHornPlugin.Z3_PARAMS);

        return this.apiDatabaseService != null && configureTool(settings);
    }

    ///////////////////////////////////////////////////////////////////////////////////////////////
    ////
    //// The API that specifc tools must implement
    ////
    ///////////////////////////////////////////////////////////////////////////////////////////////

    /**
     * Implementers must override an evaluation routine that operates on a specific search criteria
     * 
     * @param ctx
     * @param hornProgram
     * @param coordinate
     * @param monitor
     * @return
     */
    public abstract GhiHornFixedPoint makeHornFixedPoint(final HornProgram hornProgram,
            final GhiHornArgument<?> args,
            final TaskMonitor mon);

    /**
     * Implementors must specify how to configure tools
     * 
     * @param settings
     * @return
     */
    public abstract boolean configureTool(Map<String, Object> settings);

    /**
     * 
     * @param context
     * @param hornProgram
     */
    protected abstract void initializeTool(final HornProgram hornProgram, final TaskMonitor mon)
            throws CancelledException;

    /**
     * 
     * @param context
     * @param hornProgram
     */
    protected abstract void finalizeTool(final HornProgram hornProgram, final TaskMonitor mon);

    /**
     * Select the coordinates to evaluate.
     * 
     * @return
     */
    public abstract Set<GhiHornArgument<?>> getArguments(HornProgram hornPraogram);

}

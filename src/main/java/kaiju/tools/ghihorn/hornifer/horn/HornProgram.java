package kaiju.tools.ghihorn.hornifer.horn;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.SortedSet;
import java.util.TreeSet;
import com.google.common.base.VerifyException;
import ghidra.graph.DefaultGEdge;
import ghidra.graph.GDirectedGraph;
import ghidra.graph.GraphFactory;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;
import ghidra.util.task.TaskMonitor;
import kaiju.tools.ghihorn.hornifer.block.HornBlock;
import kaiju.tools.ghihorn.hornifer.horn.element.HornElement;
import kaiju.tools.ghihorn.hornifer.horn.element.HornFact;
import kaiju.tools.ghihorn.hornifer.horn.element.HornPredicate;
import kaiju.tools.ghihorn.hornifer.horn.variable.HornVariable;
import kaiju.tools.ghihorn.hornifer.horn.variable.HornVariableName;

/**
 * More or less a container for the horn things
 */
public class HornProgram {
    
    private final Program program;
    private final Set<HornFunction> functions;
    private final List<Address> entryPointAddrs;

    // Because of function instances, one block can be mapped to mulutple horn
    // predicates differntiated by IDs
    private final Map<HornBlock, Set<HornPredicate>> blockToPredicateMap;
    private final Map<String, HornFunctionInstance> idToInstanceMap;
    private final Map<String, Set<HornFunctionInstance>> nameToInstanceMap;
    private final Map<String, Set<HornPredicate>> idToPredicateMap;
    private final Set<HornVariable> globalVariableSet;
    private final Set<HornPredicate> predicates;
    private final Set<HornPredicate> entryPointPreds;
    private final Set<HornClause> clauses;
    private final Set<HornFact> facts;

    // More or less a call graph to find the calls from each predicate
    private final GDirectedGraph<HornPredicate, DefaultGEdge<HornPredicate>> callTreeGraph;

    /**
     * Create a horn program from a program
     * 
     * @param p
     */
    public HornProgram(final Program p) {
        this.program = p;

        this.callTreeGraph = GraphFactory.createDirectedGraph();

        // A synchronized set can always be derived from a concurrent map
        this.functions = new HashSet<>();
        this.predicates = new HashSet<>();
        this.entryPointPreds = new HashSet<>();

        this.idToPredicateMap = new HashMap<>();
        this.nameToInstanceMap = new HashMap<>();
        this.blockToPredicateMap = new HashMap<>();
        this.globalVariableSet = new HashSet<>();
        this.idToInstanceMap = new HashMap<>();
        this.clauses = new HashSet<>();
        this.facts = new HashSet<>();
        this.entryPointAddrs = new ArrayList<>();
        this.program.getSymbolTable().getExternalEntryPointIterator().forEach(entryPointAddrs::add);
        
        // We also need to account for functions that have no callers as entry points
        FunctionIterator fItr = p.getFunctionManager().getFunctions(true);
        while (fItr.hasNext()) {
            Function func = fItr.next();
            Set<Function> callers = func.getCallingFunctions(TaskMonitor.DUMMY);
            if (callers.isEmpty()) {
                entryPointAddrs.add(func.getEntryPoint());
            }
        }
    }

    /**
     * Add a fact to this program
     * 
     * @param fact
     */
    public void addFact(final HornFact fact) throws VerifyException {
      
        this.facts.add(fact);
    }

    /**
     * 
     * @return just the facts
     */
    public Set<HornFact> getFacts() {
      
        return this.facts;
    }

    /**
     * Add a predicate to this program
     * 
     * @param hornFunction
     * @param blk
     * @param vars
     * @return
     */
    public HornPredicate makeHornPredicate(final HornFunction hornFunction, final String predName,
            final String id,
            final ProgramLocation loc, final Collection<HornVariable> vars) {

        // Create a sorted set for variables that are sorted by the string for
        // the expression
        SortedSet<HornVariable> variables = new TreeSet<>(
                Comparator.comparing(HornVariable::formatName,
                        Comparator.nullsFirst(String::compareTo)));

        for (HornVariable v : vars) {
            if (v != null && v.getScope() == HornVariable.Scope.Local) {

                HornVariableName localVarName = new HornVariableName(v);
                HornVariable newVar = HornVariable.createWithNewName(v, localVarName);
                variables.add(newVar);
            }
        }

        // Add globals and function-scope variables
        variables.addAll(getGlobalVariables());

        // Add preconditions from the function if it already created. The
        // variables in the precondition predicate will be the
        // function-level variables, such as parameters and preserved state.
        final HornFunctionInstance instance = getInstanceByID(id);
        Set<HornVariable> funcVars = new HashSet<>();
        if (instance != null) {
            HornPredicate precondition = instance.getPrecondition();
            if (precondition != null) {
                funcVars.addAll(precondition.getVariables());
            }
        }

        // because funcVars and variables is a set, duplicates should be removed
        // automatically
        if (!funcVars.isEmpty()) {
            variables.addAll(funcVars);
        }

        // Add variables, sorted by name
        final HornPredicate pred =
                new HornPredicate(predName, id, loc, variables.toArray(new HornVariable[0]));

        this.predicates.add(pred);

        if (idToPredicateMap.containsKey(id)) {
            this.idToPredicateMap.get(id).add(pred);
        } else {
            this.idToPredicateMap.put(id, new HashSet<>() {
                {
                    add(pred);
                }
            });
        }

        return pred;
    }

    /**
     * Add a predicate for a block to this program, indexed by caller address
     * 
     * @param hornFunction
     * @param blk
     * @param liveVars
     * @return
     */
    public HornPredicate makeHornBlockPredicate(final HornFunctionInstance funcInstance,
            final HornBlock blk,
            final Collection<HornVariable> liveVars) {

        HornFunction hornFunction = funcInstance.getHornFunction();
        final String id = funcInstance.getInstanceId();

        // If a block with this ID already exists, then return it
        if (blockToPredicateMap.containsKey(blk)) {
            Set<HornPredicate> callerPreds = blockToPredicateMap.get(blk);
            for (HornPredicate pred : callerPreds) {
                if (pred.getInstanceId().equals(id)) {
                    return pred;
                }
            }
        }

        // The variables are the live variables + the block defined local variables
        Set<HornVariable> allVars = blk.getVariables();

        allVars.addAll(liveVars);

        final String predName = new StringBuilder(blk.toString()).toString();

        Program fnProg = funcInstance.getHornFunction().getFunction().getProgram();
        final ProgramLocation loc = new ProgramLocation(fnProg, blk.getStartAddress());
        final HornPredicate pred = makeHornPredicate(hornFunction, predName, id, loc, allVars);
        pred.setHornBlock(blk);

        // Save the entry point predicates for this horn program
        for (Address ep : entryPointAddrs) {
            if (blk.containsAddress(ep)) {
                entryPointPreds.add(pred);
                break;
            }
        }

        if (blockToPredicateMap.containsKey(blk)) {
            this.blockToPredicateMap.get(blk).add(pred);
        } else {
            this.blockToPredicateMap.put(blk, new HashSet<>() {
                {
                    add(pred);
                }
            });
        }

        return pred;
    }

    /**
     * @return the predicates associated with an ID
     */
    public Set<HornPredicate> getPredicatesByInstanceId(String id) {
        if (!idToPredicateMap.containsKey(id)) {
            return new HashSet<>();
        }
        return idToPredicateMap.get(id);
    }

    /**
     * Return the set of function instances for a given function name
     * 
     * @param funcName
     * @return
     */
    public Set<HornFunctionInstance> getFunctionInstancesByName(final String funcName) {
        return this.nameToInstanceMap.get(funcName);
    }

    /**
     * @return the entryPointAddrs
     */
    public List<Address> getEntryPointAddresses() {
        return entryPointAddrs;
    }

    /**
     * @return the entryPointPreds
     */
    public Set<HornPredicate> getEntryPointPredicates() {
        return entryPointPreds;
    }

    /**
     * 
     * @param a
     * @return
     */
    public HornFunctionInstance getInstanceByID(final String id) {
        return this.idToInstanceMap.get(id);
    }

    /**
     * add a new horn function instance
     * 
     * @param a
     * @param c
     */
    public void addHornFunctionInstance(final HornFunctionInstance instance) {
        if (instance != null) {
            this.idToInstanceMap.put(instance.getInstanceId(), instance);

            final String funcName = instance.getHornFunction().getName();
            if (this.nameToInstanceMap.containsKey(funcName)) {
                this.nameToInstanceMap.get(funcName).add(instance);
            } else {
                this.nameToInstanceMap.put(funcName, new HashSet<>() {
                    {
                        add(instance);
                    }
                });
            }
        }
    }

    /**
     * Add a global variable if it has not been previously found
     * 
     * @param gv
     */
    public void addGlobalVariable(final HornVariable gv) {

        // Not strictly needed by makes things a bit more explicit
        if (!this.globalVariableSet.contains(gv)) {
            this.globalVariableSet.add(gv);
        }
    }

    /**
     * 
     * @return
     */
    public Set<HornVariable> getGlobalVariables() {
        return this.globalVariableSet;
    }

    /**
     * 
     * @return
     */
    public Set<HornPredicate> getPredicates() {
        return this.predicates;
    }

    public Set<HornClause> getClauses() {
        return this.clauses;
    }

    public boolean containsPredicate(final HornPredicate pred) {
        return this.predicates.contains(pred);
    }

    /**
     * Add a new clause to the program, be sure to register the predicates and save the graph
     * 
     * @param clause
     */
    public void addClause(final HornClause clause) {

        final HornElement body = clause.getBody();
        final HornElement head = clause.getHead();

        if (!this.predicates.contains(clause.getBody())) {
            if (body instanceof HornPredicate) {
                this.predicates.add((HornPredicate) body);
            }
        }
        if (!this.predicates.contains(clause.getHead())) {
            if (head instanceof HornPredicate) {
                this.predicates.add((HornPredicate) head);
            }
        }
        this.clauses.add(clause);
    }

    public GDirectedGraph<HornElement, DefaultGEdge<HornElement>> buildClauseGraph() {

        // A gradphical representation of addresses from the clauses
        final GDirectedGraph<HornElement, DefaultGEdge<HornElement>> clauseGraph =
                GraphFactory.createDirectedGraph();

        for (HornClause c : clauses) {
            final HornElement from = c.getBody();
            final HornElement to = c.getHead();

            if (!clauseGraph.containsVertex(from)) {
                clauseGraph.addVertex(from);
            }
            if (!clauseGraph.containsVertex(to)) {
                clauseGraph.addVertex(to);
            }
            var edge = new DefaultGEdge<>(from, to);
            if (!clauseGraph.containsEdge(edge)) {
                clauseGraph.addEdge(edge);
            }
        }
        return clauseGraph;
    }

    /**
     * Create a new call graph edge
     * 
     * @param from
     * @param to
     */
    public void addCallTreeEdge(final HornPredicate from, final HornPredicate to) {

        if (!callTreeGraph.containsVertex(from)) {
            callTreeGraph.addVertex(from);
        }
        if (!callTreeGraph.containsVertex(to)) {
            callTreeGraph.addVertex(to);
        }
        callTreeGraph.addEdge(new DefaultGEdge<>(from, to));
    }

    /**
     * 
     * @param blkLoc
     * @return
     */
    public Set<HornPredicate> findPredicateByAddress(Address blkLoc) {

        // Find the block that contains the address
        var optBlk = findBlockContainingAddress(blkLoc);
        if (optBlk.isPresent()) {
            HornBlock blk = optBlk.get();
            Set<HornPredicate> pred = blockToPredicateMap.get(blk);
            if (pred != null) {
                return pred;
            }
        }
        return new HashSet<>();
    }

    /**
     * Fina a relation using the hornblock
     * 
     * @param blk
     * @return the set of predicates (possibly none) for this bloack
     */
    public Set<HornPredicate> findPredicatesByHornBlock(HornBlock blk) {
        return blockToPredicateMap.getOrDefault(blk, new HashSet<>());
    }

    /**
     * Fetch block containing an address (if it exists)
     * 
     * @param address
     * @return
     */
    public Optional<HornBlock> findBlockContainingAddress(final Address address) {
        for (HornFunction func : functions) {
            if (func.containsAddress(address)) {
                for (HornBlock hb : func.getBlocks()) {
                    if (hb.containsAddress(address)) {
                        return Optional.of(hb);
                    }
                }
            }
        }
        return Optional.empty();
    }

    /**
     * Find the horn function containing an address.
     * 
     * @param addr address to search for
     * @return the found horn function or empty
     */
    public Optional<HornFunction> findFunctionContainingAddress(final Address addr) {
        for (var func : this.functions) {
            if (func.containsAddress(addr)) {
                return Optional.of(func);
            }
        }
        return Optional.empty();
    }

    /**
     * 
     * @param f
     * @return
     */
    public boolean addFunction(final HornFunction f) {
        return functions.add(f);
    }

    /**
     * Get the set of horn functions
     * 
     * @return defined horn functions
     */
    public Set<HornFunction> getHornFunctions() {
        return this.functions;
    }

    /*
     * (non-Javadoc)
     * 
     * @see java.lang.Object#toString()
     */

    @Override
    public String toString() {

        StringBuilder b = new StringBuilder("HornProgram: ");

        b.append(program.getName()).append("\nrelations:\n   ");

        predicates.iterator().forEachRemaining(r -> b.append(r.toString()).append("\n   "));
        return b.toString();
    }

    /**
     * 
     * @return program name
     */
    public String getName() {
        return program.getName();
    }

    public Program getProgram() {
        return this.program;
    }

    public Map<String, HornFunctionInstance> getFunctionInstances() {
        return this.idToInstanceMap;
    }

    /**
     * @return the callGraph
     */
    public GDirectedGraph<HornPredicate, DefaultGEdge<HornPredicate>> getCallGraph() {
        return callTreeGraph;
    }
}

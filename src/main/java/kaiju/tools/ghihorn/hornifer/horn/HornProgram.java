package kaiju.tools.ghihorn.hornifer.horn;

import java.io.IOException;
import java.util.Collection;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.SortedSet;
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.stream.Collectors;
import com.google.common.base.VerifyException;
import org.apache.commons.collections4.MultiValuedMap;
import org.apache.commons.collections4.multimap.HashSetValuedHashMap;
import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.MemoryByteProvider;
import ghidra.graph.DefaultGEdge;
import ghidra.graph.GDirectedGraph;
import ghidra.graph.GraphFactory;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighGlobal;
import ghidra.program.model.pcode.HighSymbol;
import ghidra.program.model.pcode.HighVariable;
import ghidra.program.util.ProgramLocation;
import kaiju.tools.ghihorn.hornifer.block.HornBlock;
import kaiju.tools.ghihorn.hornifer.block.HornBlockProperty;
import kaiju.tools.ghihorn.hornifer.horn.element.HornElement;
import kaiju.tools.ghihorn.hornifer.horn.element.HornFact;
import kaiju.tools.ghihorn.hornifer.horn.element.HornPredicate;
import kaiju.tools.ghihorn.hornifer.horn.variable.HornConstant;
import kaiju.tools.ghihorn.hornifer.horn.variable.HornVariable;
import kaiju.tools.ghihorn.hornifer.horn.variable.HornVariableName;

/**
 * More or less a container for the horn things
 */
public class HornProgram {

    private final Program program;
    private final Set<HornFunction> hornFunctions;
    private final Set<HornFunction> externalFunctions;
    private final Set<HornFunction> thunkFunctions;
    private final Address entryPointAddr;
    private HornPredicate entryPointPredicate;

    // Because of function instances, one block can be mapped to mulutple horn
    // predicates differntiated by IDs
    private final Map<HornBlock, Set<HornPredicate>> blockToPredicateMap;
    private final Map<String, HornFunctionInstance> idToInstanceMap;
    private final Map<String, Set<HornFunctionInstance>> nameToInstanceMap;
    private final Map<String, Set<HornPredicate>> idToPredicateMap;

    // Global variables and there initialized global variables. The initialized
    // globals are akin to BSS values
    private final Set<HornVariable> globalVariableSet;
    private final Map<HornVariable, HornConstant> initializedGlobalVariables;

    private HornFunctionInstance entryPointFuncInst;
    private final Set<HornPredicate> predicates;
    private final Set<HornPredicate> callerPreds;
    private final Set<HornClause> clauses;
    private final MultiValuedMap<String, HornClause> apiCallingClauses;
    private final MultiValuedMap<String, HornClause> apiReturningClauses;
    private final Set<HornFact> facts;

    // More or less a call graph to find the calls from each predicate
    private final GDirectedGraph<HornPredicate, DefaultGEdge<HornPredicate>> callTreeGraph;

    /**
     * Create a horn program from a program
     * 
     * @param p
     */
    public HornProgram(final Program p, Address ep) {
        this.program = p;

        this.callTreeGraph = GraphFactory.createDirectedGraph();

        // A synchronized set can always be derived from a concurrent map
        this.hornFunctions = new TreeSet<>(
                Comparator.comparing(HornFunction::getName,
                        Comparator.nullsFirst(String::compareTo)));

        this.externalFunctions = new TreeSet<>(
                Comparator.comparing(HornFunction::getName,
                        Comparator.nullsFirst(String::compareTo)));

        this.thunkFunctions = new TreeSet<>(
            Comparator.comparing(HornFunction::getName,
                    Comparator.nullsFirst(String::compareTo)));

        this.predicates = new HashSet<>();
        this.callerPreds = new HashSet<>();

        this.idToPredicateMap = new HashMap<>();

        // Make this case insensitive
        this.nameToInstanceMap = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);
        this.blockToPredicateMap = new HashMap<>();
        this.initializedGlobalVariables = new HashMap<>();
        this.globalVariableSet = new HashSet<>();
        this.idToInstanceMap = new HashMap<>();
        this.clauses = new HashSet<>();
        this.apiCallingClauses = new HashSetValuedHashMap<>();
        this.apiReturningClauses = new HashSetValuedHashMap<>();
        this.facts = new HashSet<>();

        this.entryPointAddr = ep;
        this.entryPointFuncInst = null;
        this.entryPointPredicate = null;
    }

    /**
     * Fetch the values for initialized global variables
     * 
     * @return
     */
    public Map<HornVariable, HornConstant> initializedGlobals() {
        return initializedGlobalVariables;
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
     * Add a predicate to this program. The predicate includes all global variables, function
     * variables, and local variables
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
                Comparator.comparing(HornVariable::getName,
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

        final HornFunctionInstance instance = this.idToInstanceMap.get(id);
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

        idToPredicateMap.computeIfAbsent(id, i -> new HashSet<>()).add(pred);

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
            Set<HornPredicate> blkCallerPreds = blockToPredicateMap.get(blk);
            for (HornPredicate pred : blkCallerPreds) {
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

        if (blk.hasProperty(HornBlockProperty.Property.Call)) {
            this.callerPreds.add(pred);
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

    public Optional<HornPredicate> getEntryPredicate() {

        if (this.entryPointPredicate == null) {

            List<HornPredicate> entryList = predicates.stream()
                    .filter(p -> p.getLocator().getAddress().equals(entryPointAddr))
                    .collect(Collectors.toList());

            if (entryList.size() == 1) {
                this.entryPointPredicate = entryList.get(0);
                this.entryPointPredicate.makeEntry();

            } else if (entryList.size() > 1) {

                // Favor the precondition as it will be first
                for (HornPredicate p : entryList) {
                    if (p.isPrecondition()) {
                        this.entryPointPredicate = p;
                        break;
                    }
                }
                if (this.entryPointPredicate == null) {
                    this.entryPointPredicate = entryList.get(0);
                }
                this.entryPointPredicate.makeEntry();
            }
        }
        return Optional.ofNullable(this.entryPointPredicate);

    }

    /**
     * Fetch the predicates that contain a call
     * 
     * @return
     */
    public Set<HornPredicate> getCallerPreds() {
        return this.callerPreds;
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
     * @return the entryPointPreds
     */
    public HornFunctionInstance getEntryPointFunctionInstance() {
        return entryPointFuncInst;
    }

    /**
     * 
     * @param a
     * @return
     */
    public Optional<HornFunctionInstance> getInstanceByID(final String id) {
        if (this.idToInstanceMap.containsKey(id)) {
            return Optional.of(this.idToInstanceMap.get(id));
        }
        return Optional.empty();
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

            Address instanceAddr = instance.getHornFunction().getFunction().getEntryPoint();
            if (entryPointAddr.equals(instanceAddr)) {
                entryPointFuncInst = instance;
            }

            final String funcName = instance.getHornFunction().getName();
            this.nameToInstanceMap.computeIfAbsent(funcName, k -> new HashSet<>()).add(instance);
        }
    }

    /**
     * @return the entryPointAddr
     */
    public Address getEntryPointAddr() {
        return entryPointAddr;
    }

    /**
     * Add a global variable if it has not been previously found
     * 
     * @param newGlobalVar
     */
    public void addGlobalVariable(final HornVariable newGlobalVar) {

        // Not strictly needed by makes things a bit more explicit
        if (!this.globalVariableSet.contains(newGlobalVar)) {
            this.globalVariableSet.add(newGlobalVar);

            // Attempt to read the initilized value of this variable

            final HighVariable newGlobalHighVar = newGlobalVar.getHighVariable();
            if (newGlobalHighVar == null) {
                return;
            }

            final Program hvProgram = newGlobalHighVar.getHighFunction().getFunction().getProgram();
            final Memory memory = hvProgram.getMemory();
            final ByteProvider provider = new MemoryByteProvider(memory,
                    hvProgram.getAddressFactory().getDefaultAddressSpace());
            final BinaryReader reader = new BinaryReader(provider, !memory.isBigEndian());

            try {
                // the representative varnode seems to be the declare location
                final DataType hvDataType = newGlobalHighVar.getDataType();
                HornConstant globalVariableValue = null;

                if (hvDataType.getLength() == Long.BYTES) {
                    globalVariableValue = new HornConstant(
                            reader.readLong(newGlobalHighVar.getRepresentative().getOffset()));
                } else if (hvDataType.getLength() == Integer.BYTES) {
                    globalVariableValue = new HornConstant(
                            reader.readInt(newGlobalHighVar.getRepresentative().getOffset()));
                } else if (hvDataType.getLength() == Byte.BYTES) {
                    globalVariableValue = new HornConstant(
                            reader.readByte(newGlobalHighVar.getRepresentative().getOffset()));
                }

                // TODO: are any other meaningful sizes? what about static arrays?
                if (globalVariableValue != null) {
                    initializedGlobalVariables.put(newGlobalVar, globalVariableValue);
                }

            } catch (IOException e) {
                // There is no value
            }
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

        if (clauses.contains(clause)) {
            return;
        }

        final HornElement body = clause.getBody();
        final HornElement head = clause.getHead();
        final String bodyName = clause.getBody().getName();

        // Record some information about the clause, such as whether it is a call to or return from
        // an API

        int callStartPos = bodyName.lastIndexOf("_pre");
        if (callStartPos != -1) {
            final String apiName = bodyName.substring(0, callStartPos);
            for (HornFunction exf : this.externalFunctions) {
                if (exf.getName().equals(apiName)) {
                    this.apiCallingClauses.put(apiName.toUpperCase(), clause);
                    break;
                }
            }
        }
        int callEndPos = bodyName.lastIndexOf("_post");
        if (callEndPos != -1) {
            final String apiName = bodyName.substring(0, callEndPos);
            for (HornFunction exf : this.externalFunctions) {
                if (exf.getName().equals(apiName)) {
                    this.apiReturningClauses.put(apiName.toUpperCase(), clause);
                    break;
                }
            }
        }

        if (!this.predicates.contains(body)) {
            if (body instanceof HornPredicate) {
                this.predicates.add((HornPredicate) body);
            }
        }
        if (!this.predicates.contains(head)) {
            if (head instanceof HornPredicate) {
                this.predicates.add((HornPredicate) head);
            }
        }
        this.clauses.add(clause);
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

    public Optional<HornClause> findClause(String name) {
        for (HornClause c : clauses) {
            if (c.getName().equals(name)) {
                return Optional.of(c);
            }
        }
        return Optional.empty();
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
        for (HornFunction func : hornFunctions) {
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
        for (var func : this.hornFunctions) {
            if (func.containsAddress(addr)) {
                return Optional.of(func);
            }
        }
        return Optional.empty();
    }

    public boolean addExternalFunction(final HornFunction extHornFunc) {
        externalFunctions.add(extHornFunc);

        return addFunction(extHornFunc);
    }

    /**
     * Return set of external functions
     */
    public Set<HornFunction> getExternallFunctions() {
        return this.externalFunctions;
    }

    /**
     * Return the set of thunks
     * 
     * @return
     */
    public Set<HornFunction> getThunkFunctions() {
        return this.thunkFunctions;
    }

    /**
     * 
     * @param f
     * @return
     */
    public boolean addFunction(final HornFunction f) {


        if (!hornFunctions.contains(f)) {

            hornFunctions.add(f);

            final HighFunction highFunc = f.getHighFunction();

            if (highFunc != null) {

                // Attempt to add all the global variables in this function. The nature of the
                // variable does not matter, global variables are passed to all predicates

                Iterator<HighSymbol> symIter = highFunc.getGlobalSymbolMap().getSymbols();
                while (symIter.hasNext()) {
                    HighSymbol sym = symIter.next();
                    HighVariable highVar = sym.getHighVariable();
                    if (highVar instanceof HighGlobal) {
                        HornVariable globalHv = HornVariable.mkVariable(highVar);
                        addGlobalVariable(globalHv);
                    }
                }
            }

            // Save some notion of thunk-ness
            if (f.isThunk()) {
                this.thunkFunctions.add(f);
            }
        }
        return false;
    }

    /**
     * Get the set of horn functions
     * 
     * @return defined horn functions
     */
    public Set<HornFunction> getHornFunctions() {
        return this.hornFunctions;
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

    /**
     * @return the all the clauses that r
     */
    public Collection<HornClause> getAllApiReturningClauses() {
        return apiReturningClauses.values();
    }

    /**
     * @return the apiCallingClauses
     */
    public Collection<HornClause> getAllApiCallingClauses() {
        return apiCallingClauses.values();
    }

    /**
     * @return the apiReturningClauses
     */
    public Collection<HornClause> getApiReturningClauses(final String apiName) {
        return apiReturningClauses.get(apiName.toUpperCase());
    }

    /**
     * @return the apiCallingClauses
     */
    public Collection<HornClause> getApiCallingClauses(final String apiName) {
        return apiCallingClauses.get(apiName.toUpperCase());
    }
}

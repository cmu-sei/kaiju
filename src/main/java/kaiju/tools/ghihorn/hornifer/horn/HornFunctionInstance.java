package kaiju.tools.ghihorn.hornifer.horn;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;
import ghidra.util.Msg;
import kaiju.tools.ghihorn.hornifer.block.HornBlock;
import kaiju.tools.ghihorn.hornifer.horn.element.HornPredicate;
import kaiju.tools.ghihorn.hornifer.horn.variable.HornVariable;

/**
 * A specific instance of a function. Influenced heavily by Jayhorn's MethodContract. The function
 * instance is a specific invocation of a function as determined by the instance ID. The ID itself
 * is the address of the call to this function instance or, if there are no callers, the address of
 * the entrypoint to the function.
 * 
 * Note that function instances must create instantiated via the @see createInstance
 */
public class HornFunctionInstance {

    private final String instanceId;
    private final Address xrefAddress;
    private final HornFunction hornFunction;
    private final HornPredicate precondition;
    private final HornPredicate postcondition;

    private List<HornVariable> params;
    private Set<HornVariable> localVars;
    private HornVariable resultVar;

    /**
     * 
     * @param f
     * @param xrefAddress
     * @param pre
     * @param post
     * @param ins
     * @param res
     */
    private HornFunctionInstance(HornFunction f, final String i, final Address x, HornPredicate pre,
            HornPredicate post) {

        this.instanceId = i;
        this.hornFunction = f;
        this.xrefAddress = x;

        this.precondition = pre;
        precondition.setImported(f.isImported());
        precondition.setExternal(f.isExternal());

        this.postcondition = post;
        postcondition.setImported(f.isImported());
        postcondition.setExternal(f.isExternal());

        this.params = new ArrayList<>();
        this.localVars = new HashSet<>();
    }

    /**
     * Create a new function instance
     * 
     * @param plugin
     * @param hornProgram
     * @param hornFunction
     * @param xrefAddress
     * @return
     */
    public static HornFunctionInstance createInstance(
            final HornProgram hornProgram,
            final HornFunction hornFunction, final Address xrefAddress) {

        // If there are no callers then use the entry as the ID for this instance
        final String id = (xrefAddress == Address.NO_ADDRESS)
                ? HornPredicate.addressToId(hornFunction.getEntry())
                : HornPredicate.addressToId(xrefAddress);

        final List<HornVariable> inParams = hornFunction.getParameters();
        final List<HornVariable> outParams = new ArrayList<>();
        HornVariable retValVar = hornFunction.getResult();
        if (retValVar != null) {
            outParams.add(retValVar);
        }

        final Function function = hornFunction.getFunction();
        ProgramLocation startLoc = null, endLoc = null;
        final Program mainProgram = hornProgram.getProgram();

        if (hornFunction.isExternal() || hornFunction.isImported()) {

            // With external functions start and end are the same and they are
            // the xref addresses for this call (because there is no program
            // body to locate)

            startLoc = new ProgramLocation(mainProgram, xrefAddress);
            endLoc = new ProgramLocation(mainProgram, xrefAddress);

        } else {

            // Not an external function, that means there is a body. Fetch the incoming
            // parameters

            HornBlock entryBlock = hornFunction.getEntryBlock();
            startLoc = new ProgramLocation(function.getProgram(), entryBlock.getStartAddress());

            // TODO: Really handle multiple output parameters

            List<HornBlock> retBlocks = hornFunction.getReturnBlocks();
            if (!retBlocks.isEmpty()) {
                if (retBlocks.size() > 1) {
                    Msg.warn(null,
                            "There are >1 return locations from function " + function.getName()
                                    + ", taking the first value possibly impacting accuracy");
                }
                endLoc = new ProgramLocation(function.getProgram(),
                        retBlocks.get(0).getStartAddress());
            }
        }

        // Need to make fresh predicates for this specific function call
        final String preName = new StringBuilder(hornFunction.getName()).append("_pre").toString();
        final String postName =
                new StringBuilder(hornFunction.getName()).append("_post").toString();

        final HornPredicate prePred =
                hornProgram.makeHornPredicate(hornFunction, preName, id, startLoc, inParams);
        final HornPredicate postPred =
                hornProgram.makeHornPredicate(hornFunction, postName, id, endLoc, outParams);

        HornFunctionInstance contract =
                new HornFunctionInstance(hornFunction, id, xrefAddress, prePred, postPred);

        contract.addParameters(inParams);

        contract.addLocaVariables(hornFunction.getLocalVariables());

        if (outParams != null && !outParams.isEmpty()) {
            // Assuming the 0th output parameter is the official result
            contract.setResult(outParams.get(0));
        }

        return contract;
    }


    /**
     * @return the id
     */
    public String getInstanceId() {
        return instanceId;
    }

    /**
     * Properly format the input paramteters for this functioin instance
     * 
     * @param ins the list of parameters for this function
     */
    public void addParameters(final List<HornVariable> ins) {

        for (int ordinal = 0; ordinal < ins.size(); ordinal++) {
            final HornVariable p = ins.get(ordinal);
            p.setDefiningFunctionInstance(this);
            this.params.add(ordinal, p);
        }
    }

    /**
     * @param localVariables the locaVariables to set
     */
    public void addLocaVariables(Set<HornVariable> locaVars) {

        this.localVars.addAll(locaVars);
        this.localVars.forEach(v -> v.setDefiningFunctionInstance(this));
    }

    /**
     * Add a result parameter
     * 
     * @param ctx
     * @param res
     */
    public void setResult(final HornVariable res) {

        // final HornVariableName resName = new HornVariableName(res);
        // this.resultVar = HornVariable.createWithNewName(res, resName);
        this.resultVar = res;
        this.resultVar.setDefiningFunctionInstance(this);
    }

    /**
     * 
     */
    public String toString() {
        return new StringBuilder(this.hornFunction.toString()).append("[").append(xrefAddress)
                .append("]: ")
                .append(precondition).append(", ").append(postcondition).append("]").toString();
    }

    /**
     * @return the xrefAddress
     */
    public Address getXrefAddress() {
        return xrefAddress;
    }

    /**
     * @return the hornFunction
     */
    public HornFunction getHornFunction() {
        return hornFunction;
    }

    /**
     * @return the precondition
     */
    public HornPredicate getPrecondition() {
        return precondition;
    }

    /**
     * @return the postcondition
     */
    public HornPredicate getPostcondition() {
        return postcondition;
    }

    /**
     * @return the params
     */
    public List<HornVariable> getInputParameters() {
        return params;
    }

    /**
     * @return the result
     */
    public HornVariable getResultVariable() {
        return resultVar;
    }

}

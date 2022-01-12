package kaiju.tools.ghihorn.tools.pathanalyzer;

import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.Optional;
import com.google.common.base.Verify;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.util.ProgramLocation;
import ghidra.util.task.TaskMonitor;
import kaiju.tools.ghihorn.exception.GhiHornException;
import kaiju.tools.ghihorn.hornifer.GhiHornifier;
import kaiju.tools.ghihorn.hornifer.horn.GhiHornArgument;
import kaiju.tools.ghihorn.hornifer.horn.GhiHornFixedPoint;
import kaiju.tools.ghihorn.hornifer.horn.HornClause;
import kaiju.tools.ghihorn.hornifer.horn.HornProgram;
import kaiju.tools.ghihorn.hornifer.horn.element.HornFact;
import kaiju.tools.ghihorn.hornifer.horn.element.HornPredicate;
import kaiju.tools.ghihorn.hornifer.horn.variable.HornConstant;
import kaiju.tools.ghihorn.hornifer.horn.variable.HornVariable;

public class PathAnalyzerHornifier extends GhiHornifier {

    private Address startAddr;
    private Address endAddr;

    public PathAnalyzerHornifier() {
        super(PathAnalyzerController.NAME);
    }

    /**
     * Compile a program & arguments to sets of facts and rules
     */
    @Override
    public synchronized GhiHornFixedPoint makeHornFixedPoint(final HornProgram hornProgram,
            final GhiHornArgument<?> arguments, final TaskMonitor monitor) {

        final GhiHornFixedPoint fx = new GhiHornFixedPoint(getZ3Parameters());
        fx.addRules(hornProgram.getClauses());
        fx.addFacts(hornProgram.getFacts());

        PathAnalyzerArgument arg = (PathAnalyzerArgument) arguments;

        HornPredicate startPred = null;
        if (arg.getEntry().equals(hornProgram.getEntryPointAddr())) {
            // start at the entry point
            Optional<HornPredicate> entryPred = hornProgram.getEntryPredicate();
            if (entryPred.isPresent()) {
                startPred = entryPred.get();
            }

        } else {
            // Some addressess may be inside a basic block, hence the "containing"
            Set<HornPredicate> startSet = hornProgram.findPredicateByAddress(arg.getEntry());
            if (!startSet.isEmpty()) {
                startPred = startSet.iterator().next();
            }
        }
        Set<HornPredicate> endSet = hornProgram.findPredicateByAddress(arg.getGoal());

        Verify.verify(startPred != null && !endSet.isEmpty(),
                "Cannot find start/end location for evaluation");

        monitor.setMessage("Found start address in block: " + startPred.getFullName());

        // Add initialized variables to the staring fact
        Map<HornVariable, HornConstant> initGlobals = hornProgram.initializedGlobals();
        HornVariable[] vars = new HornVariable[initGlobals.size()];
        HornConstant[] vals = new HornConstant[initGlobals.size()];

        int i = 0;
        for (var entry : initGlobals.entrySet()) {
            vars[i] = entry.getKey();
            vals[i] = entry.getValue();
            ++i;
        }

        final HornFact startFact =
                new HornFact(START_FACT_NAME, startPred.getLocator(), vars, vals);
        fx.addFact(startFact);

        final String startRuleName =
                new StringBuilder(START_FACT_NAME)
                        .append("-")
                        .append(startPred.getFullName())
                        .toString();

        fx.addRule(new HornClause(startRuleName, startFact, startPred));

        // End setting up the start

        ProgramLocation endLoc = null;
        if (endSet.size() > 0) {
            endLoc = endSet.iterator().next().getLocator();
        }

        final HornPredicate goalPred = new HornPredicate(GOAL_FACT_NAME, endLoc);

        // There are multiple possible endpoints, then add them as rules
        for (HornPredicate endPred : endSet) {

            monitor.setMessage("Found end address in block: " + goalPred.getFullName());

            final String goalXRuleName = new StringBuilder(endPred.getFullName()).append("-")
                    .append(GOAL_FACT_NAME).toString();

            fx.addRule(new HornClause(goalXRuleName, endPred, goalPred));
        }

        return fx;
    }

    /**
     * Configure the encoder
     */
    @Override
    public boolean configureTool(final Map<String, Object> settings) {

        final PathAnalyzerConfig configuration =
                PathAnalyzerController.class.getAnnotation(PathAnalyzerConfig.class);

        this.startAddr = (Address) settings.get(configuration.startAddress());
        this.endAddr = (Address) settings.get(configuration.endAddress());

        return (this.startAddr != null && this.endAddr != null);
    }

    /**
     * 
     */
    @Override
    public Set<GhiHornArgument<?>> getCoordinates(HornProgram hornProgram) {
        return new HashSet<GhiHornArgument<?>>() {
            {
                add(new PathAnalyzerArgument(startAddr, endAddr));
            }
        };
    }

    @Override
    protected void initializeTool(HornProgram hornProgram, final TaskMonitor mon) {

        Set<GhiHornArgument<?>> args = getCoordinates(hornProgram);
        if (args.size() != 1) {
            throw new GhiHornException("Incorrect number of arguments provided");
        }

        // Make sure that both the start and end are in the program

        GhiHornArgument<?> arg = args.iterator().next();
        Address s = (Address) arg.getEntry();
        Address e = (Address) arg.getGoal();
        int count = 0;
        for (Function f : hornProgram.getProgram().getFunctionManager().getFunctions(true)) {
            if (f.getBody().contains(s)) {
                count++;
            }
            if (f.getBody().contains(e)) {
                count++;
            }
            if (count == 2) {
                return;
            }
        }
        throw new GhiHornException("Cannot find start/end address in program!");
    }

    @Override
    protected void finalizeTool(HornProgram hornProgram, final TaskMonitor mon) {
        // There is nothing to finalize besides the standard encoding
        return;

    }
}

package kaiju.tools.ghihorn.tools.pathanalyzer;

import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import com.google.common.base.Verify;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.util.ProgramLocation;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import kaiju.tools.ghihorn.hornifer.GhiHornifier;
import kaiju.tools.ghihorn.hornifer.horn.GhiHornArgument;
import kaiju.tools.ghihorn.hornifer.horn.HornClause;
import kaiju.tools.ghihorn.hornifer.horn.GhiHornFixedPoint;
import kaiju.tools.ghihorn.hornifer.horn.HornProgram;
import kaiju.tools.ghihorn.hornifer.horn.element.HornPredicate;

public class PathAnalyzerHornifier extends GhiHornifier {
    private Address startAddr;
    private Address endAddr;

    public PathAnalyzerHornifier() {
        super(PathAnalyzerFrontEnd.NAME);
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

        // Some addressess may be inside a basic block, hence the "containing"
        Set<HornPredicate> startSet = hornProgram.findPredicateByAddress(arg.getStart());
        Set<HornPredicate> endSet = hornProgram.findPredicateByAddress(arg.getEnd());
        Verify.verify(!startSet.isEmpty() && !endSet.isEmpty(),
                "Cannot find start/end location for evaluation");

        final HornPredicate startPred = startSet.iterator().next();

        monitor.setMessage("Found start address in block: " + startPred.getFullName());

        // If these are in different functions, then bad things may happen

        // The argument to the fixed point is 0, which is the initial value
        // of the sequence counter
        final String startFactName =
                new StringBuilder("start_").append(startPred.getFullName()).toString();

        final ProgramLocation startLoc = startPred.getLocator();

        final HornPredicate startFact =
                new HornPredicate(startFactName, startPred.getInstanceId(), startLoc);

        final String startRuleName =
                new StringBuilder(startFactName).append("-").append(startPred.getFullName())
                        .toString();

        fx.addRule(new HornClause(startRuleName, startFact, startPred));

        // End setting up the start
        ProgramLocation endLoc = null;
        if (endSet.size() > 0) {
            endLoc = endSet.iterator().next().getLocator();
        }
        final HornPredicate goalPred = new HornPredicate("goal", endLoc);
        fx.setGoal(goalPred);

        // There are multiple possible endpoints, then add them as rules
        for (HornPredicate endPred : endSet) {

            monitor.setMessage("Found end address in block: " + goalPred.getFullName());

            final String goalXRuleName =
                    new StringBuilder(endPred.getFullName()).append("-goal").toString();

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
                PathAnalyzerFrontEnd.class.getAnnotation(PathAnalyzerConfig.class);

        this.startAddr = (Address) settings.get(configuration.startAddress());
        this.endAddr = (Address) settings.get(configuration.endAddress());

        return (this.startAddr != null && this.endAddr != null);
    }

    /**
     * 
     */
    @Override
    public Set<GhiHornArgument<?>> getArguments(HornProgram hornProgram) {
        return new HashSet<GhiHornArgument<?>>() {
            {
                add(new PathAnalyzerArgument(startAddr, endAddr));
            }
        };
    }

    @Override
    protected void initializeTool(HornProgram hornProgram, final TaskMonitor mon)
            throws CancelledException {
        Set<GhiHornArgument<?>> args = getArguments(hornProgram);
        if (args.size() != 1) {
            throw new CancelledException("Incorrect number of arguments");
        }
        GhiHornArgument<?> arg = args.iterator().next();
        Address s = (Address) arg.getStart();
        Address e = (Address) arg.getEnd();
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
        throw new CancelledException("Cannot find start/end address in program!");
    }

    @Override
    protected void finalizeTool(HornProgram hornProgram, final TaskMonitor mon) {
        // There is nothing to finalize besides the standard encoding
        return;

    }
}

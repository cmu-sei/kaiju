package kaiju.tools.ghihorn.cfg;

import ghidra.program.model.pcode.PcodeOp;

public class HighCfgEdgeGuard {
   
    private boolean state;
    private PcodeOp guardOp;

    HighCfgEdgeGuard() {
        this.guardOp = null;
        this.state = true;
    }
    private HighCfgEdgeGuard(boolean state, final PcodeOp cond) {
        this.state = state;
        this.guardOp = cond;
    }

    public static HighCfgEdgeGuard mkGuardedEdge(boolean s, PcodeOp cond) {
        return new HighCfgEdgeGuard(s, cond);
    }

    public static HighCfgEdgeGuard mkUnguardedEdge() {
        return new HighCfgEdgeGuard();
    } 

    public boolean isGuarded() {
        // If there is a guard operation then it is guarded
        return this.guardOp != null;
    }

    /**
     * The guard controls the conditions under which the edge is taken
     * 
     * @return
     */
    public PcodeOp getGuardOp() {
        return guardOp;
    }

    /**
     * If the guard state is true, then the edge is the edge is taken when the guard is true.
     * Otherwise, if the guard state is false, then the edge is taken when the guard is false
     * 
     * @return
     */
    public boolean getState() {
        return state;
    }

    @Override
    public String toString() {
        if (guardOp != null) {
            //@formatter:off
            return new StringBuilder("Taken when '") 
                       .append(guardOp.toString())
                       .append("' is ")
                       .append(String.valueOf(state))
                       .toString();
            //@formatter:on
        }
        return "Unguarded";
    }
}

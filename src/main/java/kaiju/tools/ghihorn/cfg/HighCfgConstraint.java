package kaiju.tools.ghihorn.cfg;

import ghidra.program.model.pcode.PcodeOp;
public class HighCfgConstraint {
    private boolean state;
    private PcodeOp condition;

    /**
     * Construct an edge that is assumed to be unguarded
     */
    public HighCfgConstraint() {
        this.state = true;
        this.condition = null;
    }

    public HighCfgConstraint(boolean state, final PcodeOp cond) {
        this.state = state;
        this.condition = cond;
    }

    /**
     * The guard controls the conditions under which the edge is taken
     * 
     * @return
     */
    public PcodeOp getConstraint() {
        return condition;
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
        if (condition != null) {
            //@formatter:off
            return new StringBuilder("Taken when '") 
                       .append(condition.toString())
                       .append("' is ")
                       .append(String.valueOf(state))
                       .toString();
            //@formatter:on
        }
        return "Unguarded";
    }
}

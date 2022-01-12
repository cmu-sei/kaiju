package kaiju.tools.ghihorn.answer;

import ghidra.program.model.address.Address;
import kaiju.tools.ghihorn.answer.format.GhiHornFormattableElement;
import kaiju.tools.ghihorn.answer.format.GhiHornOutputFormatter;
import kaiju.tools.ghihorn.hornifer.GhiHornifier;
import kaiju.tools.ghihorn.hornifer.horn.element.HornElement;
import kaiju.tools.ghihorn.z3.GhiHornFixedpointStatus;

/**
 * Vertex attributes are essentially the horn element and it's interpretation
 */
public abstract class GhiHornAnswerAttributes implements GhiHornFormattableElement {
    protected String displayName = "UNKNOWN", vertexName = "";
    protected final HornElement hornElement;
    protected boolean isGoal, isStart;
    protected boolean isPrecondition, isPostcondition;

    protected GhiHornAnswerAttributes(String vtxName, HornElement elm) {

        this.hornElement = elm;
        this.vertexName = vtxName;
        this.isGoal = false;
        this.isStart = false;
        this.isPrecondition = false;
        this.isPrecondition = false;

        setDisplayName();
    }

    private void setDisplayName() {

        this.displayName = this.vertexName;

        // Strip off the location parts of the name
        int n = vertexName.lastIndexOf("_");
        if (n != -1) {
            this.displayName = vertexName.substring(0, n);
        }

        int pre = vertexName.lastIndexOf("_pre");
        int pst = vertexName.lastIndexOf("_post");
        if (-1 != pre) {
            isPrecondition = true;
            this.displayName = this.displayName.substring(0, pre);

        } else if (-1 != pst) {
            isPostcondition = true;
            this.displayName = this.displayName.substring(0, pst);
        }

        if (displayName.equalsIgnoreCase(GhiHornifier.START_FACT_NAME)) {
            this.isStart = true;
        }
        if (displayName.equalsIgnoreCase(GhiHornifier.GOAL_FACT_NAME)) {
            this.isGoal = true;
        }
    }

    /**
     * @return the isPostcondition
     */
    public boolean isPostcondition() {
        return isPostcondition;
    }

    /**
     * @return the isPrecondition
     */
    public boolean isPrecondition() {
        return isPrecondition;
    }

    /**
     * @return the isStart
     */
    public boolean isStart() {
        return isStart;
    }

    /**
     * @return the isGoal
     */
    public boolean isGoal() {
        return isGoal;
    }

    /**
     * @return the actual vertex name
     */
    public String getVertexName() {
        return vertexName;
    }

    /**
     * @return the display name
     */
    public String getName() {
        return displayName;
    }

    /**
     * @return the pred
     */
    public HornElement getHornElement() {
        return hornElement;
    }

    public Address getAddress() {
        return hornElement.getLocator().getAddress();
    }

    public abstract GhiHornFixedpointStatus getStatus();

    @Override
    public String format(GhiHornOutputFormatter formatter) {
        return formatter.format(this);
    }

    public String toString() {
        return this.getName();
    }
}

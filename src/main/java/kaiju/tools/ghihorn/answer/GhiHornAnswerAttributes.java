package kaiju.tools.ghihorn.answer;

import ghidra.program.model.address.Address;
import kaiju.tools.ghihorn.hornifer.horn.element.HornElement;
import kaiju.tools.ghihorn.z3.GhiHornFixedpointStatus;

/**
 * Vertex attributes are essentially the horn element and it's interpretation
 */
public abstract class GhiHornAnswerAttributes {
    protected String name = "UNKOWN";
    protected final HornElement hornElement;
    protected boolean isGoal, isStart;

    protected GhiHornAnswerAttributes(String n, HornElement elm) {
        this.name = n;
        this.hornElement = elm;
        this.isGoal = false;
        this.isStart = false;
    }

    public void makeStart() {
        this.isStart = true;
    }

    public void makeGoal() {
        this.isGoal = true;
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
     * @return the name
     */
    public String getName() {
        return name;
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
}

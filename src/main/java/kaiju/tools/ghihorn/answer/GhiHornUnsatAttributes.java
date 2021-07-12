package kaiju.tools.ghihorn.answer;

import kaiju.tools.ghihorn.hornifer.horn.element.HornElement;
import kaiju.tools.ghihorn.z3.GhiHornFixedpointStatus;

public class GhiHornUnsatAttributes extends GhiHornAnswerAttributes {
    private final Boolean result;

    public GhiHornUnsatAttributes(final String name, final HornElement elm, boolean res) {
        super(name, elm);
        result = res;
    }

    /**
     * @return the result
     */
    public boolean getResult() {
        return result;
    }
    
    public GhiHornFixedpointStatus getStatus() {
        return GhiHornFixedpointStatus.Unsatisfiable;
    }

    @Override
    public String toString() {
        return super.toString();
    }
}

package kaiju.tools.ghihorn.answer;

import java.util.Map;
import kaiju.tools.ghihorn.hornifer.horn.element.HornElement;
import kaiju.tools.ghihorn.hornifer.horn.variable.HornVariable;
import kaiju.tools.ghihorn.z3.GhiHornFixedpointStatus;

public class GhiHornSatAttributes extends GhiHornAnswerAttributes {
    private final Map<HornVariable, String> varValMap;

    public GhiHornSatAttributes(final String name, final HornElement elm,
            Map<HornVariable, String> vals) {
                
        super(name, elm);
        this.varValMap = vals;
    }

    public Map<HornVariable, String> getValueMap() {
        return varValMap;
    }

    public GhiHornFixedpointStatus getStatus() {
        return GhiHornFixedpointStatus.Satisfiable;
    }

    public String getValueMapAsString() {
        if (varValMap.isEmpty()) {
            return "";
        }
        final StringBuilder sb = new StringBuilder();
        int i = 0;
         var ci = varValMap.entrySet().iterator();
        while (ci.hasNext()) {
            var e = ci.next();
            sb.append(e.getKey()).append("=").append(e.getValue());
            if (i + 1 < varValMap.size()) {
                sb.append(" && ");
            }
            i++;
        }

        return sb.toString();
    }

    @Override
    public String toString() {
        return getName() + ": " + getValueMapAsString();
    }
}

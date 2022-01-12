package kaiju.tools.ghihorn.answer;

import java.util.Optional;
import java.util.Set;
import java.util.Iterator;
import kaiju.tools.ghihorn.hornifer.horn.element.HornElement;
import kaiju.tools.ghihorn.z3.GhiHornFixedpointStatus;

public class GhiHornUnsatAttributes extends GhiHornAnswerAttributes {
    private final Set<String> conditions;

    /**
     * 
     * @param name
     * @param elm
     * @param conds
     */
    public GhiHornUnsatAttributes(final String name, final HornElement elm, Set<String> conds) {
        super(name, elm);
        conditions = conds;
    }

    /**
     * @return the result condition
     */
    public String getConditionAsString() {
        if (conditions.isEmpty()) {
            return "";
        }
        final StringBuilder sb = new StringBuilder();
        int i = 0;
        Iterator<String> ci = conditions.iterator();
        while (ci.hasNext()) {
            sb.append(ci.next());
            if (i + 1 < conditions.size()) {
                sb.append(" && ");
            }
            i++;
        }

        return sb.toString();
    }

    /**
     * @return the result condition as a boolean
     */
    public Optional<Boolean> getConditionAsBoolean() {

        // Will there ever be a situation where there are >1 conditions and it is a list of boolean
        // values? Seems not, but you never know
        if (conditions.size() == 1) {
            String cond = conditions.iterator().next();
            if (cond.equalsIgnoreCase("true") || cond.equalsIgnoreCase("false")) {
                return Optional.of(Boolean.valueOf(cond));
            }
        }
        return Optional.empty();
    }

    public GhiHornFixedpointStatus getStatus() {
        return GhiHornFixedpointStatus.Unsatisfiable;
    }

    @Override
    public String toString() {
        String condString = getConditionAsString();
        StringBuffer sb = new StringBuffer(getVertexName());
        if (!condString.isBlank()) {
            sb.append(": "). append(condString);
        }
        return sb.toString();
    }
}

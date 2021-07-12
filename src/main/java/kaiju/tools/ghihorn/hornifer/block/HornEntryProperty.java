package kaiju.tools.ghihorn.hornifer.block;

import java.util.HashMap;
import java.util.Map;

import kaiju.tools.ghihorn.hornifer.horn.variable.HornVariable;
/**
 *   
 */ 
 public class HornEntryProperty implements HornBlockProperty {
    // Incoming parameters to the entry
    private Map<Integer, HornVariable> parameters;

    public HornEntryProperty() {
        this.parameters = new HashMap<>();
    }

    /**
     * Add a parameter 
     * @param ordinal the ordinal 
     * @param v the horn variable to add
     */
    public void addParameter(Integer ordinal, final HornVariable v) {
        parameters.put(ordinal, v);
    }

    /**
     * Fetch a parameter by ordinal s
     * @param ordinal
     * @return
     */
    public HornVariable getParameter(Integer ordinal) {
        return this.parameters.get(ordinal);
    }

    /**
     * Feth all the parameters
     * @return
     */
    public Map<Integer, HornVariable> getParameters() {
        return this.parameters;
    }

    @Override
    public Property getProperty() {
        return HornBlockProperty.Property.Entry;
    }

    public String toString() {
        StringBuilder b = new StringBuilder("Entry Block\n----------Params:\n");
        this.parameters.forEach((k, v) -> b.append(k).append(" ->").append(v));
    
        return b.toString();
    }
}

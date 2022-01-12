package kaiju.tools.ghihorn.hornifer.block;

import java.util.ArrayList;
import java.util.EnumMap;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import com.microsoft.z3.Expr;
import com.microsoft.z3.Sort;
import ghidra.program.model.address.Address;
import ghidra.program.model.pcode.PcodeOp;
import kaiju.tools.ghihorn.cfg.HighCfgVertex;
import kaiju.tools.ghihorn.cfg.VertexAttributes;
import kaiju.tools.ghihorn.hornifer.block.HornBlockProperty.Property;
import kaiju.tools.ghihorn.hornifer.horn.HornFunction;
import kaiju.tools.ghihorn.hornifer.horn.expression.PcodeExpression;
import kaiju.tools.ghihorn.hornifer.horn.variable.HornVariable;
import kaiju.tools.ghihorn.z3.GhiHornContext;

public class HornBlock {

    private final EnumMap<HornBlockProperty.Property, HornBlockProperty> propertyMap;
    private final HornFunction hornFunction;
    private final HighCfgVertex<Address, VertexAttributes> vertex;
    private final TreeMap<PcodeOp, PcodeExpression> pcodeExprMap;
    private final Set<HornVariable> useVariables;
    private final Set<HornVariable> defVariables;

    /**
     * Copy constructor
     * 
     * @param other
     */
    public HornBlock(HornBlock other) {
        this(other.hornFunction, other.vertex);

        this.defVariables.addAll(other.defVariables);
        this.useVariables.addAll(other.useVariables);
    }

    /**
     * Create a horn block from a vertex in a function
     * 
     * @param hornFunc
     * @param v
     */
    public HornBlock(HornFunction hornFunc, HighCfgVertex<Address, VertexAttributes> v) {
        this.hornFunction = hornFunc;
        this.vertex = v;
        this.propertyMap = new EnumMap<>(HornBlockProperty.Property.class);
        this.useVariables = new HashSet<>();
        this.defVariables = new HashSet<>();

        // order the pcode expressions based on pcode itself
        pcodeExprMap = new TreeMap<>((pc1, pc2) -> {
            int o1 = pc1.getSeqnum().getOrder();
            int o2 = pc2.getSeqnum().getOrder();
            if (o1 < o2) {
                return -1;
            } else if (o2 < o1) {
                return 1;
            }
            // equal should not happen, but you never know ...
            return 0;
        });
    }

    /**
     * @return the startAddress
     */
    public Address getStartAddress() {
        return this.vertex.getEntity().getMinAddress();
    }

    /**
     * @return the stopAddress
     */
    public Address getStopAddress() {
        return this.vertex.getEntity().getMaxAddress();

    }

    public boolean hasProperty(Property type) {
        return this.propertyMap.containsKey(type);
    }

    public HornBlockProperty getProperty(HornBlockProperty.Property type) {
        return this.propertyMap.get(type);
    }

    public boolean addProperty(HornBlockProperty prop) {
        return (null == propertyMap.putIfAbsent(prop.getProperty(), prop));
    }

    public HornFunction getHornFunction() {
        return this.hornFunction;
    }

    public boolean addDefVariable(final HornVariable v) {
        return defVariables.add(v);
    }

    public boolean addUseVariable(final HornVariable v) {
        return useVariables.add(v);
    }

    public void addExpression(PcodeOp pcode, PcodeExpression expression) {
        this.pcodeExprMap.put(pcode, expression);
    }

    public boolean isExternal() {
        return this.hornFunction.isExternal();
    }

    public boolean isImported() {
        return this.hornFunction.isImported();
    }

    /**
     * Instantiate the state for this block
     * 
     * @param ctx
     * @return
     */
    public Map<Expr<? extends Sort>, Expr<? extends Sort>> instantiateState(GhiHornContext ctx) {

        Map<Expr<? extends Sort>, Expr<? extends Sort>> state = new HashMap<>();
        List<Expr<? extends Sort>> orderedPcodeExprs = instantiateExpressionsInOrder(ctx);

        // create the input/output state for this block. The initial state is
        // the mapping of each pcode, which is typically of the form (= out in)

        for (var pc : orderedPcodeExprs) {
            if (pc != null && pc.isEq()) {
                Expr<?>[] args = pc.getArgs();
                if (!args[0].equals(args[1])) {

                    // For some reason pcode can have a format of X = X, which has no impact on
                    // true state but overwrites the state prior

                    state.put(args[0], args[1]);
                }
            }
        }

        // Nothing to substitute?
        if (state.size() <= 1) {
            return state;
        }

        for (int outer = 0; outer < orderedPcodeExprs.size(); outer++) {

            Expr<? extends Sort> in = orderedPcodeExprs.get(outer).getArgs()[0];
            Expr<? extends Sort> out = state.get(in);

            // +1 so not sub-ing yourself
            boolean fixedpoint = false;
            for (int inner = outer + 1; inner < orderedPcodeExprs.size(); inner++) {

                Expr<? extends Sort> nextIn = orderedPcodeExprs.get(inner).getArgs()[0];
                Expr<? extends Sort> nextOut = state.get(nextIn);
                
                if (out != null && nextOut != null && !out.equals(nextOut)) {
                    Expr<? extends Sort> sub = nextOut.substitute(in, out); // in=from, out=to
                    state.replace(nextIn, sub);
                } else {
                    fixedpoint = true;
                }
            }
            if (fixedpoint) {
                // If there were no changes, then the state is settled into a fixed point
                break;
            }
        }
        return state;
    }

    /**
     * intantiate the expressions in pcode order
     * 
     * @param ctx a valid z3 context
     * 
     * @return the list of instantiated expressions
     */
    public List<Expr<? extends Sort>> instantiateExpressionsInOrder(GhiHornContext ctx) {

        // iterate over the entryset for explicit order
        List<Expr<? extends Sort>> pcodeOrderExprs = new ArrayList<>();
        pcodeExprMap.entrySet()
                    .stream()
                    .sequential()
                    .map(pcx -> pcx.getValue().instantiate(ctx))
                .filter(expr -> expr != null).forEach(pcodeOrderExprs::add);

        return pcodeOrderExprs;

    }

    /**
     * @return the expressions
     */
    public TreeMap<PcodeOp, PcodeExpression> getExpressions() {
        return pcodeExprMap;
    }

    /**
     * @return the variables
     */
    public Set<HornVariable> getVariables() {
        return new HashSet<HornVariable>() {
            {
                addAll(useVariables);
                addAll(defVariables);
            }
        };
    }

    /**
     * @return the vertex
     */
    public HighCfgVertex<Address, VertexAttributes> getVertex() {
        return vertex;
    }

    /*
     * (non-Javadoc)
     * 
     * @see java.lang.Object#toString()
     */
    @Override
    public String toString() {
        return vertex.getLocator().toString();
    }

    public String getInformation() {

        final StringBuilder b = new StringBuilder("==========\n");
        b.append(toString()).append("\n---------- Def:\n");
        this.defVariables.forEach(d -> b.append(" * ").append(d).append("\n"));
        b.append("\n---------- Use:\n");
        this.useVariables.forEach(u -> b.append(" * ").append(u).append("\n"));
        b.append("\n---------- Exprs:\n");
        this.pcodeExprMap.keySet().forEach(e -> b.append(" * ").append(e).append("\n"));

        return b.toString();
    }

    /**
     * @return true if this block contains an address; false otherwise
     */
    public boolean containsAddress(final Address addr) {
        VertexAttributes attrs = vertex.getEntity();
        return attrs.containsAddress(addr);
    }

    public Set<HornVariable> getUseVariables() {
        return this.useVariables;
    }

    public Set<HornVariable> getDefVariables() {
        return this.defVariables;
    }

    /*
     * (non-Javadoc)
     * 
     * @see java.lang.Object#hashCode()
     */

    @Override
    public int hashCode() {
        return vertex.getLocator().hashCode();
    }

    /*
     * (non-Javadoc)
     * 
     * @see java.lang.Object#equals(java.lang.Object)
     */

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;
        if (getClass() != obj.getClass())
            return false;
        HornBlock other = (HornBlock) obj;
        if (defVariables == null) {
            if (other.defVariables != null)
                return false;
        } else if (!defVariables.equals(other.defVariables))
            return false;
        if (hornFunction == null) {
            if (other.hornFunction != null)
                return false;
        } else if (!hornFunction.equals(other.hornFunction))
            return false;
        if (pcodeExprMap == null) {
            if (other.pcodeExprMap != null)
                return false;
        } else if (!pcodeExprMap.equals(other.pcodeExprMap))
            return false;
        if (propertyMap == null) {
            if (other.propertyMap != null)
                return false;
        } else if (!propertyMap.equals(other.propertyMap))
            return false;
        if (useVariables == null) {
            if (other.useVariables != null)
                return false;
        } else if (!useVariables.equals(other.useVariables))
            return false;
        if (vertex == null) {
            if (other.vertex != null)
                return false;
        } else if (!vertex.equals(other.vertex))
            return false;
        return true;
    }

}

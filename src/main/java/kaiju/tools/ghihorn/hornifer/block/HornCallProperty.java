package kaiju.tools.ghihorn.hornifer.block;

import java.util.HashMap;
import java.util.Map;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import kaiju.tools.ghihorn.hornifer.horn.expression.HornExpression;
import kaiju.tools.ghihorn.hornifer.horn.variable.HornVariable;

/**
 * Represens a call property including call address, arguments, and return value
 */
public class HornCallProperty implements HornBlockProperty {

    private final Map<Integer, HornVariable> callArguments;
    private Address calledFromAddr;
    private Function calledFunction;
    private HornVariable retVal;
    private boolean isExternal;

    public HornCallProperty() {
        this.callArguments = new HashMap<>();
        this.retVal = null;
        this.isExternal = false;
    }

    public boolean isExternal() {
        return this.isExternal;
    }

    public void isExternal(boolean v) {
        this.isExternal = v;
    }

    public void addRetVal(HornVariable rv) {
        this.retVal = rv;
    }

    public HornVariable getRetVal() {
        return this.retVal;
    }

    public void addCallArgument(Integer ordinal, final HornVariable arg) {
        callArguments.put(ordinal, arg);
    }

    public HornExpression getCallArgument(Integer ordinal) {
        return this.callArguments.get(ordinal);
    }

    public Map<Integer, HornVariable> getCallArguments() {
        return this.callArguments;
    }

    @Override
    public Property getProperty() {
        return HornBlockProperty.Property.Call;
    }

    /**
     * @return the calledFromAddr
     */
    public Address getCalledFromAddress() {
        return calledFromAddr;
    }

    /**
     * @param calledFromAddr the calledFromAddr to set
     */
    public void setCalledFromAddr(Address calledFromAddr) {
        this.calledFromAddr = calledFromAddr;
    }

    /**
     * @return the calledFunction
     */
    public Function getCalledFunction() {
        return calledFunction;
    }

    /**
     * @param calledFunction the calledFunction to set
     */
    public void setCalledFunction(Function calledFunction) {
        this.calledFunction = calledFunction;
    }

    public String toString() {
        StringBuilder b =
                new StringBuilder("Call to: ").append(this.calledFunction).append(", From: ")
                        .append(calledFromAddr).append("\n----------Args:\n");
        this.callArguments.forEach((k, v) -> b.append(k).append(" ->").append(v));
        b.append("Return:").append(this.retVal);
        return b.toString();
    }
}

package kaiju.tools.ghihorn.tools.apianalyzer;

import ghidra.program.model.address.Address;
import kaiju.tools.ghihorn.answer.format.GhiHornOutputFormatter;
import kaiju.tools.ghihorn.hornifer.horn.GhiHornArgument;
import kaiju.tools.ghihorn.hornifer.horn.HornFunctionInstance;

/**
 * APIAnalyzer coordinates are in terms of functions (API calls rather than addresses)
 */
public class ApiAnalyzerArgument implements GhiHornArgument<HornFunctionInstance> {

    private final ApiSignature signature;
    private final HornFunctionInstance startPoint;
    private final HornFunctionInstance endPoint;
    private final HornFunctionInstance entryPoint;

    /**
     * @param sig
     * @param startAddr
     * @param endAddr
     */
    public ApiAnalyzerArgument(ApiSignature sig, HornFunctionInstance entry,
            HornFunctionInstance start, HornFunctionInstance end) {

        this.signature = sig;
        this.entryPoint = entry;
        this.startPoint = start;
        this.endPoint = end;
    }

    /**
     * @return the signatureName
     */
    public ApiSignature getSignature() {
        return signature;
    }

    public HornFunctionInstance getStart() {
        return startPoint;
    }

    /**
     * p
     * 
     * @return the startAddr
     */
    public HornFunctionInstance getEntry() {
        return entryPoint;
    }

    /**
     * @return the endAddr
     */
    public HornFunctionInstance getGoal() {
        return endPoint;
    }

    public Address getStartAsAddress() {
        if (endPoint == null) {
            return Address.NO_ADDRESS;
        }
        return startPoint.getPrecondition().getLocator().getAddress();
    }

    @Override
    public Address getGoalAsAddress() {
        if (endPoint == null) {
            return Address.NO_ADDRESS;
        }
        return endPoint.getPostcondition().getLocator().getAddress();
    }


    @Override
    public Address getEntryAsAddress() {
        if (entryPoint == null) {
            return Address.NO_ADDRESS;
        }
        return entryPoint.getPrecondition().getLocator().getAddress();

    }

    @Override
    public String toString() {
        return new StringBuilder("Sig: ")
                .append(signature.getName())
                .append(", Entry: ")
                .append(getEntryAsAddress())
                .append(", Start: ")
                .append(getStartAsAddress())
                .append(", Goal: ")
                .append(getGoalAsAddress())
                .toString();
    }

    @Override
    public String format(GhiHornOutputFormatter formatter) {
        return formatter.format(this);
    }
}

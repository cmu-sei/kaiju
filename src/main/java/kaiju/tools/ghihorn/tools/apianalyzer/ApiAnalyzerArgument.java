package kaiju.tools.ghihorn.tools.apianalyzer;

import ghidra.program.model.address.Address;
import kaiju.tools.ghihorn.hornifer.horn.GhiHornArgument;
import kaiju.tools.ghihorn.hornifer.horn.element.HornPredicate;


public class ApiAnalyzerArgument implements GhiHornArgument<HornPredicate> {
    private final ApiSignature signature;
    private final HornPredicate startPred;
    private final HornPredicate endPred;

    /**
     * @param sig
     * @param startAddr
     * @param endAddr
     */
    public ApiAnalyzerArgument(ApiSignature sig, HornPredicate startAddr, HornPredicate endAddr) {
        this.signature = sig;
        this.startPred = startAddr;
        this.endPred = endAddr;
    }

    /**
     * @return the signatureName
     */
    public ApiSignature getSignature() {
        return signature;
    }

    /**
     * @return the startAddr
     */
    public HornPredicate getStart() {
        return startPred;
    }

    /**
     * @return the endAddr
     */
    public HornPredicate getEnd() {
        return endPred;
    }

    @Override
    public String toString() {
        return new StringBuilder(signature.getName())
                .append(": ")
                .append(startPred.getLocator().getAddress())
                .append("-")
                .append(endPred.getLocator().getAddress())
                .toString();
    }

    @Override
    public Address getStartAddress() {
        if (endPred == null) {
            return Address.NO_ADDRESS;
        }
        return endPred.getLocator().getAddress();
    }

    @Override
    public Address getEndAddress() {
        if (startPred == null) {
            return Address.NO_ADDRESS;
        }
        return startPred.getLocator().getAddress();

    }
}

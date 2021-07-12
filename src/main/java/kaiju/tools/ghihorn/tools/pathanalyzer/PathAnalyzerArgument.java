package kaiju.tools.ghihorn.tools.pathanalyzer;

import ghidra.program.model.address.Address;
import kaiju.tools.ghihorn.hornifer.horn.GhiHornArgument;

public class PathAnalyzerArgument implements GhiHornArgument<Address> {
    private final Address startAddr;
    private final Address endAddr;

    /**
     * @param sig
     * @param startAddr
     * @param endAddr
     */
    public PathAnalyzerArgument(Address startAddr, Address endAddr) {
        this.startAddr = startAddr;
        this.endAddr = endAddr;
    }

    /**
     * @return the startAddr
     */
    public Address getStart() {
        return startAddr;
    }

    /**
     * @return the endAddr
     */
    public Address getEnd() {
        return endAddr;
    }

    @Override
    public String toString() {
        return new StringBuilder(startAddr.toString())
                .append("-")
                .append(endAddr)
                .toString();
    }

    @Override
    public Address getStartAddress() {
        if (startAddr == null) {
            return Address.NO_ADDRESS;
        }
        return startAddr;
    }

    @Override
    public Address getEndAddress() {
        if (endAddr == null) {
            return Address.NO_ADDRESS;
        }
        return endAddr;
    }
}

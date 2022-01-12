package kaiju.tools.ghihorn.tools.pathanalyzer;

import ghidra.program.model.address.Address;
import kaiju.tools.ghihorn.answer.format.GhiHornOutputFormatter;
import kaiju.tools.ghihorn.hornifer.horn.GhiHornArgument;

public class PathAnalyzerArgument implements GhiHornArgument<Address> {
    private final Address entryAddr;
    private final Address goalAddr;

    /**
     * @param sig
     * @param startAddr
     * @param endAddr
     */
    public PathAnalyzerArgument(Address startAddr, Address endAddr) {
        this.entryAddr = startAddr;
        this.goalAddr = endAddr;
    }

    /**
     * @return the startAddr
     */
    @Override
    public Address getEntry() {
        return entryAddr;
    }

    /**
     * @return the endAddr
     */
    @Override
    public Address getGoal() {
        return goalAddr;
    }

    @Override
    public String toString() {
        return new StringBuilder("Start: ")
                .append(entryAddr.toString())
                .append(", Goal: ")
                .append(goalAddr)
                .toString();
    }

    @Override
    public Address getEntryAsAddress() {
        if (entryAddr == null) {
            return Address.NO_ADDRESS;
        }
        return entryAddr;
    }

    @Override
    public Address getGoalAsAddress() {
        if (goalAddr == null) {
            return Address.NO_ADDRESS;
        }
        return goalAddr;
    }

    @Override
    public String format(GhiHornOutputFormatter formatter) {
        return formatter.format(this);
    }
}

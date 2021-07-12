package kaiju.tools.ghihorn.cfg;

import java.util.List;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.pcode.PcodeBlockBasic;
import ghidra.program.model.pcode.PcodeOp;

public class VertexAttributes {

    /** every vertex has pcode */
    private final List<PcodeOp> pcodeList;
    private AddressSet cover;

    public VertexAttributes(AddressSet c, final List<PcodeOp> pc) {
        this.pcodeList = pc;
        this.cover = c;
    }

    /**
     * Fetch the pcode associated with this block
     * 
     * @return
     */
    public List<PcodeOp> getPcode() {
        return this.pcodeList;
    }

    public PcodeOp getFirstPcode() {
        if (pcodeList.isEmpty()) {
            return null;
        }
        return pcodeList.get(0);
    }

    public PcodeOp getLastPcode() {
        if (pcodeList.isEmpty()) {
            return null;
        }
        return pcodeList.get(pcodeList.size() - 1);
    }

    private boolean endsInOp(int opcode) {
        PcodeOp endPcode = getLastPcode();
        if (endPcode != null) {
            return (endPcode.getOpcode() == opcode);
        }
        return false;
    }

    public boolean endsInCall() {
        return endsInOp(PcodeOp.CALL);
    }

    public boolean endsInReturn() {
        return endsInOp(PcodeOp.RETURN);
    }

    public Address getFirstPcodeAddress() {
        if (pcodeList.isEmpty()) {
            return Address.NO_ADDRESS;
        }
        return this.pcodeList.get(0).getSeqnum().getTarget();
    }

    public Address getMinAddress() {
        return cover.getMinAddress();
    }

    public Address getMaxAddress() {
        return cover.getMaxAddress();
    }

    public boolean containsAddress(final Address addr) {
        return cover.contains(addr);
    }

    public Address getLastPcodeAddress() {
        PcodeOp lastPcode = getLastPcode();
        if (lastPcode == null) {
            return Address.NO_ADDRESS;
        }
        return lastPcode.getSeqnum().getTarget();
    }

    public PcodeBlockBasic getPcodeBlockBasic() {

        if (this.pcodeList != null && !this.pcodeList.isEmpty()) {
            return getFirstPcode().getParent();
        }
        return null;
    }

    @Override
    public String toString() {
        return new StringBuilder("VertexAttributes@").append(cover.toString()).toString();
    }
}

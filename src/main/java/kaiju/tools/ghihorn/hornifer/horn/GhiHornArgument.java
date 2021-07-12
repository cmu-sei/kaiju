package kaiju.tools.ghihorn.hornifer.horn;

import ghidra.program.model.address.Address;

/**
 * Interface for arguments
 */
public interface GhiHornArgument<T> {
    /**
     * 
     * @return the start
     */
    public T getStart();

    /**
     * 
     * @return the end
     */
    public T getEnd();

    public Address getStartAddress();

    public Address getEndAddress();
}

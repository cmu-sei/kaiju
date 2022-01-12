package kaiju.tools.ghihorn.hornifer.horn;

import ghidra.program.model.address.Address;
import kaiju.tools.ghihorn.answer.format.GhiHornFormattableElement;

/**
 * Interface for arguments
 */
public interface GhiHornArgument<T> extends GhiHornFormattableElement {

    /**
     * 
     * @return the starting element
     */
    public T getEntry();

    /**
     * 
     * @return the ending element
     */
    public T getGoal();

    public Address getEntryAsAddress();

    public Address getGoalAsAddress();
}

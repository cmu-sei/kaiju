package kaiju.tools.ghihorn.hornifer.block;

import ghidra.program.model.pcode.HighVariable;
import kaiju.tools.ghihorn.hornifer.horn.variable.HornVariable;

/**
 * Represents a return block. Although a function can have multiple "returns" there is generally one
 * result parameter. It is captured here
 */
public class HornRetnProperty implements HornBlockProperty {

    private HighVariable retHighVar;
    private HornVariable retVal;

    public HornRetnProperty() {
        retHighVar = null;
        retVal = null;
    }

    public boolean hasRetVal() {
        return (this.retHighVar != null && this.retVal != null);
    }

    public void setReturnValueHighVariable(final HighVariable retVar) {
        this.retHighVar = retVar;
    }

    public void setReturnValue(final HornVariable ret) {
        this.retVal = ret;
    }

    public HighVariable getReturnValueHighVariable() {
        return this.retHighVar;
    }

    public HornVariable getReturnValue() {
        return this.retVal;
    }

    @Override
    public Property getProperty() {
        return Property.Return;
    }

    public String toString() {
        return new StringBuilder("Return block; Value: ").append(retVal).toString();
    }
}


package kaiju.tools.ghihorn.z3;

import com.microsoft.z3.Expr;
import com.microsoft.z3.Sort;

public class GhiHornUndefinedType implements GhiHornDataType {

    @Override
    public GhiHornType getType() {
        return GhiHornType.Undefined;
    }

    @Override
    public Sort mkSort(GhiHornContext ctx) {
        return null;
    }

    @Override
    public Expr<? extends Sort> mkConst(GhiHornContext ctx, String name) {
        return null;
    }    
}

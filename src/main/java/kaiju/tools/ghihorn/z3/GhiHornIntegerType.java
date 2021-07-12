package kaiju.tools.ghihorn.z3;

import com.microsoft.z3.Expr;
import com.microsoft.z3.Sort;

public class GhiHornIntegerType implements GhiHornDataType  {
    
    @Override
    public Sort mkSort(final GhiHornContext ctx) {
        return ctx. mkIntSort();
    }

    @Override
    public Expr<? extends Sort> mkConst(final GhiHornContext ctx, final String name) {
        return ctx.mkIntConst(name);
    
    }   
    
    @Override
    public GhiHornType getType() {        
        return GhiHornType.Int;
    }
}

package kaiju.tools.ghihorn.z3;

import com.microsoft.z3.Expr;
import com.microsoft.z3.Sort;

public class GhiHornBooleanType implements GhiHornDataType {

    @Override
    public Sort mkSort(GhiHornContext ctx) {
        return ctx.mkBoolSort();
    }

    @Override
    public Expr<? extends Sort> mkConst(GhiHornContext ctx, String name) {
        return ctx.mkBoolConst(name);
    }

    @Override
    public GhiHornType getType() {
        return GhiHornType.Bool;
    }
}
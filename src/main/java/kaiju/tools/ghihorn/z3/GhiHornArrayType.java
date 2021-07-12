package kaiju.tools.ghihorn.z3;

import com.microsoft.z3.ArraySort;
import com.microsoft.z3.Expr;
import com.microsoft.z3.Sort;


public class GhiHornArrayType implements GhiHornDataType {
    private GhiHornDataType indexType;
    private GhiHornDataType valueType;

    public GhiHornArrayType(GhiHornDataType indexType, GhiHornDataType valueType) {
        this.indexType = indexType;
        this.valueType = valueType;
    }

    @Override
    public GhiHornType getType() {
        return GhiHornType.Array;
    }

    @Override
    public Sort mkSort(GhiHornContext ctx) {
        Sort idxSort = indexType.mkSort(ctx);
        Sort valSort = valueType.mkSort(ctx);

        return ctx.mkArraySort(idxSort, valSort);
    }

    @Override
    public Expr<ArraySort<? extends Sort, ? extends Sort>> mkConst(GhiHornContext ctx, String name) {

        Sort indexSort = indexType.mkSort(ctx);
        Sort valueSort = valueType.mkSort(ctx);

        ArraySort<? extends Sort, ? extends Sort> arrayType = ctx.mkArraySort(indexSort, valueSort);
        
        return ctx.mkConst(name, arrayType);
    }

    /**
     * @return the indexType
     */
    public GhiHornDataType getIndexDataType() {
        return indexType;
    }

    /**
     * @return the valueType
     */
    public GhiHornDataType getValueDataType() {
        return valueType;
    }
}

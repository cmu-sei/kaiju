package kaiju.tools.ghihorn.z3;

import com.microsoft.z3.Expr;
import com.microsoft.z3.Sort;

/**
 * 
 */
public class GhiHornBitVectorType implements GhiHornDataType {
    public static int DEFAULT_BV_SIZE=64;
    private int size;

    public GhiHornBitVectorType(int size) {
        this.size = size;
    }

    /**
     * Create a 64b BV type
     */
    public GhiHornBitVectorType() {
        this.size = DEFAULT_BV_SIZE;
    }


    @Override
    public Sort mkSort(final GhiHornContext ctx) {
        return ctx.mkBitVecSort(size);
    }

    @Override
    public Expr<? extends Sort> mkConst(final GhiHornContext ctx, final String name) {
        return ctx.mkBVConst(name, size);
    }

    /**
     * @return the size
     */
    public int getSize() {
        return size;
    }

    @Override
    public GhiHornType getType() {
       return GhiHornType.BitVec;
    }
   
    
}

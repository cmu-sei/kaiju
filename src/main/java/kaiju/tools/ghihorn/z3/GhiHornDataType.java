package kaiju.tools.ghihorn.z3;

import com.microsoft.z3.Expr;
import com.microsoft.z3.Sort;

// Variable types
public interface GhiHornDataType {
    public static final int FLOAT_EBITS = 11;
    public static final int FLOAT_SBITS = 53;
    public static final int SIZE_64BIT = 64;
    public static final int BYTE_WIDTH = 8;
    
    public GhiHornType getType();
    public Sort mkSort(GhiHornContext ctx);
    public Expr<? extends Sort> mkConst(GhiHornContext ctx, String name);
}
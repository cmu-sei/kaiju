package kaiju.tools.ghihorn.hornifer.horn.expression;

import com.microsoft.z3.Expr;
import com.microsoft.z3.Sort;
import com.microsoft.z3.Z3Exception;

import kaiju.tools.ghihorn.z3.GhiHornContext;
import kaiju.tools.ghihorn.z3.GhiHornType;

/**
 * Common interface for every type of expression
 */
public interface HornExpression {

    /**
     * Every expression must be able to be instantiated
     * 
     * @param ctx
     * @return
     * @throws Z3Exception
     */
    public Expr<? extends Sort> instantiate(GhiHornContext ctx);

    public GhiHornType getType();

    public HornExpression[] getComponents();
}

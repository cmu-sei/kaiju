package kaiju.tools.ghihorn.hornifer.horn.expression;

import com.microsoft.z3.BoolExpr;
import kaiju.tools.ghihorn.z3.GhiHornContext;
import kaiju.tools.ghihorn.z3.GhiHornType;

public class FalseExpression implements HornExpression {
    
    @Override
    public BoolExpr instantiate(GhiHornContext ctx) {
        return ctx.mkFalse();
    }

    /**
     * @param lhs
     * @param rhs
     */
    public FalseExpression() {
        
    }

    @Override
    public String toString() {
        return "false";
    }

    @Override
    public GhiHornType getType() {
        return GhiHornType.Bool;
    }

    @Override
    public HornExpression[] getComponents() {
       return new HornExpression[] { };
    }
}

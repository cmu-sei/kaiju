package kaiju.tools.ghihorn.hornifer.horn.variable;

import com.microsoft.z3.Expr;
import com.microsoft.z3.Sort;

import kaiju.tools.ghihorn.hornifer.horn.expression.HornExpression;
import kaiju.tools.ghihorn.hornifer.horn.variable.HornVariable.Scope;
import kaiju.tools.ghihorn.z3.GhiHornContext;
import kaiju.tools.ghihorn.z3.GhiHornType;

/**
 * Variables bound to a Z3 expression 
 */
public class HornVariableExpression {
    
    private final HornVariable variable;
    
    // An expression can be a value
    private final HornExpression expression;

    /**
     * @param variable
     * @param expression
     */
    public HornVariableExpression(HornVariable variable, HornExpression expression) {
        this.variable = variable;
        this.expression = expression;
    }

    public HornVariableExpression(HornVariable variable) {
        this.variable = variable;
        this.expression = null;
    }

    public Expr<? extends Sort> instantiate(GhiHornContext ctx) {
        if (expression != null) {
            return expression.instantiate(ctx);
        }
        return variable.instantiate(ctx);
    }

    /**
     * @return the variable
     */
    public HornVariable getVariable() {
      return variable;
    }

    /**
     * @return the expression
     */
    public HornExpression getExpression() {
      return expression;
    }

    /**
     * @return the expr
     */
    public GhiHornType getType() {
        return variable.getType();
    }

    public String getName() {
        return variable.getName();
    }

    /**
     * @return the scope
     */
    public Scope getScope() {
        return variable.getScope();
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder("[Var=");
        sb.append(this.variable.toString());
        if (expression != null) {
            sb.append(", Expr= ").append(expression.toString());
        }
        return sb.append("]").toString();
    }
}

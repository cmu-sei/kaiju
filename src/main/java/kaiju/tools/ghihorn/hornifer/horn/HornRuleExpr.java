package kaiju.tools.ghihorn.hornifer.horn;

import com.microsoft.z3.BoolExpr;
import com.microsoft.z3.BoolSort;
import com.microsoft.z3.Expr;
import com.microsoft.z3.FuncDecl;
import com.microsoft.z3.Symbol;
import kaiju.tools.ghihorn.z3.GhiHornContext;

/**
 * A Horn rule expression, including the relations and expressions for the head and body
 */
public class HornRuleExpr {
    private final BoolExpr headExpr, bodyExpr, ruleExpr;
    private final Expr<BoolSort> constraintExpr;
    private final Symbol nameSymbol;

    public HornRuleExpr(final String name, final GhiHornContext ctx, BoolExpr body,
            BoolExpr head, Expr<BoolSort> constraints ) {
        this.bodyExpr = body;
        this.headExpr = head;
        this.nameSymbol = ctx.mkSymbol(name);
        this.constraintExpr = constraints;
        this.ruleExpr = ctx.mkRule(name, ctx.mkAnd(bodyExpr, constraintExpr), headExpr);
    }

    /*
     * (non-Javadoc)
     * 
     * @see java.lang.Object#hashCode()
     */
    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        
        result = prime * result + ((bodyExpr == null) ? 0 : bodyExpr.hashCode());
        result = prime * result + ((constraintExpr == null) ? 0 : constraintExpr.hashCode());        
        result = prime * result + ((headExpr == null) ? 0 : headExpr.hashCode());
        result = prime * result + ((nameSymbol == null) ? 0 : nameSymbol.hashCode());
        result = prime * result + ((ruleExpr == null) ? 0 : ruleExpr.hashCode());
        return result;
    }

    /**
     * @return the headDecl
     */
    public FuncDecl<BoolSort> getHeadDecl() {
        return headExpr.getFuncDecl();
    }

    /**
     * @return the bodyDecl
     */
    public FuncDecl<BoolSort> getBodyDecl() {
        return bodyExpr.getFuncDecl();
    }

    /**
     * @return the headExpr
     */
    public Expr<BoolSort> getHeadExpr() {
        return headExpr;
    }

    /**
     * @return the bodyExpr
     */
    public Expr<BoolSort> getBodyExpr() {
        return bodyExpr;
    }

    /**
     * @return the ruleExpr
     */
    public Expr<BoolSort> getRuleExpr() {
        return ruleExpr;
    }

    /**
     * @return the constraintExpr
     */
    public Expr<BoolSort> getConstraintExpr() {
        return constraintExpr;
    }

    /**
     * @return the nameSymbol
     */
    public Symbol getNameSymbol() {
        return nameSymbol;
    }

    @Override
    public String toString() {
        final StringBuilder sb = new StringBuilder();

        sb.append(this.headExpr.toString()).append(" <- ").append(this.bodyExpr.toString());
        if (constraintExpr != null) {
            sb.append(" && ").append(constraintExpr);
        }
        return sb.toString();
    }

    /*
     * (non-Javadoc)
     * 
     * @see java.lang.Object#equals(java.lang.Object)
     */
    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;
        if (getClass() != obj.getClass())
            return false;
        HornRuleExpr other = (HornRuleExpr) obj;
        if (bodyExpr == null) {
            if (other.bodyExpr != null)
                return false;
        } else if (!bodyExpr.equals(other.bodyExpr))
            return false;
        if (constraintExpr == null) {
            if (other.constraintExpr != null)
                return false;
        } else if (!constraintExpr.equals(other.constraintExpr))
            return false;
        if (headExpr == null) {
            if (other.headExpr != null)
                return false;
        } else if (!headExpr.equals(other.headExpr))
            return false;
        if (nameSymbol == null) {
            if (other.nameSymbol != null)
                return false;
        } else if (!nameSymbol.equals(other.nameSymbol))
            return false;
        if (ruleExpr == null) {
            if (other.ruleExpr != null)
                return false;
        } else if (!ruleExpr.equals(other.ruleExpr))
            return false;
        return true;
    }
}

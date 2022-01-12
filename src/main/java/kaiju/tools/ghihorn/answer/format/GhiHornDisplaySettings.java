package kaiju.tools.ghihorn.answer.format;

public class GhiHornDisplaySettings {

    private boolean showGlobalVars, showLocalVars, showAllState, hideTempVars, hideExternalFuncs;
    private OutputFormat format;

    public enum OutputFormat {
        JSON, TEXT, DOT;
    }

    public enum SettingVariables {
        //@formatter:off
        OututJson ("Generate json output"),
        OuputText ("Generate text output"),
        ShowGlobalVars ("Show global variables"),
        ShowLocalVars ("Show local variables"),
        ShowAllState ("Show all state"),
        HideTempVars ("Hide temporary variables"),
        HideExternalFunctions ("Hide external function bodies");
        //@formatter:on

        private String description;

        public String description() {
            return this.description;
        }

        private SettingVariables(String desc) {
            this.description = desc;
        }
    }

    public GhiHornDisplaySettings() {
        showGlobalVars = true;
        showLocalVars = true;
        hideExternalFuncs = true;
        hideTempVars = true;
        format = OutputFormat.TEXT;
    }

    /**
     * @param hideExternalFuncs the showExternalApiFuncs to set
     */
    public void hideExternalFuncs(boolean x) {
        hideExternalFuncs = x;
    }

    /**
     * @return the showExternalApiFunctions
     */
    public boolean hideExternalFunctions() {
        return hideExternalFuncs;
    }

    /**
     * @return the showGlobalVars
     */
    public boolean showGlobalVariables() {
        return showGlobalVars;
    }

    /**
     * @param t if true, then hide
     */
    public void hideTempVariables(boolean t) {
        hideTempVars = t;
    }

    /**
     * @return the showGlobalVars
     */
    public boolean hideTempVariables() {
        return hideTempVars;
    }

    /**
     * @param g if true, then show
     */
    public void showGlobalVariables(boolean g) {
        showGlobalVars = g;
    }

    /**
     * 
     * @param s if true, then show
     */
    public void showLocalVariables(boolean s) {
        showLocalVars = s;
    }

    /**
     * @return true means show local variables
     */
    public boolean showLocalVariables() {
        return showLocalVars;
    }

    /**
     * 
     * @param f
     */
    public void setOutputFormat(OutputFormat f) {
        this.format = f;
    }

    /**
     * 
     * @return
     */
    public boolean showAllState() {
        return showAllState;
    }
    
    public void showAllState(boolean b) {
        this.showAllState = b;
    }

    /**
     * 
     * @return
     */
    public OutputFormat getOutputFormat() {
        return this.format;
    }

}


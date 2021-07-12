package kaiju.tools.ghihorn.answer.format;

import java.util.Map;

public class GhiHornDisplaySettings {

    private boolean showGlobalVars, showAllStateVars, showDecompilerVars;

    public static enum VarSettings {
        ShowGlobalVars {
            @Override
            public String toString() {
                return "Show global variables";
            }
        },

        ShowStateVars {
            @Override
            public String toString() {
                return "Show all state variables";
            }
        },

        ShowDecompilerVars {
            @Override
            public String toString() {
                return "Show decompiler variables";
            }
        }
    }

    public GhiHornDisplaySettings() {
        showGlobalVars = true;
        showAllStateVars = false;
        showDecompilerVars = true;
    }

    public GhiHornDisplaySettings(Map<VarSettings, Boolean> s) {
        showGlobalVars = s.getOrDefault(VarSettings.ShowGlobalVars, true);
        showAllStateVars = s.getOrDefault(VarSettings.ShowStateVars, false);
        showDecompilerVars = s.getOrDefault(VarSettings.ShowDecompilerVars, true);
    }

    /**
     * @return the showGlobalVars
     */
    public boolean showGlobalVariables() {
        return showGlobalVars;
    }

    /**
     * @return the showStateVars
     */
    public boolean showAllStateVariables() {
        return showAllStateVars;
    }

    /**
     * @return the showDecompilerVars
     */
    public boolean onlyShowDecompilerVariables() {
        return showDecompilerVars;
    }
}

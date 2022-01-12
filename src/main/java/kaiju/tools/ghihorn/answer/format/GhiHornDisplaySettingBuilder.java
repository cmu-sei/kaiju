package kaiju.tools.ghihorn.answer.format;

import kaiju.tools.ghihorn.answer.format.GhiHornDisplaySettings.OutputFormat;

public class GhiHornDisplaySettingBuilder {
    private boolean showGlobalVars, showLocalVars, showAllState, hideTempVars, hideExternalFuncs;
    private OutputFormat format;

    public GhiHornDisplaySettingBuilder() {
        showAllState = false;
        showGlobalVars = false;
        showLocalVars = false;
        hideTempVars = true;
        format = OutputFormat.TEXT;
    }

    public GhiHornDisplaySettingBuilder showGlobalVariables(boolean b) {
        this.showGlobalVars = b;
        return this;
    }

    public GhiHornDisplaySettingBuilder showLocalVariables(boolean b) {
        this.showLocalVars = b;
        return this;
    }

    public GhiHornDisplaySettingBuilder hideExternalFuncs(boolean b) {
        this.hideExternalFuncs = b;
        return this;
    }

    public GhiHornDisplaySettingBuilder hideTempVariables(boolean b) {
        this.hideTempVars = b;
        return this;
    }

    public GhiHornDisplaySettingBuilder showAllState(boolean b) {
        this.showAllState = b;
        return this;
    }

    public GhiHornDisplaySettingBuilder generateJson() {
        this.format = OutputFormat.JSON;
        return this;
    }

    public GhiHornDisplaySettingBuilder generateText() {
        this.format = OutputFormat.TEXT;
        return this;
    }

    public GhiHornDisplaySettings build() {

        GhiHornDisplaySettings settings = new GhiHornDisplaySettings();
        settings.showGlobalVariables(showGlobalVars);
        settings.hideExternalFuncs(hideExternalFuncs);
        settings.hideTempVariables(hideTempVars);
        settings.showAllState(showAllState);
        settings.showLocalVariables(showLocalVars);
        settings.setOutputFormat(format);

        return settings;
    }
}



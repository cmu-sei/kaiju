package kaiju.ghihorn;

import java.beans.PropertyChangeEvent;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import ghidra.util.Msg;
import kaiju.tools.ghihorn.cmd.GhiHornCommandListener;
import kaiju.tools.ghihorn.hornifer.GhiHornCommandEvent;
import kaiju.tools.ghihorn.hornifer.horn.GhiHornAnswer;

class GhiHornEventListener implements GhiHornCommandListener {

    private Map<GhiHornCommandEvent, String> eventConfig = new HashMap<>();
    private boolean isDone = false;
    private List<GhiHornAnswer> resultList = new ArrayList<>();;

    public boolean isDone() {
        return isDone;
    }

    public List<GhiHornAnswer> getAnswer() {
        return this.resultList;
    }

    /**
     * Receive events from the ApiAnalyzer command, either log or output
     */
    @Override
    public void propertyChange(PropertyChangeEvent evt) {

        final String propName = evt.getPropertyName();

        if (propName.equalsIgnoreCase(eventConfig.get(GhiHornCommandEvent.StatusMessage))) {

            String status = (String) evt.getNewValue();
            Msg.info(this, status);

        } else if (propName.equalsIgnoreCase(eventConfig.get(GhiHornCommandEvent.ResultReady))) {

            GhiHornAnswer result = (GhiHornAnswer) evt.getNewValue();

            resultList.add(result);

        } else if ((propName.equalsIgnoreCase(eventConfig.get(GhiHornCommandEvent.Completed))) ||
                (propName.equalsIgnoreCase(eventConfig.get(GhiHornCommandEvent.Cancelled)))) {
            isDone = true;
        }
    }

    @Override
    public Map<GhiHornCommandEvent, String> getCommandEvents() {
        return this.eventConfig;
    }

    @Override
    public void registerCommandEvent(String id, GhiHornCommandEvent evt) {
        this.eventConfig.put(evt, id);
    }
}

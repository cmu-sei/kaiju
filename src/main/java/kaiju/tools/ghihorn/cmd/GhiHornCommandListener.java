package kaiju.tools.ghihorn.cmd;

import java.beans.PropertyChangeListener;
import java.util.Map;
import kaiju.tools.ghihorn.hornifer.GhiHornCommandEvent;

public interface GhiHornCommandListener extends PropertyChangeListener {
    public Map<GhiHornCommandEvent, String> getCommandEvents();   
    public void registerCommandEvent(final String id, final GhiHornCommandEvent evt);
        
}

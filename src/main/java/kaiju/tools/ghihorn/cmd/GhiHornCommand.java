package kaiju.tools.ghihorn.cmd;

import java.beans.PropertyChangeSupport;
import java.util.Map;
import com.google.common.base.VerifyException;
import com.microsoft.z3.Z3Exception;
import ghidra.framework.cmd.BackgroundCommand;
import ghidra.framework.model.DomainObject;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.CancelledListener;
import ghidra.util.task.TaskMonitor;
import kaiju.tools.ghihorn.exception.GhiHornException;
import kaiju.tools.ghihorn.hornifer.GhiHornCommandEvent;
import kaiju.tools.ghihorn.hornifer.GhiHornifier;
import kaiju.tools.ghihorn.hornifer.horn.GhiHornAnswer;

public class GhiHornCommand extends BackgroundCommand implements CancelledListener {

    private GhiHornifier hornifier;
    private PropertyChangeSupport pcs;
    private String statusUpdatePropertyID;
    private String completePropertyID;
    private String cancelPropertyID;
    private String resultPropertyID;

    /**
     * 
     * @param plugin
     */
    public GhiHornCommand(String name, GhiHornifier h) {

        super(name, true, true, false);

        this.hornifier = h;
    }

    /**
     * Connect the signal changes to the command
     * 
     * @param listener
     * @param eventConfig
     */
    public void addCommandListener(final GhiHornCommandListener listener) {

        Map<GhiHornCommandEvent, String> eventConfig = listener.getCommandEvents();
        
        this.pcs = new PropertyChangeSupport(this);

        this.statusUpdatePropertyID = eventConfig.get(GhiHornCommandEvent.StatusMessage);
        this.pcs.addPropertyChangeListener(statusUpdatePropertyID, listener);

        this.completePropertyID = eventConfig.get(GhiHornCommandEvent.Completed);
        this.pcs.addPropertyChangeListener(completePropertyID, listener);
       
        this.cancelPropertyID = eventConfig.get(GhiHornCommandEvent.Cancelled);
        this.pcs.addPropertyChangeListener(cancelPropertyID, listener);

        this.resultPropertyID = eventConfig.get(GhiHornCommandEvent.ResultReady);
        this.pcs.addPropertyChangeListener(resultPropertyID, listener);
    }

    

    @Override
    public void taskCompleted() {
        if (pcs != null) {
            pcs.firePropertyChange(completePropertyID, null, this);
        }
    }

    @Override
    public void cancelled() {

        if (pcs != null) {
            pcs.firePropertyChange(cancelPropertyID, null, this);

        }
        hornifier.cancel();
    }

    public void updateResults(final GhiHornAnswer result) {
        synchronized (pcs) {
            if (pcs != null && result != null) {
                pcs.firePropertyChange(resultPropertyID, null, result);
            }
        }
    }

    public void sendStatusMsg(String message) {
        synchronized (pcs) {
            if (pcs != null) {
                pcs.firePropertyChange(statusUpdatePropertyID, null, message);
            }
        }
    }

    @Override
    protected void setStatusMsg(final String message) {
        super.setStatusMsg(message);
        sendStatusMsg(message);
        
    }

    /**
     * Execute this command
     */
    @Override
    public boolean applyTo(final DomainObject obj, final TaskMonitor monitor) {

        final Program program = (Program) obj;
        if (program == null) {
            setStatusMsg("Invalid program");
            return false;
        }

        try {

            this.hornifier.setCommand(this);

            // The analysis information must be generated for the entire CFG
            // ahead of time to accumulate the required variables

            if (!hornifier.verifyConfiguration()) {
                setStatusMsg("Invalid configurtion");
                return false;
            }

            monitor.addCancelledListener(this);

            hornifier.evaluate(hornifier.hornify(program, monitor), monitor);

        } catch (Z3Exception z3x) {
            z3x.printStackTrace();
            setStatusMsg("Error during Z3 encoding " + z3x);
            return false;
        } catch (CancelledException cx) {
            setStatusMsg("Cancelled: " + cx.getMessage());
            return false;
        } catch (VerifyException | GhiHornException gve) {
            setStatusMsg("Could not complete analysis: " + gve.getMessage());

            // These are command-specific failures are not worth displaying a dialog, so return true
        } catch (Exception e) {
            e.printStackTrace();
            setStatusMsg("Error: " + e.getMessage());
            return false;
        }
        
        return true;
    }

    public boolean isCancelled() {
        return hornifier.isCancelled();
    }

    /* (non-Javadoc)
     * @see java.lang.Object#hashCode()
     */
    
    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((cancelPropertyID == null) ? 0 : cancelPropertyID.hashCode());
        result = prime * result
                + ((completePropertyID == null) ? 0 : completePropertyID.hashCode());
      
        result = prime * result + ((hornifier == null) ? 0 : hornifier.hashCode());
        result = prime * result + ((pcs == null) ? 0 : pcs.hashCode());
        result = prime * result + ((resultPropertyID == null) ? 0 : resultPropertyID.hashCode());
        result = prime * result
                + ((statusUpdatePropertyID == null) ? 0 : statusUpdatePropertyID.hashCode());
        return result;
    }

    /* (non-Javadoc)
     * @see java.lang.Object#equals(java.lang.Object)
     */
    
    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (!(obj instanceof GhiHornCommand))
            return false;
        GhiHornCommand other = (GhiHornCommand) obj;
        if (cancelPropertyID == null) {
            if (other.cancelPropertyID != null)
                return false;
        } else if (!cancelPropertyID.equals(other.cancelPropertyID))
            return false;
        if (completePropertyID == null) {
            if (other.completePropertyID != null)
                return false;
        } else if (!completePropertyID.equals(other.completePropertyID))
            return false;
        if (hornifier == null) {
            if (other.hornifier != null)
                return false;
        } else if (!hornifier.equals(other.hornifier))
            return false;
        if (pcs == null) {
            if (other.pcs != null)
                return false;
        } else if (!pcs.equals(other.pcs))
            return false;
        if (resultPropertyID == null) {
            if (other.resultPropertyID != null)
                return false;
        } else if (!resultPropertyID.equals(other.resultPropertyID))
            return false;
        if (statusUpdatePropertyID == null) {
            if (other.statusUpdatePropertyID != null)
                return false;
        } else if (!statusUpdatePropertyID.equals(other.statusUpdatePropertyID))
            return false;
        return true;
    }

    


}

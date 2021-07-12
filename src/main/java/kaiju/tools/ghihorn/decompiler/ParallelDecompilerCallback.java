package kaiju.tools.ghihorn.decompiler;

import generic.cache.CachingPool;
import generic.concurrent.QCallback;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.pcode.HighFunction;
import ghidra.util.Msg;
import ghidra.util.task.TaskMonitor;

/**
 * Callback to handle parallel decompilation and generation of high functions
 */
public class ParallelDecompilerCallback
        implements QCallback<Function, HighFunction> {

    private CachingPool<DecompInterface> pool;

    /**
     * 
     */
    public ParallelDecompilerCallback(CachingPool<DecompInterface> decompilerPool) {
        this.pool = decompilerPool;
    }

    /**
     * 
     */
    @Override
    public HighFunction process(Function function, TaskMonitor monitor)
            throws Exception {

        if (monitor.isCancelled()) {
            return null;
        }

        DecompInterface decompiler = pool.get();
        try {
            return doWork(function, decompiler, monitor);
        } finally {
            pool.release(decompiler);
        }
    }
    
    /**
     * 
     * @param function
     * @param decompiler
     * @param monitor
     * @return
     */
    private HighFunction doWork(Function function,
            DecompInterface decompiler, TaskMonitor monitor) {

        Address entryPoint = function.getEntryPoint();
        CodeUnit codeUnitAt = function.getProgram().getListing().getCodeUnitAt(entryPoint);

        if (!(codeUnitAt instanceof Instruction)) {
            return null;
        }

        monitor.setMessage("Decompiling " + function.getName());

        final DecompileResults dr = decompiler.decompileFunction(function,
                decompiler.getOptions().getDefaultTimeout(), monitor);

        String errorMessage = dr.getErrorMessage();
        if (!"".equals(errorMessage)) {
            Msg.warn(ParallelDecompilerCallback.this, "Error decompiling: " + errorMessage);
            monitor.incrementProgress(1);
            return null;
        }

        return dr.getHighFunction();
    }
}

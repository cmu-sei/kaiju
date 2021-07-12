package kaiju.tools.ghihorn.hornifer.horn;

import java.util.Map;
import java.util.Set;

import kaiju.tools.ghihorn.hornifer.horn.variable.HornVariable;

public class LiveHornVariables<T> {

    public final Map<T, Set<HornVariable>> liveIn;
    public final Map<T, Set<HornVariable>> liveOut;

    public LiveHornVariables(Map<T, Set<HornVariable>> in, Map<T, Set<HornVariable>> out) {
        liveIn = in;
        liveOut = out;
    }
}

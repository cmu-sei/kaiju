package kaiju.tools.ghihorn.cfg;

import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.ListIterator;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Queue;
import java.util.Set;
import java.util.TreeSet;
import java.util.function.Predicate;
import java.util.stream.Collectors;
import java.util.stream.StreamSupport;

import ghidra.graph.GDirectedGraph;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.PcodeBlockBasic;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.VarnodeAST;
import ghidra.util.Msg;
import ghidra.util.datastruct.Accumulator;

public class HighCfg<L, E> implements GDirectedGraph<HighCfgVertex<L, E>, HighCfgEdge<L, E>> {
    private L entryPoint;
    private Set<L> exitPoints;
    private Set<HighCfgVertex<L, E>> vertices;
    private Set<HighCfgEdge<L, E>> edges;
    private Map<L, HighCfgVertex<L, E>> locatorToVertexMap;

    private HighCfg() {
        this.entryPoint = null;
        this.exitPoints = new HashSet<>();
        this.vertices = new HashSet<>();
        this.edges = new HashSet<>();
        this.locatorToVertexMap = new HashMap<>();
    }

    public L getEntryLocation() {
        return this.entryPoint;
    }

    public Set<L> getExitLocations() {
        return this.exitPoints;
    }

    public void addExitLocation(L x) {
        this.exitPoints.add(x);
    }

    public void setEntryLocation(L e) {
        this.entryPoint = e;
    }

    /**
     * Collect vertices according to a predicate.
     * 
     * @param predicate   the test to apply
     * @param accumulator accumulator for found vertices
     */
    public void collectVertices(Predicate<HighCfgVertex<L, E>> predicate,
            Accumulator<HighCfgVertex<L, E>> accumulator) {

        for (var v : this.vertices) {
            if (predicate.test(v)) {
                accumulator.add(v);
            }
        }
    }

    @Override
    public boolean addVertex(HighCfgVertex<L, E> v) {
        locatorToVertexMap.putIfAbsent(v.getLocator(), v);
        return this.vertices.add(v);
    }

    @Override
    public boolean removeVertex(HighCfgVertex<L, E> v) {
        locatorToVertexMap.remove(v.getLocator());
        return this.vertices.remove(v);
    }

    @Override
    public void removeVertices(Iterable<HighCfgVertex<L, E>> vi) {
        StreamSupport.stream(vi.spliterator(), false).forEach(vtx -> locatorToVertexMap.remove(vtx.getLocator()));
        this.vertices.removeAll(StreamSupport.stream(vi.spliterator(), false).collect(Collectors.toList()));
    }

    @Override
    public void addEdge(HighCfgEdge<L, E> e) {
        edges.add(e);
    }

    @Override
    public boolean removeEdge(HighCfgEdge<L, E> e) {
        return this.edges.remove(e);
    }

    @Override
    public void removeEdges(Iterable<HighCfgEdge<L, E>> ei) {
        this.edges.removeAll(StreamSupport.stream(ei.spliterator(), false).collect(Collectors.toList()));

    }

    @Override
    public HighCfgEdge<L, E> findEdge(HighCfgVertex<L, E> start, HighCfgVertex<L, E> end) {

        Iterator<HighCfgEdge<L, E>> it = this.edges.iterator();
        while (it.hasNext()) {
            HighCfgEdge<L, E> e = it.next();
            if (e.getEnd() == end && e.getStart() == start) {
                return e;
            }
        }
        return null;
    }

    @Override
    public Collection<HighCfgVertex<L, E>> getVertices() {
        return this.vertices;
    }

    @Override
    public Collection<HighCfgEdge<L, E>> getEdges() {
        return this.edges;
    }

    @Override
    public boolean containsVertex(HighCfgVertex<L, E> v) {
        return this.vertices.contains(v);
    }

    @Override
    public boolean containsEdge(HighCfgEdge<L, E> e) {
        return this.edges.contains(e);
    }

    @Override
    public boolean containsEdge(HighCfgVertex<L, E> from, HighCfgVertex<L, E> to) {
        return (findEdge(from, to) != null);
    }

    @Override
    public boolean isEmpty() {
        return this.vertices.isEmpty();
    }

    @Override
    public int getVertexCount() {
        return this.vertices.size();
    }

    @Override
    public int getEdgeCount() {
        return this.edges.size();
    }

    @Override
    public Collection<HighCfgEdge<L, E>> getInEdges(HighCfgVertex<L, E> v) {

        ArrayList<HighCfgEdge<L, E>> inEdges = new ArrayList<>();
        this.edges.forEach(e -> {
            if (e.getEnd() == v) {
                inEdges.add(e);
            }
        });
        return inEdges;
    }

    @Override
    public Collection<HighCfgEdge<L, E>> getOutEdges(HighCfgVertex<L, E> v) {
        ArrayList<HighCfgEdge<L, E>> outEdges = new ArrayList<>();
        this.edges.forEach(e -> {
            if (e.getStart() == v) {
                outEdges.add(e);
            }
        });
        return outEdges;
    }

    @Override
    public GDirectedGraph<HighCfgVertex<L, E>, HighCfgEdge<L, E>> copy() {
        HighCfg<L, E> n = new HighCfg<>();
        n.entryPoint = this.entryPoint;
        n.vertices = new HashSet<>(this.vertices);
        n.edges = new HashSet<>(this.edges);
        n.locatorToVertexMap = new HashMap<>(this.locatorToVertexMap);

        return n;
    }

    public HighCfg<L, E> emptyCopy() {
        return new HighCfg<>();
    }

    public HighCfgVertex<L, E> locateVertex(L l) {
        return locatorToVertexMap.getOrDefault(l, null);
    }

    /**
     * Over-ridden to string
     */
    public String toString() {

        StringBuilder buf = new StringBuilder();
        buf.append("Entry: ").append(entryPoint).append("\n");
        if (!exitPoints.isEmpty()) {
            buf.append("Exit(s): ");
            this.exitPoints.forEach(xp -> buf.append(xp.toString()).append(" "));
            buf.append("\n");
        }
        buf.append("Vertices:\n");
        if (!this.vertices.isEmpty()) {
            this.vertices.forEach(vertex -> buf.append(vertex.toString()).append("\n"));
        } else {
            buf.append("None\n");
        }

        buf.append("\nEdges:\n");
        if (!this.edges.isEmpty()) {
            this.edges.forEach(edge -> buf.append(edge.toString()).append("\n"));
        } else {
            buf.append("None\n");
        }

        return buf.toString();
    }

    public HighCfgVertex<L, E> getVertexByLocator(final L locator) {
        return locatorToVertexMap.get(locator);
    }

    public HighCfgVertex<L, E> getEntryVertex() {
        return locatorToVertexMap.get(this.entryPoint);
    }

    public Set<HighCfgVertex<L, E>> getExitVertices() {
        return this.vertices.stream().filter(v -> this.exitPoints.contains(v.getLocator())).collect(Collectors.toSet());
    }

    /**
     * Fetch a list of pcode operators in basic block order
     * 
     * @param bb the basic block
     * @return a list of pcode in basic block order
     */
    private static List<PcodeOp> getPcodeInBBOrder(final PcodeBlockBasic bb) {

        TreeSet<PcodeOp> pcodeSet = new TreeSet<>((pc1, pc2) -> {
            int o1 = pc1.getSeqnum().getOrder();
            int o2 = pc2.getSeqnum().getOrder();
            if (o1 < o2) {
                return -1;
            } else if (o2 < o1) {
                return 1;
            }

            // equal should not happen, but you never know
            return 0;
        });
        bb.getIterator().forEachRemaining(pcodeSet::add);

        return new ArrayList<>(pcodeSet);
    }

    /**
     * The CFG builder. The CFG is constructed in a way that splits basic blocks
     * when a call is made, which ghidra does not do by default. The resulting CFG
     * is based on the addresses used in the high function p-code, which may not
     * correspond to actuall basic block addresses, but should suffice for CHC
     * encoding
     * 
     * @param highFunction
     * @param nextAddrMap
     * @return
     */
    public static HighCfg<Address, VertexAttributes> build(final HighFunction highFunction) {

        if (highFunction == null) {
            return null;
        }

        final Address funcEntryPoint = highFunction.getFunction().getEntryPoint();
        final List<PcodeBlockBasic> blocks = highFunction.getBasicBlocks();
        HighCfg<Address, VertexAttributes> cfg = new HighCfg<>();

        // by default the entry location is unknown
        cfg.setEntryLocation(Address.NO_ADDRESS);

        // straight forward approach here - add the vertices, then for each vertex add
        // the edges. Should run in O(V+E) time
        HashMap<PcodeBlockBasic, List<HighCfgVertex<Address, VertexAttributes>>> bbToVtxMap = new HashMap<>();

        for (int i = 0; i < blocks.size(); i++) {

            final List<HighCfgVertex<Address, VertexAttributes>> vertices = new ArrayList<>();
            final PcodeBlockBasic bb = blocks.get(i);

            if (bb.contains(funcEntryPoint)) {
                cfg.setEntryLocation(bb.getStart());
            }

            // Ensure the p-code is in basicblock order
            final List<PcodeOp> bbPcodeList = getPcodeInBBOrder(bb);
            if (bbPcodeList.isEmpty()) {
                Msg.warn(null, "Basic block: " + bb.getStart() + " has no p-code");
            }

            // Create the list of pcodes in a list and split out the calls as
            // separate blocks

            // Scan for calls in the basic block p-code
            Queue<Integer> splitIndicesQueue = new LinkedList<>();

            for (int j = 0; j < bbPcodeList.size(); j++) {
                PcodeOp pcode = bbPcodeList.get(j);

                // Ghidra does not split block that are terminated by
                // unconditional jumps. This causes numerous problems
                if (pcode.getOpcode() == PcodeOp.CALL) {
                    splitIndicesQueue.add(j);
                }
            }

            Integer blockStartIndex = 0;
            Integer blockStopIndex = bbPcodeList.size() - 1;

            Address blockStartAddress = bb.getStart();
            Address blockStopAddress = bb.getStop();

            // There is at least one call so we will split
            while (!splitIndicesQueue.isEmpty()) {

                blockStopIndex = splitIndicesQueue.poll();
                blockStopAddress = bbPcodeList.get(blockStopIndex).getSeqnum().getTarget();

                AddressSet blockSet = null;
                try {
                    blockSet = new AddressSet(blockStartAddress, blockStopAddress);
                } catch (IllegalArgumentException iae) {

                    // If the start > end then this will be an invalid set. This
                    // happens when you have blocks that start with JMP
                    // (chunked functions). It is really annoying.

                    Address pcStartAddr = bbPcodeList.get(blockStartIndex).getSeqnum().getTarget();
                    Address pcStopAddr = bbPcodeList.get(blockStopIndex).getSeqnum().getTarget();

                    Msg.warn(null, "The start/stop addresses (" + blockStartAddress + ":" + blockStopAddress
                            + ") are invalid. Defaulting to p-code addresses (" + pcStartAddr + ":" + pcStopAddr
                            + "), which may not reflect physical addresses. This is probably because start > end in a split block");

                    blockSet = new AddressSet(pcStartAddr, pcStopAddr);
                }

                // Subblock #1 is the start to the call address (includsive)
                final HighCfgVertex<Address, VertexAttributes> vtx = new HighCfgVertex<>(blockStartAddress,
                        new VertexAttributes(blockSet, bbPcodeList.subList(blockStartIndex, blockStopIndex + 1)));

                vertices.add(vtx);
                cfg.addVertex(vtx);

                // Find the address of the instruction after the call.
                // Assume it is the end of the block
                Instruction nextInsn = highFunction.getFunction().getProgram().getListing()
                        .getInstructionAfter(blockStopAddress);

                // assume the previous block is the only block
                blockStartAddress = bb.getStop();
                if (nextInsn != null) {
                    Address nextInsnAddr = nextInsn.getAddress();
                    // the next instruction is in this block?
                    if (bb.contains(nextInsnAddr)) {
                        // The start address is the address of the next
                        // instruction in this block
                        blockStartAddress = nextInsn.getAddress();
                    }
                }

                blockStartIndex = blockStopIndex + 1; // right after the call
                blockStopIndex = bbPcodeList.size() - 1;
                blockStopAddress = bb.getStop();
            }

            // Add the fiinal block or the only block
            final HighCfgVertex<Address, VertexAttributes> newVtx = new HighCfgVertex<>(blockStartAddress,
                    new VertexAttributes(new AddressSet(blockStartAddress, blockStopAddress),
                            bbPcodeList.subList(blockStartIndex, blockStopIndex + 1)));

            vertices.add(newVtx);
            cfg.addVertex(newVtx);

            // add the edges in between the split blocks
            for (int v = 1; v < vertices.size(); v++) {

                HighCfgVertex<Address, VertexAttributes> vStart = vertices.get(v - 1);
                HighCfgVertex<Address, VertexAttributes> vEnd = vertices.get(v);
                HighCfgEdge<Address, VertexAttributes> edge = new HighCfgEdge<>(vStart, vEnd);

                if (!cfg.containsEdge(edge)) {
                    cfg.addEdge(edge);
                }
            }

            bbToVtxMap.put(bb, vertices);
        }

        // TODO: add edges to split vertices

        // All the calls have been expanded intra-basic block. Now the
        // basic blocks need to be put together. Interestingly, because the
        // p-code addresses do not line up with basic block aaddresses this CFG
        // will be a bit different then the original

        for (Entry<PcodeBlockBasic, List<HighCfgVertex<Address, VertexAttributes>>> entry : bbToVtxMap.entrySet()) {

            PcodeBlockBasic bb = entry.getKey();
            List<HighCfgVertex<Address, VertexAttributes>> vertices = entry.getValue();

            // fetch the out blocks for this vertex to connect edges
            HighCfgVertex<Address, VertexAttributes> lastBBVtx = vertices.get(vertices.size() - 1);

            for (int i = 0; i < bb.getOutSize(); i++) {

                PcodeBlockBasic nextBB = (PcodeBlockBasic) bb.getOut(i);
                List<HighCfgVertex<Address, VertexAttributes>> nextBBVertices = bbToVtxMap.getOrDefault(nextBB, null);
                if (nextBBVertices != null && !nextBBVertices.isEmpty()) {
                    // Fetch the first vertex of the next block
                    HighCfgVertex<Address, VertexAttributes> nextBBVtx = nextBBVertices.get(0);
                    // connect last to first
                    HighCfgEdge<Address, VertexAttributes> outEdge = new HighCfgEdge<>(lastBBVtx, nextBBVtx);

                    if (!cfg.containsEdge(outEdge)) {
                        cfg.addEdge(outEdge);
                    }
                }
            }

            // fetch the in blocks for the first vertex to connect edges
            HighCfgVertex<Address, VertexAttributes> firstBBVtx = vertices.get(0);
            for (int i = 0; i < bb.getInSize(); i++) {
                PcodeBlockBasic prevBB = (PcodeBlockBasic) bb.getIn(i);
                List<HighCfgVertex<Address, VertexAttributes>> prevBBVertices = bbToVtxMap.getOrDefault(prevBB, null);
                if (prevBBVertices != null && !prevBBVertices.isEmpty()) {

                    // Fetch the last vertex of the previous block
                    HighCfgVertex<Address, VertexAttributes> prevBBVtx = prevBBVertices.get(prevBBVertices.size() - 1);

                    // connect the last vertex of the previous block to the
                    // first vertex of this block
                    HighCfgEdge<Address, VertexAttributes> inEdge = new HighCfgEdge<>(prevBBVtx, firstBBVtx);

                    if (!cfg.containsEdge(inEdge)) {
                        cfg.addEdge(inEdge);
                    }
                }
            }
        }

        // The graph is now constructed.

        for (var vertex : cfg.getVertices()) {
            VertexAttributes attr = vertex.getEntity();
            if (attr.endsInReturn()) {

                // the CFG is keyed by the basic blocks. In the case of
                // a RETURN pcode, the block entry address is the exit
                cfg.addExitLocation(attr.getMinAddress());
            }
        }

        // The final step is to set the guards on the newly created edges. This
        // will be based on whether

        Collection<HighCfgEdge<Address, VertexAttributes>> edges = cfg.getEdges();
        for (var edge : edges) {

            // the source always controls the edge
            VertexAttributes info = edge.getStart().getEntity();

            List<PcodeOp> opList = info.getPcode();
            PcodeBlockBasic sourceBB = edge.getStart().getEntity().getPcodeBlockBasic();
            PcodeBlockBasic targetBB = edge.getEnd().getEntity().getPcodeBlockBasic();

            HighCfgEdgeGuard guard = HighCfgEdgeGuard.mkUnguardedEdge();

            if (!opList.isEmpty() && !sourceBB.equals(targetBB)) {

                ListIterator<PcodeOp> li = opList.listIterator(opList.size());

                // These are the two elements of the edge condition. What is the
                // condition (guard) on the edge, and how should it be evaluated
                // (taken when guard true or false?).
                //
                // Assume that the edge is unguarded by default

                PcodeOp conditionTestOp = null;
                do {
                    final PcodeOp op = li.previous();

                    // According to Ghidra's documentation CBRANCH pcode is "if (input1) goto
                    // input0", thus input1 is the condition

                    if (op.getOpcode() == PcodeOp.CBRANCH) {
                        VarnodeAST condVn = (VarnodeAST) op.getInput(1);
                        conditionTestOp = condVn.getDef();
                        break;
                    }
                } while (li.hasPrevious());

                if (conditionTestOp != null) {
                    final PcodeBlockBasic trueOut = (PcodeBlockBasic) sourceBB.getTrueOut();
                    final PcodeBlockBasic falseOut = (PcodeBlockBasic) sourceBB.getFalseOut();

                    if (trueOut.equals(targetBB)) {
                        guard = HighCfgEdgeGuard.mkGuardedEdge(true, conditionTestOp);
                    } else if (falseOut.equals(targetBB)) {
                        guard = HighCfgEdgeGuard.mkGuardedEdge(false, conditionTestOp);
                    } else {
                        Msg.error(HighCfg.class, "Cannot evaluate guard on edge: " + edge);
                    }
                } 
            }
            edge.setGuard(guard);
        }

        return cfg;
    }

    // Taken from soot for better or worse
    public List<HighCfgVertex<L, E>> successorListOf(HighCfgVertex<L, E> vertex) {
        List<HighCfgVertex<L, E>> successors = new ArrayList<>();

        for (var e : getOutEdges(vertex)) {
            var oppo = getOppositeVertex(e, vertex);
            if (oppo != null) {
                successors.add(oppo);
            }
        }

        return successors;
    }

    private HighCfgVertex<L, E> getOppositeVertex(HighCfgEdge<L, E> e, HighCfgVertex<L, E> vertex) {
        HighCfgVertex<L, E> source = e.getStart();
        HighCfgVertex<L, E> target = e.getEnd();
        if (vertex.equals(source)) {
            return target;
        } else if (vertex.equals(target)) {
            return source;
        }
        return null;
    }

    // Depends only on entry point of this CFG, which is unique number
    @Override
    public int hashCode() {
        return entryPoint.hashCode();
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null) {
            return false;
        }
        if (getClass() != obj.getClass()) {
            return false;
        }

        @SuppressWarnings("unchecked")
        HighCfg<L, E> other = (HighCfg<L, E>) obj;
        if (entryPoint != other.entryPoint) {
            return false;
        }

        return true;
    }
}

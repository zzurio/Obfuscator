package club.cpacket.obfuscator.flow;

import org.objectweb.asm.tree.analysis.Frame;
import org.objectweb.asm.tree.analysis.Value;

import java.util.HashSet;
import java.util.Set;

public class Node<V extends Value> extends Frame<V> {

    public Set<Node<V>> successors = new HashSet<Node<V>>();

    public Node(int numLocals, int nStack) {
        super(numLocals, nStack);
    }

    public Node(Frame<? extends V> src) {
        super(src);
    }
}
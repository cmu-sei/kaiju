package kaiju.tools.ghihorn.hornifer.block;

/**
 * Properties are a way to add infomration to a block. This is preferred to harder typing
 * implementations because blocks can have mulitple properties at once, such as being an entry and
 * being a call block simultaneously
 */
public interface HornBlockProperty {
    public enum Property {
        Entry, Return, Call;
    }

    public Property getProperty();
}

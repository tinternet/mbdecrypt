package mbdecrypt;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.dataformat.xml.XmlMapper;

final class Xml {
    private Xml() {}

    /** Parses xml elements without a root element. */
    static <T> T parse(String xml, Class<T> type) throws JsonProcessingException {
        return new XmlMapper().readValue("<config>" + xml + "</config>", type);
    }
}

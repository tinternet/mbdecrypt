package mbdecrypt;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.dataformat.xml.annotation.JacksonXmlElementWrapper;
import com.fasterxml.jackson.dataformat.xml.annotation.JacksonXmlProperty;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * The named decryptors of the connection, from its {@code decrypt-decryptors}
 */
public final class Decryptors {
    /**
     * A {@code <decryptor>} element
     *
     * @param name      letters and digits, case-insensitive
     * @param algorithm see {@link Algorithms#create}
     * @param key       the encryption key in hex
     * @param iv        a fixed IV (or GCM nonce) in hex, optional
     * @param padding   {@code pkcs7} (the default), {@code spaces} or {@code zeros}
     */
    record Element(String name, String algorithm, String key, String iv, String padding) {
    }

    record Elements(
            @JacksonXmlElementWrapper(useWrapping = false) @JacksonXmlProperty(localName = "decryptor") List<Element> decryptors) {
    }

    private final Map<String, Decryptor> decryptors;

    private Decryptors(Map<String, Decryptor> decryptors) {
        this.decryptors = decryptors;
    }

    public static Decryptors parse(String xml) throws IllegalArgumentException {
        List<Element> elements = null;

        if (xml != null && !xml.isBlank()) {
            try {
                elements = Xml.parse(xml, Elements.class).decryptors();
            } catch (JsonProcessingException e) {
                throw new IllegalArgumentException("Decryptors in the connection settings aren't valid XML (line %d)"
                        .formatted(e.getLocation().getLineNr()));
            }
        }

        if (elements == null || elements.isEmpty()) {
            throw new IllegalArgumentException("no decryptors are configured; add them to the connection settings, "
                    + "under Decryptors, as <decryptor name=\"…\" algorithm=\"…\" key=\"<hex>\"/>");
        }

        Map<String, Decryptor> decryptors = new LinkedHashMap<>();
        for (int i = 0; i < elements.size(); i++) {
            Element element = elements.get(i);
            String name = element == null || element.name() == null ? "" : element.name().toLowerCase(Locale.ROOT);

            if (!name.matches("[a-z0-9]+")) {
                throw new IllegalArgumentException("decryptor %d needs a name of letters and digits".formatted(i + 1));
            }
            if (element.algorithm() == null) {
                throw new IllegalArgumentException("decryptor '%s' needs an algorithm".formatted(name));
            }

            byte[] key = hex(element.key());
            byte[] iv = element.iv() == null ? null : hex(element.iv());
            if (key == null || (element.iv() != null && iv == null)) {
                throw new IllegalArgumentException(
                        "decryptor '%s' needs both the key and iv (if any) in hex".formatted(name));
            }

            try {
                if (decryptors.put(name, Algorithms.create(element.algorithm(), key, iv, element.padding())) != null) {
                    throw new IllegalArgumentException("it's configured twice");
                }
            } catch (IllegalArgumentException e) {
                throw new IllegalArgumentException("decryptor '%s': %s".formatted(name, e.getMessage()), e);
            }
        }

        return new Decryptors(decryptors);
    }

    /** Convert hex string to byte array or null if not a hex string */
    private static byte[] hex(String text) {
        if (text == null || text.isBlank())
            return null;
        try {
            return HexFormat.of().parseHex(text.strip());
        } catch (IllegalArgumentException e) {
            return null;
        }
    }

    Decryptor get(String name) throws IllegalArgumentException {
        Decryptor decryptor = decryptors.get(name.toLowerCase(Locale.ROOT));
        if (decryptor == null) {
            throw new IllegalArgumentException(
                    "no decryptor named '%s'; the decryptors are %s".formatted(name, decryptors.keySet()));
        }
        return decryptor;
    }
}

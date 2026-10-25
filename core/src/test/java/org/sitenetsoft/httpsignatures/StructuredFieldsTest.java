package org.sitenetsoft.httpsignatures;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Base64;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;
import org.sitenetsoft.httpsignatures.StructuredFields.InnerList;
import org.sitenetsoft.httpsignatures.StructuredFields.Item;

class StructuredFieldsTest {

    static final String SIG_INPUT = "sig1=(\"@method\" \"@authority\" \"@path\");created=1618884473;keyid=\"test-key-rsa-pss\"";

    @Test
    void parsesSignatureInputDictionary() {
        Map<String, Object> dict = StructuredFields.parseDictionary(SIG_INPUT);
        assertEquals(List.of("sig1"), List.copyOf(dict.keySet()));
        InnerList list = (InnerList) dict.get("sig1");
        assertEquals(List.of("@method", "@authority", "@path"), list.items().stream().map(i -> (String) i.value()).toList());
        assertEquals(1618884473L, list.params().get("created"));
        assertEquals("test-key-rsa-pss", list.params().get("keyid"));
        assertTrue(list.items().get(0).params().isEmpty());
    }

    @Test
    void parsesItemParameters() {
        Map<String, Object> dict = StructuredFields.parseDictionary("sig=(\"@query-param\";name=\"Pet\" \"content-digest\";bs);tag=\"x\";alg=\"ed25519\";expires=1618884800;nonce=\"b3k2pp5k7z-50gnwp.yemd\"");
        InnerList list = (InnerList) dict.get("sig");
        assertEquals("Pet", list.items().get(0).params().get("name"));
        assertEquals(Boolean.TRUE, list.items().get(1).params().get("bs"));
        assertEquals("x", list.params().get("tag"));
        assertEquals(1618884800L, list.params().get("expires"));
    }

    @Test
    void parsesByteSequenceDictionary() {
        byte[] bytes = "hello".getBytes();
        Map<String, Object> dict = StructuredFields.parseDictionary("sig1=:" + Base64.getEncoder().encodeToString(bytes) + ":");
        Item item = (Item) dict.get("sig1");
        assertArrayEquals(bytes, (byte[]) item.value());
    }

    @Test
    void parsesMultipleMembers() {
        Map<String, Object> dict = StructuredFields.parseDictionary("sha-256=:abc=:, sha-512=:def=:");
        assertEquals(2, dict.size());
        assertTrue(dict.containsKey("sha-512"));
    }

    @Test
    void serializesInnerListBackToSameText() {
        Map<String, Object> dict = StructuredFields.parseDictionary(SIG_INPUT);
        assertEquals(SIG_INPUT, StructuredFields.serializeDictionary(dict));
        InnerList list = (InnerList) dict.get("sig1");
        assertEquals("(\"@method\" \"@authority\" \"@path\");created=1618884473;keyid=\"test-key-rsa-pss\"",
                StructuredFields.serializeInnerList(list));
    }

    @Test
    void serializesByteSequencesStringsAndBooleans() {
        InnerList list = new InnerList(List.of(new Item("a\"b", Map.of()), new Item(Boolean.TRUE, Map.of()),
                new Item(new byte[] { 1, 2 }, Map.of())), Map.of());
        assertEquals("(\"a\\\"b\" ?1 :AQI=:)", StructuredFields.serializeInnerList(list));
    }

    @Test
    void rejectsUnterminatedString() {
        HttpSignatureException e = assertThrows(HttpSignatureException.class,
                () -> StructuredFields.parseDictionary("sig1=(\"@method"));
        assertEquals(HttpSignatureException.Reason.MALFORMED, e.reason());
    }

    @Test
    void rejectsGarbage() {
        assertThrows(HttpSignatureException.class, () -> StructuredFields.parseDictionary("=(=)"));
        assertThrows(HttpSignatureException.class, () -> StructuredFields.parseDictionary("sig1=:not base64!:"));
    }
}

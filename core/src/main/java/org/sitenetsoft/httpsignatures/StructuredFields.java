package org.sitenetsoft.httpsignatures;

import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * The subset of RFC 8941 Structured Fields that HTTP signatures need: dictionaries whose members are items or inner
 * lists, with string, integer, boolean, byte-sequence and token values, and parameters on both.
 */
public final class StructuredFields {

    private StructuredFields() {
    }

    /**
     * A bare token value (unquoted).
     */
    public record Token(String value) {
    }

    /**
     * An item: value is {@link String}, {@link Long}, {@link Boolean}, {@code byte[]} or {@link Token}.
     */
    public record Item(Object value, Map<String, Object> params) {
        public Item {
            params = params == null ? Map.of() : Map.copyOf(params);
        }
    }

    public record InnerList(List<Item> items, Map<String, Object> params) {
        public InnerList {
            items = List.copyOf(items);
            params = params == null ? Map.of() : new LinkedHashMap<>(params);
        }
    }

    public static Map<String, Object> parseDictionary(String input) {
        Parser p = new Parser(input);
        Map<String, Object> dict = new LinkedHashMap<>();
        p.skipSpaces();
        while (!p.atEnd()) {
            String key = p.key();
            Object value;
            if (p.peek() == '=') {
                p.next();
                value = p.peek() == '(' ? p.innerList() : p.item();
            } else {
                value = new Item(Boolean.TRUE, p.params());
            }
            dict.put(key, value);
            p.skipOws();
            if (p.atEnd()) {
                break;
            }
            p.expect(',');
            p.skipOws();
            if (p.atEnd()) {
                throw malformed("trailing comma");
            }
        }
        return dict;
    }

    public static String serializeDictionary(Map<String, Object> dict) {
        StringBuilder sb = new StringBuilder();
        for (Map.Entry<String, Object> e : dict.entrySet()) {
            if (sb.length() > 0) {
                sb.append(", ");
            }
            sb.append(e.getKey());
            if (e.getValue() instanceof InnerList l) {
                sb.append('=').append(serializeInnerList(l));
            } else if (e.getValue() instanceof Item i) {
                if (Boolean.TRUE.equals(i.value())) {
                    serializeParams(sb, i.params());
                } else {
                    sb.append('=');
                    serializeItem(sb, i);
                }
            } else {
                throw new IllegalArgumentException("dictionary member must be Item or InnerList");
            }
        }
        return sb.toString();
    }

    public static String serializeInnerList(InnerList list) {
        StringBuilder sb = new StringBuilder("(");
        boolean first = true;
        for (Item item : list.items()) {
            if (!first) {
                sb.append(' ');
            }
            first = false;
            serializeItem(sb, item);
        }
        sb.append(')');
        serializeParams(sb, list.params());
        return sb.toString();
    }

    public static String serializeItem(Item item) {
        StringBuilder sb = new StringBuilder();
        serializeItem(sb, item);
        return sb.toString();
    }

    private static void serializeItem(StringBuilder sb, Item item) {
        serializeBareItem(sb, item.value());
        serializeParams(sb, item.params());
    }

    private static void serializeBareItem(StringBuilder sb, Object value) {
        if (value instanceof String s) {
            sb.append('"');
            for (char c : s.toCharArray()) {
                if (c == '"' || c == '\\') {
                    sb.append('\\');
                }
                if (c < 0x20 || c > 0x7e) {
                    throw new IllegalArgumentException("sf-string cannot contain non-ASCII or control characters");
                }
                sb.append(c);
            }
            sb.append('"');
        } else if (value instanceof Long || value instanceof Integer) {
            sb.append(value);
        } else if (value instanceof Boolean b) {
            sb.append(b ? "?1" : "?0");
        } else if (value instanceof byte[] bytes) {
            sb.append(':').append(Base64.getEncoder().encodeToString(bytes)).append(':');
        } else if (value instanceof Token t) {
            sb.append(t.value());
        } else {
            throw new IllegalArgumentException("unsupported item type: " + value);
        }
    }

    private static void serializeParams(StringBuilder sb, Map<String, Object> params) {
        for (Map.Entry<String, Object> e : params.entrySet()) {
            sb.append(';').append(e.getKey());
            if (!Boolean.TRUE.equals(e.getValue())) {
                sb.append('=');
                serializeBareItem(sb, e.getValue());
            }
        }
    }

    static HttpSignatureException malformed(String what) {
        return new HttpSignatureException(HttpSignatureException.Reason.MALFORMED, "Malformed structured field: " + what);
    }

    private static final class Parser {
        private final String s;
        private int i;

        Parser(String s) {
            this.s = s == null ? "" : s;
        }

        boolean atEnd() {
            return i >= s.length();
        }

        char peek() {
            return atEnd() ? '\0' : s.charAt(i);
        }

        char next() {
            if (atEnd()) {
                throw malformed("unexpected end of input");
            }
            return s.charAt(i++);
        }

        void expect(char c) {
            if (next() != c) {
                throw malformed("expected '" + c + "' at " + (i - 1));
            }
        }

        void skipSpaces() {
            while (!atEnd() && s.charAt(i) == ' ') {
                i++;
            }
        }

        void skipOws() {
            while (!atEnd() && (s.charAt(i) == ' ' || s.charAt(i) == '\t')) {
                i++;
            }
        }

        String key() {
            int start = i;
            if (atEnd() || !(isLcAlpha(peek()) || peek() == '*')) {
                throw malformed("expected key at " + i);
            }
            while (!atEnd() && (isLcAlpha(peek()) || Character.isDigit(peek()) || "_-.*".indexOf(peek()) >= 0)) {
                i++;
            }
            return s.substring(start, i);
        }

        static boolean isLcAlpha(char c) {
            return c >= 'a' && c <= 'z';
        }

        InnerList innerList() {
            expect('(');
            List<Item> items = new ArrayList<>();
            while (true) {
                skipSpaces();
                if (atEnd()) {
                    throw malformed("unterminated inner list");
                }
                if (peek() == ')') {
                    next();
                    break;
                }
                items.add(item());
                if (peek() != ' ' && peek() != ')') {
                    throw malformed("expected space or ')' in inner list at " + i);
                }
            }
            return new InnerList(items, params());
        }

        Item item() {
            Object value = bareItem();
            return new Item(value, params());
        }

        Map<String, Object> params() {
            Map<String, Object> params = new LinkedHashMap<>();
            while (peek() == ';') {
                next();
                skipSpaces();
                String key = key();
                Object value = Boolean.TRUE;
                if (peek() == '=') {
                    next();
                    value = bareItem();
                }
                params.put(key, value);
            }
            return params;
        }

        Object bareItem() {
            char c = peek();
            if (c == '"') {
                return string();
            }
            if (c == ':') {
                return byteSequence();
            }
            if (c == '?') {
                next();
                char b = next();
                if (b == '1') {
                    return Boolean.TRUE;
                }
                if (b == '0') {
                    return Boolean.FALSE;
                }
                throw malformed("bad boolean at " + i);
            }
            if (c == '-' || Character.isDigit(c)) {
                return number();
            }
            if (Character.isLetter(c) || c == '*') {
                return token();
            }
            throw malformed("unexpected character '" + c + "' at " + i);
        }

        String string() {
            expect('"');
            StringBuilder sb = new StringBuilder();
            while (true) {
                if (atEnd()) {
                    throw malformed("unterminated string");
                }
                char c = next();
                if (c == '\\') {
                    char e = next();
                    if (e != '"' && e != '\\') {
                        throw malformed("bad escape in string");
                    }
                    sb.append(e);
                } else if (c == '"') {
                    return sb.toString();
                } else if (c < 0x20 || c > 0x7e) {
                    throw malformed("invalid character in string");
                } else {
                    sb.append(c);
                }
            }
        }

        byte[] byteSequence() {
            expect(':');
            int start = i;
            while (!atEnd() && peek() != ':') {
                i++;
            }
            if (atEnd()) {
                throw malformed("unterminated byte sequence");
            }
            String b64 = s.substring(start, i);
            next();
            try {
                return Base64.getDecoder().decode(b64);
            } catch (IllegalArgumentException e) {
                throw malformed("invalid base64 in byte sequence");
            }
        }

        Object number() {
            int start = i;
            if (peek() == '-') {
                next();
            }
            boolean decimal = false;
            while (!atEnd() && (Character.isDigit(peek()) || peek() == '.')) {
                if (peek() == '.') {
                    decimal = true;
                }
                i++;
            }
            String text = s.substring(start, i);
            try {
                return decimal ? (Object) Double.parseDouble(text) : (Object) Long.parseLong(text);
            } catch (NumberFormatException e) {
                throw malformed("bad number '" + text + "'");
            }
        }

        Token token() {
            int start = i;
            while (!atEnd() && (Character.isLetterOrDigit(peek()) || "!#$%&'*+-.^_`|~:/".indexOf(peek()) >= 0)) {
                i++;
            }
            return new Token(s.substring(start, i));
        }
    }
}

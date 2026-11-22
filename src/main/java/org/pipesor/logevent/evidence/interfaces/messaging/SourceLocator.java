package org.pipesor.logevent.evidence.interfaces.messaging;

import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.util.regex.Pattern;

/**
 * Aggregate source locator of protected evidence 2.2:
 * {@code v2:job:<job-id>:member:<member>:lines:<first>-<last>:sha256:<digest>}. The grammar is owned
 * by the contract; this validator checks shape only and never names a workflow-specific member.
 */
final class SourceLocator {
    static final int MAX_LINE_SPAN = 199;
    private static final Pattern GRAMMAR = Pattern.compile(
            "v2:job:([1-9][0-9]{0,19}):member:((?:[A-Za-z0-9._~-]|%[0-9A-F]{2}){1,765})"
                    + ":lines:([1-9][0-9]{0,8})-([1-9][0-9]{0,8}):sha256:[0-9a-f]{64}");

    private SourceLocator() { }

    /** True when {@code locator} is a valid 2.2 locator bound to the authenticated {@code job}. */
    static boolean isValid(String locator, String job) {
        if (locator == null || job == null) return false;
        var parts = GRAMMAR.matcher(locator);
        if (!parts.matches() || !parts.group(1).equals(job)) return false;
        int first = Integer.parseInt(parts.group(3));
        int last = Integer.parseInt(parts.group(4));
        return first <= last && last - first <= MAX_LINE_SPAN && validMember(parts.group(2));
    }

    private static boolean validMember(String encoded) {
        var bytes = new ByteArrayOutputStream();
        for (int i = 0; i < encoded.length(); i++) {
            char current = encoded.charAt(i);
            if (current == '%') {
                int value = Integer.parseInt(encoded, i + 1, i + 3, 16);
                // Canonical form: unreserved bytes are never percent-encoded.
                if (unreserved(value)) return false;
                bytes.write(value);
                i += 2;
            } else {
                bytes.write(current);
            }
        }
        byte[] raw = bytes.toByteArray();
        if (raw.length < 1 || raw.length > 255) return false;
        final String member;
        try {
            member = StandardCharsets.UTF_8.newDecoder()
                    .onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT)
                    .decode(ByteBuffer.wrap(raw)).toString();
        } catch (CharacterCodingException invalid) {
            return false;
        }
        if (member.startsWith("/") || member.indexOf('\\') >= 0) return false;
        if (member.chars().anyMatch(Character::isISOControl)) return false;
        String[] segments = member.split("/", -1);
        if (segments.length > 2) return false;
        for (String segment : segments) {
            if (segment.isEmpty() || segment.equals("..")) return false;
        }
        return true;
    }

    private static boolean unreserved(int value) {
        return value >= 'A' && value <= 'Z' || value >= 'a' && value <= 'z' || value >= '0' && value <= '9'
                || value == '-' || value == '.' || value == '_' || value == '~';
    }
}

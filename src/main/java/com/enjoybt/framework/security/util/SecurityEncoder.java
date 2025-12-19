package com.enjoybt.framework.security.util;

import com.enjoybt.framework.security.encoder.Digester;
import org.springframework.security.crypto.codec.Hex;
import org.springframework.security.crypto.codec.Utf8;
import org.springframework.security.crypto.keygen.BytesKeyGenerator;
import org.springframework.security.crypto.keygen.KeyGenerators;
import org.springframework.security.crypto.password.PasswordEncoder;

import static org.springframework.security.crypto.util.EncodingUtils.concatenate;
import static org.springframework.security.crypto.util.EncodingUtils.subArray;

public class SecurityEncoder implements PasswordEncoder {
    private static final int DEFAULT_ITERATIONS = 1024;

    private final Digester digester;

    private final byte[] secret;

    private final BytesKeyGenerator saltGenerator;

    public SecurityEncoder() {
        this("SHA-512");
    }

    public SecurityEncoder(CharSequence secret) {
        this("SHA-256", secret);
    }

    public SecurityEncoder(String algorithm) {
        this(algorithm, "");
    }

    public SecurityEncoder(String algorithm, CharSequence secret) {
        this.digester = new Digester(algorithm, DEFAULT_ITERATIONS);
        this.secret = Utf8.encode(secret);
        this.saltGenerator = KeyGenerators.secureRandom();
    }

    @Override
    public String encode(CharSequence rawPassword) {
        return encode(rawPassword, saltGenerator.generateKey());
    }

    @Override
    public boolean matches(CharSequence rawPassword, String encodedPassword) {
        byte[] digested = decode(encodedPassword);
        byte[] salt = subArray(digested, 0, saltGenerator.getKeyLength());
        return matches(digested, digest(rawPassword, salt));
    }

    private boolean matches(byte[] expected, byte[] actual) {
        if (expected.length != actual.length) {
            return false;
        }

        int result = 0;
        for (int i = 0; i < expected.length; i++) {
            result |= expected[i] ^ actual[i];
        }
        return result == 0;
    }

    private String encode(CharSequence rawPassword, byte[] salt) {
        byte[] digest = digest(rawPassword, salt);
        return new String(Hex.encode(digest));
    }

    private byte[] digest(CharSequence rawPassword, byte[] salt) {
        byte[] digest = digester.digest(concatenate(salt, secret, Utf8.encode(rawPassword)));
        return concatenate(salt, digest);
    }

    private byte[] decode(CharSequence encodedPassword) {
        return Hex.decode(encodedPassword);
    }
}

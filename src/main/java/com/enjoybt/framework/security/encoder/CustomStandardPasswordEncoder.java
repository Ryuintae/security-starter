package com.enjoybt.framework.security.encoder;

import org.springframework.security.crypto.codec.Hex;
import org.springframework.security.crypto.codec.Utf8;
import org.springframework.security.crypto.keygen.BytesKeyGenerator;
import org.springframework.security.crypto.keygen.KeyGenerators;

import static org.springframework.security.crypto.util.EncodingUtils.concatenate;
import static org.springframework.security.crypto.util.EncodingUtils.subArray;


/**
 *  Description : Spring의 StandardPasswordEncoder.java를 참고하여 만들었으며, SHA-512를 지원할 수 있도록 구현
 */
public class CustomStandardPasswordEncoder {
	
	private final Digester digester;

	private final byte[] secret;

	private final BytesKeyGenerator saltGenerator;

	/**
	 * Constructs a standard password encoder with no additional secret value.
	 */
	public CustomStandardPasswordEncoder() {
		this("");
	}

	/**
	 * Constructs a standard password encoder with a secret value which is also included
	 * in the password hash.
	 *
	 * @param secret the secret key used in the encoding process (should not be shared)
	 */
	public CustomStandardPasswordEncoder(CharSequence secret) {
		this("SHA-256", secret);
	}
	
	public CustomStandardPasswordEncoder(String algorithm) {
		this(algorithm, "");
	}
	
	public CustomStandardPasswordEncoder(String algorithm, CharSequence secret) {
		this.digester = new Digester(algorithm, DEFAULT_ITERATIONS);
		this.secret = Utf8.encode(secret);
		this.saltGenerator = KeyGenerators.secureRandom();
	}

	public String encode(CharSequence rawPassword) {
		return encode(rawPassword, saltGenerator.generateKey());
	}

	public boolean matches(CharSequence rawPassword, String encodedPassword) {
		byte[] digested = decode(encodedPassword);
		byte[] salt = subArray(digested, 0, saltGenerator.getKeyLength());
		return matches(digested, digest(rawPassword, salt));
	}

	// internal helpers


	private String encode(CharSequence rawPassword, byte[] salt) {
		byte[] digest = digest(rawPassword, salt);
		return new String(Hex.encode(digest));
	}

	private byte[] digest(CharSequence rawPassword, byte[] salt) {
		byte[] digest = digester.digest(concatenate(salt, secret,
				Utf8.encode(rawPassword)));
		return concatenate(salt, digest);
	}

	private byte[] decode(CharSequence encodedPassword) {
		return Hex.decode(encodedPassword);
	}

	/**
	 * Constant time comparison to prevent against timing attacks.
	 */
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

	private static final int DEFAULT_ITERATIONS = 1024;
	
}

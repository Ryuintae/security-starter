package com.enjoybt.framework.security.encoder;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 *  Description : CustomStandardPasswordEncoder.java에서 사용하기 위한  알고리즘 관리 객체
 */
public class Digester {

	private final String algorithm;

	private final int iterations;

	/**
	 * Create a new Digester.
	 * 
	 * @param algorithm
	 *            the digest algorithm; for example, "SHA-1" or "SHA-256".
	 * @param iterations
	 *            the number of times to apply the digest algorithm to the input
	 */
	public Digester(String algorithm, int iterations) {
		// eagerly validate the algorithm
		createDigest(algorithm);
		this.algorithm = algorithm;
		this.iterations = iterations;
	}

	public byte[] digest(byte[] value) {
		MessageDigest messageDigest = createDigest(algorithm);
		byte[] temp = value.clone();
		for (int i = 0; i < iterations; i++) {
			temp = messageDigest.digest(temp);
		}
		return temp;
	}

	private static MessageDigest createDigest(String algorithm) {
		try {
			return MessageDigest.getInstance(algorithm);
		} catch (NoSuchAlgorithmException e) {
			throw new IllegalStateException("No such hashing algorithm", e);
		}
	}
}

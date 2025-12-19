package com.enjoybt.framework.security.encoder;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.servlet.http.HttpSession;
import java.io.UnsupportedEncodingException;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;

/**
 *  Description : RSA 키를 관리하기 위한 객체
 */
public class RSAGenerator {

	private static final Logger LOGGER = LoggerFactory.getLogger(RSAGenerator.class);
	
	private static final int KEY_SIZE = 2048;
	private static final String RSA_KEY = "RSA_PK";
	private static final String KEY_TYPE = "RSA";
	
	/**
	 * Description : RSA 키를 만들어서 공개키는 리턴하고, 비밀키는 세션에 담도록 처리
	 * @param session(HttpSession)			- 사용자 세션
	 * @return(String[])					- 공개키
	 */
	public static String[] createRsaGenerator(HttpSession session) {
		String[] result = new String[2];
		
		KeyPairGenerator generator;
		KeyPair keyPair;
		KeyFactory keyFactory;
		PublicKey publicKey;
		PrivateKey privateKey;
		
		try {
			generator = KeyPairGenerator.getInstance(KEY_TYPE);
			generator.initialize(KEY_SIZE);
			
			keyPair = generator.genKeyPair();
			keyFactory = KeyFactory.getInstance(KEY_TYPE);
			
			publicKey = keyPair.getPublic();
			privateKey = keyPair.getPrivate();
			
			session.setAttribute(RSA_KEY, privateKey);
			
			RSAPublicKeySpec publicSpec = (RSAPublicKeySpec) keyFactory.getKeySpec(publicKey, RSAPublicKeySpec.class);
			
			String publicKeyModulus = publicSpec.getModulus().toString(16);
			String publicKeyExponent = publicSpec.getPublicExponent().toString(16);
			
			result[0] = publicKeyModulus;
			result[1] = publicKeyExponent;
			
		} catch (NoSuchAlgorithmException e) {
			LOGGER.error("RSA Generator Error", e);
			result = null;
		} catch (InvalidKeySpecException e) {
			LOGGER.error("RSA Generator Error", e);
			result = null;
		}
		
		return result;
	}
	
	/**
	 * Description : 비밀키를 가져오고, 세션에서 비밀키를 제거
	 * @param session(HttpSession)		- 사용자 세션
	 * @return(PrivateKey)				- 비밀키
	 */
	public static PrivateKey getPrivateKey(HttpSession session) {
		PrivateKey privateKey = null;
		
		try{
			
			privateKey = (PrivateKey)session.getAttribute(RSA_KEY);
			session.removeAttribute(RSA_KEY);
			
		}catch(NullPointerException e) {
			LOGGER.error("RSA Generator Error", e);
		}
		
		return privateKey;
	}
	
	/**
	 * Description : 암호화 된 데이터를 복호화하는 기능
	 * @param privateKey(PrivateKey)		- 비밀키
	 * @param str(String)					- 암호화 된 데이터
	 * @return (String)						- 복호화 된 데이터
	 */
	public static String getValue(PrivateKey privateKey, String str) {
		String result = "";
		
		try {
			
			Cipher cipher = Cipher.getInstance(KEY_TYPE);
			byte[] encryptedBytes = hexToByteArray(str);
			
			cipher.init(Cipher.DECRYPT_MODE, privateKey);
			
			byte[] decryptedBytes = cipher.doFinal(encryptedBytes);
			
			result = new String(decryptedBytes, "utf-8");
			
		}catch(NullPointerException e) {
			LOGGER.error("RSA Generator Error", e);
			result = null;
		} catch (NoSuchAlgorithmException e) {
			LOGGER.error("RSA Generator Error", e);
			result = null;
		} catch (NoSuchPaddingException e) {
			LOGGER.error("RSA Generator Error", e);
			result = null;
		} catch (InvalidKeyException e) {
			LOGGER.error("RSA Generator Error", e);
			result = null;
		} catch (UnsupportedEncodingException e) {
			LOGGER.error("RSA Generator Error", e);
			result = null;
		} catch (IllegalBlockSizeException e) {
			LOGGER.error("RSA Generator Error", e);
			result = null;
		} catch (BadPaddingException e) {
			LOGGER.error("RSA Generator Error", e);
			result = null;
		}
		
		return result;
	}
	
	public static byte[] hexToByteArray(String hex) {
		if (hex == null || hex.length() % 2 != 0) {
			return new byte[] {};
		}

		byte[] bytes = new byte[hex.length() / 2];
		for (int i = 0; i < hex.length(); i += 2) {
			byte value = (byte) Integer.parseInt(hex.substring(i, i + 2), 16);
			bytes[(int) Math.floor(i / 2)] = value;
		}
		return bytes;
	}
}

/*
 * Copyright 2011-2016 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.springframework.security.crypto.encrypt;

import static org.springframework.security.crypto.encrypt.CipherUtils.doFinal;
import static org.springframework.security.crypto.encrypt.CipherUtils.initCipher;
import static org.springframework.security.crypto.encrypt.CipherUtils.newSecretKey;
import static org.springframework.security.crypto.util.EncodingUtils.concatenate;
import static org.springframework.security.crypto.util.EncodingUtils.subArray;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

import org.springframework.security.crypto.codec.Hex;
import org.springframework.security.crypto.keygen.BytesKeyGenerator;

/**
 * Encryptor that uses 256-bit AES encryption.
 *
 * @author Keith Donald
 * @author Dave Syer
 */
final class AesBytesEncryptor implements BytesEncryptor {

	private final SecretKey secretKey;

	private final Cipher encryptor;

	private final Cipher decryptor;

	private final BytesKeyGenerator ivGenerator;

	private CipherAlgorithm alg;

	static final String AES_CBC_ALGORITHM = "AES/CBC/PKCS5Padding";

	static final String AES_GCM_ALGORITHM = "AES/GCM/NoPadding";

	public AesBytesEncryptor(String password, CharSequence salt) {
		this(password, salt, null);
	}

	public AesBytesEncryptor(String password, CharSequence salt,
			BytesKeyGenerator ivGenerator) {
		this(password, salt, ivGenerator, CipherAlgorithm.CBC);
	}

	public AesBytesEncryptor(String password, CharSequence salt,
							 BytesKeyGenerator ivGenerator, CipherAlgorithm alg) {
		this(password, salt, ivGenerator, alg, 256);
	}

	public AesBytesEncryptor(String password, CharSequence salt,
							 BytesKeyGenerator ivGenerator, CipherAlgorithm alg, int keyLength) {
		PBEKeySpec keySpec = new PBEKeySpec(password.toCharArray(), Hex.decode(salt),
				1024, keyLength);
		SecretKey secretKey = newSecretKey("PBKDF2WithHmacSHA1", keySpec);
		this.secretKey = new SecretKeySpec(secretKey.getEncoded(), "AES");
		this.alg = alg;
		this.encryptor = alg.createCipher();
		this.decryptor = alg.createCipher();
		this.ivGenerator = ivGenerator != null ? ivGenerator : alg.defaultIvGenerator();
	}

	public byte[] encrypt(byte[] bytes) {
		synchronized (this.encryptor) {
			byte[] iv = this.ivGenerator.generateKey();
			initCipher(this.encryptor, Cipher.ENCRYPT_MODE, this.secretKey,
					this.alg.getParameterSpec(iv));
			byte[] encrypted = doFinal(this.encryptor, bytes);
			return this.ivGenerator != NULL_IV_GENERATOR ? concatenate(iv, encrypted)
					: encrypted;
		}
	}

	public byte[] decrypt(byte[] encryptedBytes) {
		synchronized (this.decryptor) {
			byte[] iv = iv(encryptedBytes);
			initCipher(this.decryptor, Cipher.DECRYPT_MODE, this.secretKey,
					this.alg.getParameterSpec(iv));
			return doFinal(
					this.decryptor,
					this.ivGenerator != NULL_IV_GENERATOR ? encrypted(encryptedBytes,
							iv.length) : encryptedBytes);
		}
	}

	// internal helpers

	private byte[] iv(byte[] encrypted) {
		return this.ivGenerator != NULL_IV_GENERATOR ? subArray(encrypted, 0,
				this.ivGenerator.getKeyLength()) : NULL_IV_GENERATOR.generateKey();
	}

	private byte[] encrypted(byte[] encryptedBytes, int ivLength) {
		return subArray(encryptedBytes, ivLength, encryptedBytes.length);
	}

	static final BytesKeyGenerator NULL_IV_GENERATOR = new BytesKeyGenerator() {

		private final byte[] VALUE = new byte[16];

		public int getKeyLength() {
			return this.VALUE.length;
		}

		public byte[] generateKey() {
			return this.VALUE;
		}

	};
}

package org.springframework.security.crypto.encrypt;

import org.springframework.security.crypto.keygen.BytesKeyGenerator;
import org.springframework.security.crypto.keygen.KeyGenerators;

/**
 * For building an Encryptor. Start with define.
 */
public class EncryptorBuilder {

    //Builder fields with default values
    private CharSequence password;
    private CharSequence salt;
    private CipherAlgorithm cipherAlgorithm = CipherAlgorithm.CBC;
    private BytesKeyGenerator ivGenerator = KeyGenerators.secureRandom(16);
    private int keyLength = 256;

    /**
     * Private constructor, use the define factory method instead.
     */
    private EncryptorBuilder(CharSequence password, CharSequence salt) {
        if(password == null) throw new IllegalStateException("Cannot build encryptor without password");
        if(salt == null) throw new IllegalStateException("Cannot build encryptor without salt");
        this.password = password;
        this.salt = salt;
    }

    public static EncryptorBuilder define(CharSequence password, CharSequence salt) {
        return new EncryptorBuilder(password, salt);
    }

    public TextEncryptor forText() {
        return new HexEncodingTextEncryptor(forBytes());
    }

    public EncryptorBuilder queryable() {
        this.ivGenerator = AesBytesEncryptor.NULL_IV_GENERATOR;
        return this;
    }

    public BytesEncryptor forBytes(){
        return new AesBytesEncryptor(password.toString(), salt, ivGenerator, cipherAlgorithm, keyLength);
    }

    public EncryptorBuilder withKeyLength(int keyLength) {
        this.keyLength = keyLength;
        return this;
    }

    public EncryptorBuilder withIvGenerator(BytesKeyGenerator ivGenerator) {
        this.ivGenerator = ivGenerator;
        return this;
    }

    public EncryptorBuilder withCipherAlg(CipherAlgorithm alg) {
        this.cipherAlgorithm = alg;
        return this;
    }

    public EncryptorBuilder stronger() {
        this.cipherAlgorithm = CipherAlgorithm.GCM;
        return this;
    }
}

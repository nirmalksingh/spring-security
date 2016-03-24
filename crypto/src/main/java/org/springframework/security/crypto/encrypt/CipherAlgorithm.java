package org.springframework.security.crypto.encrypt;

import org.springframework.security.crypto.keygen.BytesKeyGenerator;
import org.springframework.security.crypto.keygen.KeyGenerators;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import java.security.spec.AlgorithmParameterSpec;

import static org.springframework.security.crypto.encrypt.CipherUtils.newCipher;

public enum CipherAlgorithm {

    CBC(AesBytesEncryptor.AES_CBC_ALGORITHM, AesBytesEncryptor.NULL_IV_GENERATOR),
    GCM(AesBytesEncryptor.AES_GCM_ALGORITHM, KeyGenerators.secureRandom(16));

    private BytesKeyGenerator ivGenerator;
    private String name;

    private CipherAlgorithm(String name, BytesKeyGenerator ivGenerator) {
        this.name = name;
        this.ivGenerator = ivGenerator;
    }

    @Override
    public String toString() {
        return this.name;
    }

    public AlgorithmParameterSpec getParameterSpec(byte[] iv) {
        return this == CBC ? new IvParameterSpec(iv) : new GCMParameterSpec(128, iv);
    }

    public Cipher createCipher() {
        return newCipher(this.toString());
    }

    public BytesKeyGenerator defaultIvGenerator() {
        return this.ivGenerator;
    }
}

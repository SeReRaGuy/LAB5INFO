package com.example.lab5info;

import org.bouncycastle.crypto.engines.GOST28147Engine;
import org.bouncycastle.crypto.modes.CFBBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.util.encoders.Hex;

import java.io.*;

public class Main {

    public static void main(String[] args) throws IOException {
        byte[] key;
        try (BufferedWriter bufferedWriter = new BufferedWriter(new FileWriter("key.txt"))) {
            bufferedWriter.write("00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF");
        }
        try (BufferedReader bufferedReader = new BufferedReader(new FileReader("key.txt"))) {
            String keyString = bufferedReader.readLine();
            if (keyString != null) {
                key = Hex.decode(keyString);
            } else {
                throw new IOException("ERROR: Key is empty");
            }
        }
        byte[] initVector = Hex.decode("1122334455667788");
        File archiveToEncrypt = new File("archive.7z");
        byte[] openData = new byte[(int) archiveToEncrypt.length()];
        try (InputStream inputStream = new FileInputStream(archiveToEncrypt)) {
            inputStream.read(openData);
        }
        byte[] encryptedData = encrypt(key, initVector, openData);
        byte[] decryptedData = decrypt(key, initVector, encryptedData);
        try (OutputStream outputStream = new FileOutputStream(new File("archive_decrypted.7z"))) {
            outputStream.write(decryptedData);
        }
    }

    public static byte[] encrypt(byte[] key, byte[] iv, byte[] openData) {
        GOST28147Engine gostsCipher = new GOST28147Engine();
        gostsCipher.init(true, new KeyParameter(key));
        CFBBlockCipher cfbCipher = new CFBBlockCipher(gostsCipher, 64);
        cfbCipher.init(true, new ParametersWithIV(new KeyParameter(key), iv));
        byte[] encryptedData = new byte[openData.length];
        for (int i = 0; i < openData.length; i++) {
            encryptedData[i] = (byte) (openData[i] ^ cfbCipher.returnByte((byte) 0));
        }
        return encryptedData;
    }

    public static byte[] decrypt(byte[] key, byte[] iv, byte[] encryptedData) {
        GOST28147Engine cipher = new GOST28147Engine();
        cipher.init(true, new KeyParameter(key));
        CFBBlockCipher cfbCipher = new CFBBlockCipher(cipher, 64);
        cfbCipher.init(true, new ParametersWithIV(new KeyParameter(key), iv));
        byte[] decryptedData = new byte[encryptedData.length];
        for (int i = 0; i < encryptedData.length; i++) {
            decryptedData[i] = (byte) (encryptedData[i] ^ cfbCipher.returnByte((byte) 0));
        }
        return decryptedData;
    }
}

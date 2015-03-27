
package csec2015;

import java.security.AlgorithmParameterGenerator;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidParameterSpecException;

import java.util.Arrays;

import javax.crypto.BadPaddingException;
import javax.crypto.CipherSpi;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.ShortBufferException;

import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class AESCipher extends CipherSpi {
    byte[] iv = new byte[16];
    boolean do_pad;
    boolean do_cbc;

    protected void engineSetMode(String mode)
      throws NoSuchAlgorithmException {
        if (mode.equals("CBC")) {
            do_cbc = true;
        } else if (mode.equals("ECB")) {
            do_cbc = false;
        } else {
            throw new NoSuchAlgorithmException();
        }
    }
    protected void engineSetPadding(String padding)
      throws NoSuchPaddingException {
        if (padding.equals("NoPadding")) {
            do_pad = false;
        } else if (padding.equals("PKCS5Padding")) {
            do_pad = true;
        } else {
            throw new NoSuchPaddingException();
        }
    }
    protected int engineGetBlockSize() {
        return 16; // This is constant for AES.
    }
    protected int engineGetOutputSize(int inputLen) {
        /**
         * First method to be implemented. Should take into account
         * the data in the buffer, size of input data (inputLen)
         * and needs to calculate any padding (check if PKCS5 is set?)
         */
        
        int length = inputLen;
        
        // Where do we get how much is in the buffer?
        
        return length;
        
    }
    protected byte[] engineGetIV() {
        byte[] retiv = new byte[16];
        System.arraycopy(iv, 0, retiv, 0, 16);
        return retiv;
    }
    protected AlgorithmParameters engineGetParameters() {
        AlgorithmParameters ap = null;
        try {
            ap = AlgorithmParameters.getInstance("AES");
            ap.init(new IvParameterSpec(engineGetIV()));
        } catch (NoSuchAlgorithmException e) {
            System.err.println("Internal Error: " + e);
        } catch (InvalidParameterSpecException e) {
            System.err.println("Internal Error: " + e);
        }
        return ap;
    }
    protected void engineInit(int opmode, Key key, SecureRandom random)
      throws InvalidKeyException {
        try {
            engineInit(opmode, key, (AlgorithmParameterSpec)null, random);
        } catch (InvalidAlgorithmParameterException e) {
            System.err.println("Internal Error: " + e);
        }
    }
    protected void engineInit(int opmode, Key key, AlgorithmParameters params, SecureRandom random)
      throws InvalidKeyException {
        try {
            engineInit(opmode, key, params.getParameterSpec(IvParameterSpec.class), random);
        } catch (InvalidParameterSpecException e) {
            System.err.println("Internal Error: " + e);
        } catch (InvalidAlgorithmParameterException e) {
            System.err.println("Internal Error: " + e);
        }
    }
    protected void engineInit(int opmode, Key key, AlgorithmParameterSpec params, SecureRandom random)
      throws InvalidKeyException, InvalidAlgorithmParameterException {
        /**
         * Implement me.
         */
    }
    private int allocateSize(int inputLen) {
        /**
         * Implement me.
         */
    }
    protected byte[] engineUpdate(byte[] input, int inputOffset, int inputLen) {
        byte[] output = new byte[allocateSize(inputLen)];
        int size = 0;
        try {
            size = engineUpdate(input, inputOffset, inputLen, output, 0);
        } catch (ShortBufferException e) {
            System.err.println("Internal Error: " + e);
        }
        return Arrays.copyOf(output, size);
    }
    protected int engineUpdate(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset)
      throws ShortBufferException {
        /**
         * Implement me.
         */
    }
    protected byte[] engineDoFinal(byte[] input, int inputOffset, int inputLen)
      throws IllegalBlockSizeException, BadPaddingException {
        try {
            byte[] temp = new byte[engineGetOutputSize(inputLen)];
            int len = engineDoFinal(input, inputOffset, inputLen, temp, 0);
            return Arrays.copyOf(temp, len);
        } catch (ShortBufferException e) {
            System.err.println("Internal Error: " + e);
            return null;
        }
    }
    protected int engineDoFinal(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset)
      throws ShortBufferException, IllegalBlockSizeException, BadPaddingException {
        /**
         * Implement me.
         */
    }
}

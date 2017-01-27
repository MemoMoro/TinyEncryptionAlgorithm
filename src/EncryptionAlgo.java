import java.util.*;
 
public class EncryptionAlgo {

    private static enum Mode {
        ECB, CBC
    }

    private static int DELTA = 0x9e3779b9;
    private static int ROUNDS = 32;
    private int sum;

    private int[] key;

    public EncryptionAlgo(int[] key) {
	    if (null == key) {
            throw new NullPointerException("Key passed to constructor was null.");
        }
        if (key.length != 4) {
            throw new IllegalArgumentException("The key array passed has to be of length 4.");
        }

	    key = new int[4];
	    this.key[0] = key[0];
	    this.key[1] = key[1];
	    this.key[2] = key[2];
	    this.key[3] = key[3];
    }

    public void setKey(int[] key) {
        if (key.length != 4) {
            throw new IllegalArgumentException("key has to be 128 bits.");
        }
        this.key = key;
    }

    public int[] encryptCBC(int[] plainText, int[] previous) {
        return encrypt(plainText, Mode.CBC, previous);
    }

    public int[] encryptEBC(int[] plainText) {
        return encrypt(plainText, Mode.ECB, null);
    }

    public int[] decryptCBC(int[] plainText, int[] previous) {
        return decrypt(plainText, Mode.CBC, previous);
    }

    public int[] decryptEBC(int[] plainText) {
        return decrypt(plainText, Mode.ECB, null);
    }

	private int[] encrypt(int[] plainText, Mode mode, int[] previous) {
        int left, right;

        if (mode == Mode.ECB) {
		    left = plainText[0];	
		    right = plainText[1];
        }
        else { // mode == Mode.CBC
            left = plainText[0] ^ previous[0];
            right = plainText[1] ^ previous[1];
        }

		sum = 0;

		for (int i = 0; i < 32; i++) {
			sum += DELTA;
			left += ((right << 4) + key[0]) ^ (right+sum) ^ ((right >> 5) + key[1]);
			right += ((left << 4) + key[2]) ^ (left+sum) ^ ((left >> 5) + key[3]);
		}
		
		int block[] = new int[2];
		block[0] = left;
		block[1] = right;

		return block;
	}

	private int[] decrypt(int[] cipherText, Mode mode, int[] previous) {
		int left = cipherText[0];
		int right = cipherText[1];

		sum = DELTA << 5;

		for (int i = 0; i < 32; i++) {
			right -= ((left << 4) + key[2]) ^ (left+sum) ^ ((left >> 5) + key[3]);
			left -= ((right << 4) + key[0]) ^ (right+sum) ^ ((right >> 5) + key[1]);
			sum -= DELTA;
		}
		
		int block[] = new int[2];
        if (mode == Mode.ECB) {
		    block[0] = left;
		    block[1] = right;
        } else { // mode == Mode.CBC
            block[0] = left ^ previous[0];
            block[1] = right ^ previous[1];
        }

		return block;
	}
}

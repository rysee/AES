class AES {
    
    public static int Nk, Nb, Nr;
    
    public static byte[] K; // Cipher Key
    
    public static Word[] keyExpansion;
    
	 private static int[] sBox = { 
		//0    1     2     3     4     5     6    7     8     9     A     B      C     D     E     F
		0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
		0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0, 
		0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15, 
		0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75, 
		0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
		0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF, 
		0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8, 
		0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
		0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73, 
		0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
		0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79, 
		0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
		0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A, 
		0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E, 
		0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF, 
		0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16 };

	  private static int[] inv_sBox = { 
    
		//0    1     2     3     4     5     6    7     8     9     A     B      C     D     E     F
		0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB, 
		0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB, 
		0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E, 
		0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25, 
		0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
		0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84, 
		0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
		0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
		0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
		0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
		0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B, 
		0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4, 
		0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F, 
		0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF, 
		0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61, 
		0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D };
                
                
    private AES(byte[] key){
        // via instruction: The encryption key should be provided as an argument to the class constructor
        // I'm assuming passing a byte array would be easiest
        
        // I think this is the little bit of logic Christian 
        // mentioned in the assignement pdf
        Nb = 4; 
        Nr = -1;
        // Nk is determined by the number of 32-bit words in the cipher key
        // so theoretically Nk is equal to the length of key divided by 4 
        // since 32-bits is 4 bytes. I think this will work, will find out when 
        // we get further along.
        Nk = (key.length / 4);

        if (Nk == 4) {
            Nr = 10;
        }
        else if (Nk == 6) {
            Nr = 12;
        }
        else {
            Nr = 14;
        }
        
        K = key;
        
        keyExpansion = keyExpansion(K);

    }
    
    
    public static void main(String[] args) {

        // Key from Appendix B
        byte[] key = {(byte) 0x00, (byte) 0x01, (byte) 0x02, (byte) 0x03, (byte) 0x04, (byte) 0x05, (byte) 0x06,
                       (byte) 0x07, (byte) 0x08, (byte) 0x09, (byte) 0x0a, (byte) 0x0b, (byte) 0x0c, (byte) 0x0d,
                        (byte) 0x0e, (byte) 0x0f};
        
        AES aes = new AES(key);
        
        byte[] in = { (byte) 0x00, (byte) 0x11, (byte) 0x22, (byte) 0x33, (byte) 0x44, (byte) 0x55, (byte) 0x66,
                         (byte) 0x77, (byte) 0x88, (byte) 0x99, (byte) 0xaa, (byte) 0xbb, (byte) 0xcc, (byte) 0xdd,
                          (byte) 0xee, (byte) 0xff};
        
        byte[] out = aes.cipher(in);
        
        byte[] testDecrypt = aes.inverseCipher(out);
        printByteArray(testDecrypt);
        
        
        
        
        byte[] key256 = {(byte) 0x00, (byte) 0x01, (byte) 0x02, (byte) 0x03, (byte) 0x04, (byte) 0x05, 
                            (byte) 0x06, (byte) 0x07, (byte) 0x08, (byte) 0x09, (byte) 0x0a, (byte) 0x0b, 
                            (byte) 0x0c, (byte) 0x0d, (byte) 0x0e, (byte) 0x0f, (byte) 0x10, (byte) 0x11, 
                            (byte) 0x12, (byte) 0x13, (byte) 0x14, (byte) 0x15, (byte) 0x16, (byte) 0x17, 
                            (byte) 0x18, (byte) 0x19, (byte) 0x1a, (byte) 0x1b, (byte) 0x1c, (byte) 0x1d, 
                            (byte) 0x1e, (byte) 0x1f};
                    
        AES aes256 = new AES(key256);
        out = aes256.cipher(in); 
        printByteArray(aes256.inverseCipher(out));
   
    }
    
    public static byte[] cipher(byte[] in){
        // in would be a byte array of lenth 16
        
        // NOTE: word w[Nb*(Nr+1)]
        // w is word array of 44 words
        
        Word[] state = new Word[Nb];
        
        for (int i = 0; i < Nb; i++) {
            // This looks overly complicated but it is just converting the 16 bytes from in
            // to words and assigning them to the state
            state[i] = new Word(in[(i) + (i*3)], in[ (i+1) + (i*3)], in[(i+2) + (i*3)], in[(i+3) + (i*3)]); 
        }
        
        Word[] temp;
        //AddRoundKey(state, w[0, Nb-1]) // See Sec. 5.1.4 (0-3) == 4 words
        // Don't need a -1 one because copyOfRange's end point is exclusive
        temp = java.util.Arrays.copyOfRange(keyExpansion, 0, Nb);
        state = addRoundKey(state, temp, 0); // pass the starting number       
        
        for (int round = 1; round <= Nr-1; round++){
            
            subBytes(state); // See Sec. 5.1.1
            state = shiftRows(state); // See Sec. 5.1.2
            state = mixColumns(state); // See Sec. 5.1.3
            // AddRoundKey(state, w[round*Nb, (round+1)*Nb-1])
            // Don't need a -1 one because copyOfRange's end point is exclusive
            temp = java.util.Arrays.copyOfRange(keyExpansion, round*Nb, (round+1)*Nb);
            state = addRoundKey(state, temp, round);
        }

        subBytes(state);
        state = shiftRows(state);
        
        // AddRoundKey(state, w[Nr*Nb, (Nr+1)*Nb-1])
        // Don't need a -1 one because copyOfRange's end point is exclusive
        temp = java.util.Arrays.copyOfRange(keyExpansion, Nr*Nb, (Nr+1)*Nb);
        state = addRoundKey(state, temp, Nr*Nb);
        
        // convert state to byte[] and the return this array
        return toByteArray(state);
        
    }
    
    private static byte[] inverseCipher(byte[] in){
        
        //InvCipher(byte in[4*Nb], byte out[4*Nb], word w[Nb*(Nr+1)])

        Word[] state = new Word[Nb];
        Word[] temp;
        
        for (int i = 0; i < Nb; i++) {
            // This looks overly complicated but it is just converting the 16 bytes from in
            // to words and assigning them to the state
            state[i] = new Word(in[(i) + (i*3)], in[ (i+1) + (i*3)], in[(i+2) + (i*3)], in[(i+3) + (i*3)]); 
        }


        // AddRoundKey(state, w[Nr*Nb, (Nr+1)*Nb-1]) // See Sec. 5.1.4
        // Don't need a -1 one because copyOfRange's end point is exclusive
        temp = java.util.Arrays.copyOfRange(keyExpansion, Nr*Nb, (Nr+1)*Nb);
        state = addRoundKey(state, temp, (Nr+1)*Nb-1);
        
        
        for (int round = Nr-1; round >= 1; round--) {
            // invShift works and invSubBytes
            state = invShiftRows(state); // See Sec. 5.3.1
            
            invSubBytes(state); // See Sec. 5.3.2
            
            // AddRoundKey(state, w[round*Nb, (round+1)*Nb-1])
            // Don't need a -1 one because copyOfRange's end point is exclusive
            temp = java.util.Arrays.copyOfRange(keyExpansion, round*Nb, (round+1)*Nb);
            state = addRoundKey(state, temp, round);
            
            state = invMixColumns(state); // See Sec. 5.3.3
        }

        state = invShiftRows(state);

        invSubBytes(state);

        // AddRoundKey(state, w[0, Nb-1])
        // Don't need a -1 one because copyOfRange's end point is exclusive
        temp = java.util.Arrays.copyOfRange(keyExpansion, 0, Nb);
        state = addRoundKey(state, temp, 0);
        return toByteArray(state);  
        
    }
    
    private static byte[] toByteArray(Word[] state){
        // Takes a word array and will convert it to a byte array
        byte[] out = new byte[4*state.length];
        
        for (int i = 0; i < state.length; i++) {
            out[i + (i*3)] = (byte) state[i].w[0];
            out[(i+1) + (i*3)] = (byte) state[i].w[1];
            out[(i+2) + (i*3)] = (byte) state[i].w[2];
            out[(i+3) + (i*3)] = (byte) state[i].w[3];

        }
        
        return out;
        
    }
    
    private static Word[] addRoundKey(Word[] state, Word[] w, int l){
        // Each Round Key consists of Nb words from the key schedule
        // Those Nb words are each added into the columns of the State, such that
        // [s'(0,c), s'(1,c), s'(2,c), s'(3,c)] = 
                        // [s(0,c), s(1,c), s(2,c), s(3,c)] XOR [W(round*Nb +c)] for 0 <= c < Nb
        // Where W(i) are the key schedule words (check 5.2)

        for (int c = 0; c < state.length; c++) {
            // Word Addition
            state[c] = XOR(state[c], w[c]);
        }
        return state;
    }
    
    
    private static Word[] keyExpansion(byte[] key) {
        // KeyExpansion(byte key[4*Nk], word w[Nb*(Nr+1)], Nk)
        // Nb (Nr + 1) == number of words Nr == number of rounds
        // Nb should == 4, Nr == 10, Nk == 4

        Word[] wordArray = new Word[Nb*(Nr+1)];
        Word temp = new Word();
        
        for (int i = 0; i < Nk; i++) {
            // This adds the key to the begining of the wordArray
            wordArray[i] = new Word(key[4*i], key[(4*i)+1], key[(4*i)+2], key[(4*i)+3]);
        }
        
        // The below is the while loop from figure 11.     
        for (int i = Nk; i < Nb * (Nr+1); i++){ 
            
            temp = wordArray[i-1];
            
            if (i % Nk == 0){ // rounds that are a multiple of Nk
                temp = XOR( subWord(rotWord(temp)) , Rcon(i/Nk));    
            }
            else if (Nk > 6 && i % Nk == 4){ // if Nk == 8 ie 256
                temp = subWord(temp);
            }
            
            wordArray[i] = XOR(wordArray[i-Nk], temp);
        }

        return wordArray;
    }
    
    private static Word Rcon(int n){
        
        // This is what christian says about Rcon"
        // "Pay careful attention to the computation of Rcon[i]. The specification states that 
        // Rcon[i]=[x^(i-1), 0, 0, 0] with i starting at 1. Initialize Rcon[1]
        // with a value of [1, 0, 0, 0] and use xtime() on the first byte to compute each 
        // subsequent value. You can test the scheduler using the examples given in Appendix A.1 
        // of the specification."
        
        byte result = (byte) 0x01; // This is the initialization step
        for (int i = 2; i <= n; i++) {
            result = xtime(result);
        }   

        return new Word(result, 0x00, 0x00, 0x00);
    }
    
    private static void subBytes(Word[] state){
        // Word array instead of a two diminsional byte array
        subBytes(state, sBox);
    }
    
    public static void subBytes(Word[] state, int[] sBox) {
	int check;
        for (int i = 0; i < state.length; i++) {
            
            for (int j = 0; j < 4; j++) {
                // If Java just had unsigned ints this wouldn't be so bad
                check = Integer.parseInt("" + state[i].w[j]);
                if (check < 0) {
                    check = (check ^ 0xffffff00);
                }
                
                state[i].w[j] = sBox[Integer.parseInt("" + check)];
            }

        }
    }

    // Is inverse subBytes the same as subBytes but with inv_sBox?
    public static void invSubBytes(Word[] state){
        // Word array instead of a two diminsional byte array
        subBytes(state, inv_sBox);
    }
    
    private static Word subWord(Word word){
        int w0;
        Word temp = new Word();
        for (int i = 0; i < 4; i++) {
            w0 = Integer.parseInt("" + word.w[i]);
            if (w0 < 0) {
                w0 = w0 ^ 0xffffff00;
            }
            // The above gets rid of the negative values
            temp.w[i] = sBox[w0];
        }
        
        return temp; 
    }

    //Do we need a inverse subWord?
    //Would it be the same as subWord but using inv_sBox?
    public static Word invSubWord(Word word){
        
        int w0;
        Word temp = new Word();
        for (int i = 0; i < 4; i++) {
            w0 = Integer.parseInt("" + word.w[i]);
            if (w0 < 0) {
                w0 = w0 ^ 0xffffff00;
            }
            // The above gets rid of the negative values
            temp.w[i] = inv_sBox[w0];
        }
        
        return word; // This could be wrong
    }
    
    private static Word[] shiftRows(Word[] state){
        Word[] temp = new Word[4];
        for (int i = 0; i < 4; i++) {
            temp[i] = new Word();
        }
        
        for (int i = 0; i < 4; i++) {
            // Zeroth row is unaltered on the words
            
            temp[i].w[0] = state[i].w[0];
            temp[i].w[1] = state[(i+1)%4].w[1];
            temp[i].w[2] = state[(i+2)%4].w[2];
            temp[i].w[3] = state[(i+3)%4].w[3];
            
        }       
        return temp;
    }
    
    //This should be right
    public static Word[] invShiftRows (Word[] state){
        Word[] temp = new Word[4];
        for (int i = 0; i < 4; i++){
            temp[i] = new Word();
        }
        
        for (int i = 0; i < 4; i++){
            // 0th row is unaltered
            // Still need to start at zero because NIST has columns as Words in 
            // their doc and we have them as rows
            temp[i].w[0]= state[i].w[0]; // This is the unaltering of the zeroth row
            temp[i].w[1]= state[(i + 3)%Nb].w[1];
            temp[i].w[2]= state[(i + 2)%Nb].w[2];
            temp[i].w[3]= state[(i + 1)%Nb].w[3];
        }
        return temp;
    }   
     
    private static Word[] mixColumns(Word[] state){
        // Remember that each column in the state is represented by a word
        
        // NIST doc gives the following equations
        // s'(0,c) = ({02} * s(0,c)) ^ ({03} * s(1,c)) ^ s(2,c) ^ s(3,c)
        // s'(1,c) = s(0,c) ^ ({02} * s(1,c)) ^ ({03} * s(2,c)) ^ s(3,c)
        // s'(2,c) = s(0,c) ^ s(1,c) ^ ({02} * s(2,c)) ^ ({03} * s(3,c))
        // s'(3,c) = ({03} * s(0,c)) ^ s(1,c) ^ s(2,c) ^ ({02} * s(3,c)) 
        
        Word[] temp = new Word[4];
        // Initialize temp
        for (int i = 0; i < temp.length; i++) {
            temp[i] = new Word();
        }
        
        for (int c = 0; c < Nb; c++) {
            
            // s'(0,c) = ({02} * s(0,c)) ^ ({03} * s(1,c)) ^ s(2,c) ^ s(3,c)
            temp[c].w[0] = (multiply((byte) 0x02, (byte) state[c].w[0])) ^ 
                           (multiply((byte) 0x03, (byte) state[c].w[1])) ^ 
                           (byte) state[c].w[2] ^ (byte) state[c].w[3];
                        
                        
            // s'(1,c) = s(0,c) ^ ({02} * s(1,c)) ^ ({03} * s(2,c)) ^ s(3,c)
            temp[c].w[1] = (byte) state[c].w[0] ^ 
                           (multiply((byte) 0x02, (byte) state[c].w[1])) ^ 
                           (multiply((byte) 0x03, (byte) state[c].w[2])) ^ 
                           (byte) state[c].w[3];
            
            // s'(2,c) = s(0,c) ^ s(1,c) ^ ({02} * s(2,c)) ^ ({03} * s(3,c))
            temp[c].w[2] = (byte) state[c].w[0] ^ 
                           (byte) state[c].w[1] ^
                           (multiply((byte) 0x02, (byte) state[c].w[2])) ^ 
                           (multiply((byte) 0x03, (byte) state[c].w[3]));
            
            // s'(3,c) = ({03} * s(0,c)) ^ s(1,c) ^ s(2,c) ^ ({02} * s(3,c)) 
            temp[c].w[3] = (multiply((byte) 0x03, (byte) state[c].w[0])) ^ 
                           (byte) state[c].w[1] ^ 
                           (byte) state[c].w[2] ^
                           (multiply((byte) 0x02, (byte) state[c].w[3]));

        }
        
        return temp;
    }
    
        // Inverse MixColumns
    public static Word[] invMixColumns(Word[] state){
        
        Word[] temp = new Word[4];
        // Initialize temp
        for (int i = 0; i < temp.length; i++) {
            temp[i] = new Word();
        }
        
        for (int c = 0; c < Nb; c++) {
            
            // s'(0,c) = ({0e} * s(0,c)) ^ ({0b} * s(1,c)) ^ ({0d} * s(2,c)) ^ ({09} *s(3,c))
            temp[c].w[0] = (multiply((byte) 0x0e, (byte) state[c].w[0])) ^ 
            		(multiply((byte) 0x0b, (byte) state[c].w[1])) ^ 
            		(multiply((byte) 0x0d, (byte) state[c].w[2])) ^ 
            		(multiply((byte) 0x09, (byte) state[c].w[3]));

            // s'(1,c) = ({09} * s(0,c)) ^ ({0e} * s(1,c)) ^ ({0b} * s(2,c)) ^ ({0d} *s(3,c))
            temp[c].w[1] = (multiply((byte) 0x09, (byte) state[c].w[0])) ^ 
            		(multiply((byte) 0x0e, (byte) state[c].w[1])) ^ 
            		(multiply((byte) 0x0b, (byte) state[c].w[2])) ^ 
            		(multiply((byte) 0x0d, (byte) state[c].w[3]));

            // s'(2,c) = ({0d} * s(0,c)) ^ ({09} * s(1,c)) ^ ({0e} * s(2,c)) ^ ({0b} *s(3,c))
            temp[c].w[2] = (multiply((byte) 0x0d, (byte) state[c].w[0])) ^ 
            		(multiply((byte) 0x09, (byte) state[c].w[1])) ^ 
            		(multiply((byte) 0x0e, (byte) state[c].w[2])) ^ 
            		(multiply((byte) 0x0b, (byte) state[c].w[3]));

            // s'(3,c) = ({0b} * s(0,c)) ^ ({0d} * s(1,c)) ^ ({09} * s(2,c)) ^ ({0e} *s(3,c))
            temp[c].w[3] = (multiply((byte) 0x0b, (byte) state[c].w[0])) ^ 
            		(multiply((byte) 0x0d, (byte) state[c].w[1])) ^ 
            		(multiply((byte) 0x09, (byte) state[c].w[2])) ^ 
            		(multiply((byte) 0x0e, (byte) state[c].w[3]));

        }
        return temp;
    }
    

    private static Word rotWord(Word w){
        return new Word(w.w[1], w.w[2], w.w[3], w.w[0]);
    }
    
    private static Word XOR(Word wordOne, Word wordTwo){
        // XOR'ing two words together. I think this is just
        // The addition Duc programmed earlier only with Words
        // not bytes. Might be
        // Able to remove one or the other
        Word temp = new Word();
        
        temp.w[0] = (byte) (wordOne.w[0] ^ wordTwo.w[0]);
        temp.w[1] = (byte) (wordOne.w[1] ^ wordTwo.w[1]);
        temp.w[2] = (byte) (wordOne.w[2] ^ wordTwo.w[2]);
        temp.w[3] = (byte) (wordOne.w[3] ^ wordTwo.w[3]);
        return temp; 
        
    }
    
    
    
    private static byte[] wordAddition(byte[] wordA, byte[] wordB){
    	// Definition: word = array of 4 bytes
    	
    	byte[] result = new byte[4];
    	result[0] = (byte) addition(wordA[0],wordB[0]);
    	result[1] = (byte) addition(wordA[1],wordB[1]);
    	result[2] = (byte) addition(wordA[2],wordB[2]);
    	result[3] = (byte) addition(wordA[3],wordB[3]);
    	
    	return result;
    }
    
    private static byte[] wordMultiplication(byte[] multiplicand, byte[] multiplier){
        // Byte arrays coming in should consist of 4 bytes
        // multiplicand == a && multiplier == b
        byte a3 = multiplicand[0];
        byte a2 = multiplicand[1];
        byte a1 = multiplicand[2];
        byte a0 = multiplicand[3];
        
        
        byte b3 = multiplier[0];
        byte b2 = multiplier[1];
        byte b1 = multiplier[2];
        byte b0 = multiplier[3];
  
        byte[] result = new byte[4];
        // d0
        result[3] = (byte) (multiply(a0, b0) ^ multiply(a3,b1) ^ multiply(a2,b2) ^ multiply(a1,b3));
        // d1
        result[2] = (byte) (multiply(a1, b0) ^ multiply(a0,b1) ^ multiply(a3,b2) ^ multiply(a2,b3));
        // d2
        result[1] = (byte) (multiply(a2, b0) ^ multiply(a1,b1) ^ multiply(a0,b2) ^ multiply(a3,b3));
        // d3
        result[0] = (byte) (multiply(a3, b0) ^ multiply(a2,b1) ^ multiply(a1,b2) ^ multiply(a0,b3));
        
        return result;
    }
    
    private static byte addition(byte a, byte b){
        
	    //result is XOR of a and b
	    byte result = (byte) (a ^ b);
	    return result;
    }
    
    private static byte multiply(byte multiplicand, byte multiplier) {

        // multiply implemented using xtime on all 8 bits
        return (byte) multiply(multiplicand, multiplier, 8);             
    }
    
    private static byte multiply(byte multiplicand, byte multiplier, int round) {
        // Almost a recursive function
        byte result = (byte) ((((multiplier) & 0x1) * (multiplicand)));
        for (int i = 1; i < round; i++) {
            result = (byte) (result ^ (((multiplier) >> i & 0x1) * xtime((multiplicand), i))); 
        }
        
        return (byte) result;
        
    }
    
    private static byte xtime(byte multiplicand){
        
        return (byte) ((multiplicand<<1) ^ (((multiplicand>>7) & 1) * 0x11b));
    }
    
    private static byte xtime(byte multiplicand, int round){
        // Might move to something fully recursive
        byte temp = multiplicand;
        for (int i = 0; i < round; i++) {
            temp = xtime(temp);
        }
        
        return temp;
    }
    
    public static void printByteArray(byte[] out) { 
        // Just to save space and look prettier
        String result = "";
        for (int i = 0; i < out.length; i++) {
            
            byte value = (byte) out[i];
            result = result + String.format("%02x", value);

            }
        System.out.println(result); 
    }
    
}



class Word{
    // Might make arrays of words easier to manage
    // Can add more functionality as needed.
    // Could also change word addition and multiplication 
    // To take words instead of byte arrays. 
    
    // Made this an array of ints so as to get around the whole 
    // unsigned int crap that was breaking subBytes
    int[] w;

    public Word(int zero, int one, int two, int three){
        w  = new int[4];
        
        w[0] = zero;
        w[1] = one;
        w[2] = two;
        w[3] = three;
    }
    
    public Word(){
        w  = new int[4];      
    }
    
    @Override
    public String toString(){
        String result = "";
        
        for (int i = 0; i < 4; i++) {
            
            byte value = (byte) w[i];
            result = result + String.format("%02x", value);

            }
        return result;
    }
}

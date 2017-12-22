//Created by Jordan Bare

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Scanner;

public class SRP6aClient {

    private final BigInteger modulus_N;
    private final BigInteger generator_g;
    private final BigInteger multiplier_k;
    private final BigInteger clientSecretEphemeralValue_a;
    private final BigInteger clientPublicKey_A;
    private String username_I;
    private String password_p;
    private BigInteger salt_s;
    private BigInteger serverPublicKey_B;
    private BigInteger scrambler_u;
    private BigInteger clientIdentityHash_x;
    private BigInteger clientSessionKey_S;
    private BigInteger clientInterleavedSessionKey_K;
    private BigInteger clientAuthenticationValue_M1;
    private BigInteger serverAuthenticationValue_M2;

    public SRP6aClient() {
        this.modulus_N = new BigInteger("115b8b692e0e045692cf280b436735c77a5a9e8a9e7ed56c965f87db5b2a2ece3", 16);
        this.generator_g = new BigInteger("" + 0x02, 10);
        this.multiplier_k = new BigInteger("2b2affa597a7acb88130201e752cd0f0e3d2627280aa04b332a3375d144940104e69878242ec0c6c9acf5fa52ad3645b", 16);

        // a
        clientSecretEphemeralValue_a = new BigInteger(128, new SecureRandom());
        // A = g^a (mod N)
        clientPublicKey_A = this.generator_g.modPow(clientSecretEphemeralValue_a, this.modulus_N);
        System.out.println("clientPublicKey_A: " + clientPublicKey_A);
    }

    public void setUsername_IAndPassword_p(){
        Scanner reader = new Scanner(System.in);
        System.out.println("Please enter your username for the client: ");
        String username_I = reader.next();
        System.out.println("Please enter your password for the client: ");
        String password_p = reader.next();

        this.username_I = username_I;
        this.password_p = password_p;
    }

    public String getUsername_I() {
        return username_I;
    }

    public BigInteger getClientPublicKey_A() {
        return clientPublicKey_A;
    }

    public void setSalt(BigInteger salt){
        this.salt_s = salt;
    }
    public void setServerPublicKey_B(BigInteger serverPublicKey_B) {
        this.serverPublicKey_B = serverPublicKey_B;
    }
    public void calculateScramblerBits(){
        scrambler_u = new BigInteger(hashBytes(clientPublicKey_A.toByteArray(), serverPublicKey_B.toByteArray()));
        System.out.println("Client scrambler_u: " + scrambler_u);
    }

    public void calculateClientIdentityHash(){
        // x = H(s|H(I|:|p))
        clientIdentityHash_x = bytesToBig(hashBytes(bigToByteArray(salt_s), hashBytes(new String(username_I + ":" + password_p).getBytes())));
        System.out.println("clientIdentityHash_x: " + clientIdentityHash_x);
    }

    public Boolean checkIfBModNIsNotZero(){
        if(serverPublicKey_B.mod(modulus_N).compareTo(BigInteger.valueOf(0)) != 0){
            return true;
        }
        System.out.println("PublicKey_B modulus mod_N is zero.");
        return false;
    }

    public Boolean checkIfScramblerIsNotZero(){
        if(scrambler_u.compareTo(BigInteger.valueOf(0)) != 0){
            return true;
        }
        System.out.println("Client's scrambler_u is zero.");
        return false;
    }

    public void calculateClientSessionKey_S(){
        // S = (B - kg^x)^(a + ux)
        // K = H(S)
        BigInteger temp = clientSecretEphemeralValue_a.add(scrambler_u.multiply(clientIdentityHash_x));
        clientSessionKey_S = serverPublicKey_B.subtract((generator_g.modPow(clientIdentityHash_x, modulus_N)).multiply(multiplier_k)).modPow(temp, modulus_N);
        System.out.println("clientSessionKey_S: " + clientSessionKey_S);
    }
    public void calculateClientInterleavedSessionKey_K(){

        byte[] clientSessionKey_S_Bytes = bigToByteArray(clientSessionKey_S);
        while(clientSessionKey_S_Bytes[0] == 0){
            byte[] tmp = new byte[clientSessionKey_S_Bytes.length - 1];
            System.arraycopy(clientSessionKey_S_Bytes, 1, tmp, 0, tmp.length);
            clientSessionKey_S_Bytes = tmp;
        }
        if((clientSessionKey_S_Bytes.length % 2) != 0){
            byte[] tmp = new byte[clientSessionKey_S_Bytes.length - 1];
            System.arraycopy(clientSessionKey_S_Bytes, 1, tmp, 0, tmp.length);
            clientSessionKey_S_Bytes = tmp;
        }
        System.out.println("Byte # of clientSessionKey_S: " + clientSessionKey_S_Bytes.length);
        /*
        E is evens; F is odds.
        E = T[0] | T[2] | T[4] | ...
        F = T[1] | T[3] | T[5] | ...
        */
        int halfSessionKeyLength = clientSessionKey_S_Bytes.length / 2;
        byte[] byteArrayE = new byte[halfSessionKeyLength];
        byte[] byteArrayF = new byte[halfSessionKeyLength];
        int evenByteArrayIndex = 0;
        int oddByteArrayIndex = 0;

        for(int i = 0; i < clientSessionKey_S_Bytes.length; i++){
            if((i % 2) == 0){
                byteArrayE[evenByteArrayIndex] = clientSessionKey_S_Bytes[i];
                evenByteArrayIndex++;
            }
            else {
                byteArrayF[oddByteArrayIndex] = clientSessionKey_S_Bytes[i];
                oddByteArrayIndex++;
            }
        }

        // interleavedByteArray_K = G[0] | H[0] | G[1] | H[1] | ...
        byte[] byteArrayG = hashBytes(byteArrayE);
        byte[] byteArrayH = hashBytes(byteArrayF);
        int interleavedByteArraySize = byteArrayG.length + byteArrayH.length;
        byte[] interleavedByteArray_K = new byte[interleavedByteArraySize];
        int arrayGIndex = 0;
        int arrayHIndex = 0;
        for(int i = 0; i < interleavedByteArraySize; i++){
            if((i % 2) == 0){
                interleavedByteArray_K[i] = byteArrayG[arrayGIndex];
                arrayGIndex++;
            }
            else {
                interleavedByteArray_K[i] = byteArrayH[arrayHIndex];
                arrayHIndex++;
            }
        }
        clientInterleavedSessionKey_K = new BigInteger(interleavedByteArray_K);
        System.out.println("clientInterleavedSessionKey_K: " + clientInterleavedSessionKey_K);
    }

    public void calculateClientAuthenticationValueMForServer() throws NoSuchAlgorithmException {
        // M1 = H(H(N) XOR H(g) | H(u) | s | A | B | K)
        clientAuthenticationValue_M1 = new BigInteger(hashBytes(bigToByteArray(new BigInteger(hashBytes(bigToByteArray(modulus_N))).xor(new BigInteger(hashBytes(bigToByteArray(generator_g))))),
                hashBytes(username_I.getBytes()), bigToByteArray(salt_s), bigToByteArray(clientPublicKey_A), bigToByteArray(serverPublicKey_B), bigToByteArray(clientInterleavedSessionKey_K)));
        System.out.println("Client Auth. M1 for Server: " + clientAuthenticationValue_M1);
    }

    public BigInteger getClientAuthenticationValueMForServer() {
        return clientAuthenticationValue_M1;
    }

    public void calculateAuthMMatchingServerAuthM() throws NoSuchAlgorithmException {
        // M2 = H(A|M|K)
        serverAuthenticationValue_M2 = new BigInteger(hashBytes(bigToByteArray(clientPublicKey_A),
                bigToByteArray(clientAuthenticationValue_M1), bigToByteArray(clientInterleavedSessionKey_K)));
        System.out.println("Client Auth. M2: " + serverAuthenticationValue_M2);
    }

    public Boolean checkIfServerAuthenticatorMValueMatchesServerAuthenticatorValueM(BigInteger authenticationMValueFromServer){
        if(authenticationMValueFromServer.equals(serverAuthenticationValue_M2)){
            System.out.println("Client has confirmed that Server's Authenticator M2 response matches Client's!");
            return true;
        }
        else {
            System.out.println("Client has determined that Client and Server Authenticator M2 values do NOT match.");
            return false;
        }
    }

    private static byte[] bigToByteArray(BigInteger bigInt) {
        return bigInt.toByteArray();
    }

    private BigInteger bytesToBig(byte[] byteArray) {
        return new BigInteger(bytesToHex(byteArray), 16);
    }

    private String bytesToHex(byte[] byteArray) {
        if (byteArray == null) {
            return "";
        }
        final StringBuilder builder = new StringBuilder();
        for (byte b : byteArray) {
            builder.append(String.format("%02x", b));
        }
        return builder.toString();
    }

    private byte[] hashBytes(byte[] input1) {
        return hashBytes(input1, null);
    }
    private static byte[] hashBytes(byte[] input1, byte[] input2) {
        try {
            MessageDigest sha = MessageDigest.getInstance("SHA-384");
            sha.update(input1);
            if (input2 != null){
                sha.update(input2);
            }
            return sha.digest();
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }
    private byte[] hashBytes(byte[] input1, byte[] input2, byte[] input3, byte[] input4, byte[] input5, byte[] input6) throws NoSuchAlgorithmException {
        MessageDigest sha = MessageDigest.getInstance("SHA-384");
        sha.update(input1);
        sha.update(input2);
        sha.update(input3);
        sha.update(input4);
        sha.update(input5);
        sha.update(input6);
        return sha.digest();
    }

    private byte[] hashBytes(byte[] input1, byte[] input2, byte[] input3) throws NoSuchAlgorithmException {
        MessageDigest sha = MessageDigest.getInstance("SHA-384");
        sha.update(input1);
        sha.update(input2);
        sha.update(input3);
        return sha.digest();
    }
}

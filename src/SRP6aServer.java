//Created by Jordan Bare

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Scanner;

public class SRP6aServer {

    private final BigInteger modulus_N;
    private final BigInteger generator_g;
    private final BigInteger multiplier_k;
    private final BigInteger salt_s;
    private String username_I;
    private String password_p;
    private BigInteger serverIdentityHash_x;
    private BigInteger serverPasswordVerifier_v;
    private BigInteger serverSecretEphemeralValue_b;
    private BigInteger serverPublicKey_B;
    private BigInteger clientPublicKey_A;
    private BigInteger scrambler_u;
    private BigInteger serverSessionKey_S;
    private BigInteger serverInterleavedSessionKey_K;
    private BigInteger clientAuthenticationValue_M1;
    private BigInteger serverAuthenticationValue_M2;

    public SRP6aServer() {
        this.modulus_N = new BigInteger("115b8b692e0e045692cf280b436735c77a5a9e8a9e7ed56c965f87db5b2a2ece3", 16);
        this.generator_g = new BigInteger("" + 0x02, 10);
        this.multiplier_k = new BigInteger("2b2affa597a7acb88130201e752cd0f0e3d2627280aa04b332a3375d144940104e69878242ec0c6c9acf5fa52ad3645b", 16);
        this.salt_s = new BigInteger(256, new SecureRandom());
    }

    public void setUsername_IAndPassword_p(String username_I) {
        this.username_I = username_I;
        Scanner reader = new Scanner(System.in);
        System.out.println("Please enter the password associated with username " + username_I +
                " for the server: ");
        this.password_p = reader.next();

        calculateServerPublicKey_B();
    }

    public void calculateServerPublicKey_B(){
        // x = H(s|H(I|:|p))
        this.serverIdentityHash_x = bytesToBig(hashBytes(salt_s.toByteArray(), hashBytes(new String(this.username_I + ":" + this.password_p).getBytes())));
        System.out.println("serverIdentityHash_x: " + serverIdentityHash_x);
        // v = g^x
        this.serverPasswordVerifier_v = this.generator_g.modPow(serverIdentityHash_x, this.modulus_N);
        // b
        this.serverSecretEphemeralValue_b = new BigInteger(128, new SecureRandom());
        // B = kv + g^b (mod N)
        this.serverPublicKey_B = this.multiplier_k.multiply(serverPasswordVerifier_v).add(this.generator_g.modPow(serverSecretEphemeralValue_b, this.modulus_N));
        System.out.println("serverPublicKey_B: " + serverPublicKey_B);
    }

    public void setClientPublicKey_A(BigInteger clientPublicKey_A) {
        this.clientPublicKey_A = clientPublicKey_A;
    }

    public BigInteger getSalt_s() {
        return salt_s;
    }

    public BigInteger getServerPublicKey_B() {
        return serverPublicKey_B;
    }

    public void calculateScramblerBits(){
        // u = H(A,B)
        scrambler_u = new BigInteger(hashBytes(clientPublicKey_A.toByteArray(), serverPublicKey_B.toByteArray()));
        System.out.println("Server scrambler_u: " + scrambler_u);
    }

    public Boolean checkIfAModNIsNotZero(){
        if(clientPublicKey_A.mod(modulus_N).compareTo(BigInteger.valueOf(0)) != 0){
            return true;
        }
        System.out.println("PublicKey_A modulus mod_N is zero.");
        return false;
    }
    public void calculateServerSessionKey_S(){
        // S = (Av^u) ^ b (mod N)
        // K = H(S)
        serverSessionKey_S = clientPublicKey_A.multiply(serverPasswordVerifier_v.modPow(scrambler_u, modulus_N)).modPow(serverSecretEphemeralValue_b, modulus_N);
        System.out.println("serverSessionKey_S: " + serverSessionKey_S);
    }
    public void calculateServerInterleavedSessionKey_K(){
        byte[] serverSessionKey_S_Bytes = bigToByteArray(serverSessionKey_S);
        while(serverSessionKey_S_Bytes[0] == 0){
            byte[] tmp = new byte[serverSessionKey_S_Bytes.length - 1];
            System.arraycopy(serverSessionKey_S_Bytes, 1, tmp, 0, tmp.length);
            serverSessionKey_S_Bytes = tmp;
        }
        if((serverSessionKey_S_Bytes.length % 2) != 0){
            byte[] tmp = new byte[serverSessionKey_S_Bytes.length - 1];
            System.arraycopy(serverSessionKey_S_Bytes, 1, tmp, 0, tmp.length);
            serverSessionKey_S_Bytes = tmp;
        }
        System.out.println("Byte # of serverSessionKey_S: " + serverSessionKey_S_Bytes.length);
        /*
        E is evens; F is odds.
        E = T[0] | T[2] | T[4] | ...
        F = T[1] | T[3] | T[5] | ...
        */
        int halfSessionKeyLength = serverSessionKey_S_Bytes.length / 2;
        byte[] byteArrayE = new byte[halfSessionKeyLength];
        byte[] byteArrayF = new byte[halfSessionKeyLength];
        int evenByteArrayIndex = 0;
        int oddByteArrayIndex = 0;

        for(int i = 0; i < serverSessionKey_S_Bytes.length; i++){
            if((i % 2) == 0){
                byteArrayE[evenByteArrayIndex] = serverSessionKey_S_Bytes[i];
                evenByteArrayIndex++;
            }
            else {
                byteArrayF[oddByteArrayIndex] = serverSessionKey_S_Bytes[i];
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
        serverInterleavedSessionKey_K = new BigInteger(interleavedByteArray_K);
        System.out.println("serverInterleavedSessionKey_K: " + serverInterleavedSessionKey_K);
    }


    public void calculateAuthMMatchingClientAuthM() throws NoSuchAlgorithmException {
        // M1 = H(H(N) XOR H(g) | H(u) | s | A | B | K)
        clientAuthenticationValue_M1 = new BigInteger(hashBytes(bigToByteArray(new BigInteger(hashBytes(bigToByteArray(modulus_N))).xor(new BigInteger(hashBytes(bigToByteArray(generator_g))))),
                hashBytes(username_I.getBytes()), bigToByteArray(salt_s), bigToByteArray(clientPublicKey_A), bigToByteArray(serverPublicKey_B), bigToByteArray(serverInterleavedSessionKey_K)));
        System.out.println("Server Auth. M1: " + clientAuthenticationValue_M1);
    }

    public void calculateServerAuthenticationValueForClient() throws NoSuchAlgorithmException {
        // M2 = H(A|M|K)
        serverAuthenticationValue_M2 = new BigInteger(hashBytes(bigToByteArray(clientPublicKey_A),
                bigToByteArray(clientAuthenticationValue_M1), bigToByteArray(serverInterleavedSessionKey_K), null, null, null));
        System.out.println("Server Auth. M2 for Client: " + serverAuthenticationValue_M2);
    }
    public BigInteger getServerAuthenticationValue_M(){
        return serverAuthenticationValue_M2;
    }

    public boolean checkIfClientAuthenticatorMValueMatchesServerAuthenticatorValueM(BigInteger authenticationMValueFromClient) {

        if(authenticationMValueFromClient.equals(clientAuthenticationValue_M1)){
            System.out.println("Server has confirmed that Client's Authenticator M1 response matches Server's!");
            return true;
        }
        System.out.println("Server has determined that Client and Server Authenticator M1 values do NOT match.");
        return false;
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
        if(input4 != null){
            sha.update(input4);
            sha.update(input5);
            sha.update(input6);
        }
        return sha.digest();
    }



}

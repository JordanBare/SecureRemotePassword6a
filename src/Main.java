
/*
Created by Jordan Bare

This information is taken directly from http://srp.stanford.edu/design.html.
The program is my work, but the proofs belong to Tom Wu. This program is a
Java implementation I made in order to possibly integrate into one of my
projects. This program might need the Java Cryptography Extension (JCE) offered at
http://www.oracle.com/technetwork/java/javase/downloads/jce8-download-2133166.html
for using SHA-384.

The following is a description of SRP-6 and 6a, the latest versions of SRP:

  N    A large safe prime (N = 2q+1, where q is prime)
       All arithmetic is done modulo N.
  g    A generator modulo N
  k    Multiplier parameter (k = H(N, g) in SRP-6a, k = 3 for legacy SRP-6)
  s    User's salt
  I    Username
  p    Cleartext Password
  H()  One-way hash function
  ^    (Modular) Exponentiation
  u    Random scrambling parameter
  a,b  Secret ephemeral values
  A,B  Public ephemeral values
  x    Private key (derived from p and s)
  v    Password verifier
The host stores passwords using the following formula:
  x = H(s, p)               (s is chosen randomly)
  v = g^x                   (computes password verifier)
The host then keeps {I, s, v} in its password database. The authentication protocol itself goes as follows:
User -> Host:  I, A = g^a                  (identifies self, a = random number)
Host -> User:  s, B = kv + g^b             (sends salt, b = random number)

        Both:  u = H(A, B)

        User:  x = H(s, p)                 (user enters password)
        User:  S = (B - kg^x) ^ (a + ux)   (computes session key)
        User:  K = H(S)

        Host:  S = (Av^u) ^ b              (computes session key)
        Host:  K = H(S)
Now the two parties have a shared, strong session key K. To complete authentication, they need to prove to each other that their keys match. One possible way:
User -> Host:  M = H(H(N) xor H(g), H(I), s, A, B, K) (Host confirms M = H(H(N) xor H(g), H(I), s, A, B, K))
Host -> User:  H(A, M, K) (User confirms H(A, M, K))
The two parties also employ the following safeguards:
The user will abort if he receives B == 0 (mod N) or u == 0.
The host will abort if it detects that A == 0 (mod N).
The user must show his proof of K first. If the server detects that the user's proof is incorrect, it must abort without showing its own proof of K.
*/

import java.security.NoSuchAlgorithmException;

public class Main {

    public static void main(String[] args) throws NoSuchAlgorithmException {
        SRP6aAuthenticationProcess process = new SRP6aAuthenticationProcess();
        process.execute();
    }
}

//Created by Jordan Bare

import java.security.NoSuchAlgorithmException;

public class SRP6aAuthenticationProcess {

    public void execute() throws NoSuchAlgorithmException {
        //Simulates the client
        SRP6aClient client = new SRP6aClient();
        //Simulates the server
        SRP6aServer server = new SRP6aServer();

        //Client enters username and password
        client.setUsername_IAndPassword_p();

        //Server receives username from Client and retrieves password (hardcoded in this case)
        server.setUsername_IAndPassword_p(client.getUsername_I());

        //Server receives Client's PublicKey_A
        server.setClientPublicKey_A(client.getClientPublicKey_A());
        //Client receives Server's salt_s
        client.setSalt(server.getSalt_s());
        //Client receives Server's PublicKey_B
        client.setServerPublicKey_B(server.getServerPublicKey_B());
        // Both the Client and Server calculate their scramblerbits_u
        client.calculateScramblerBits();
        server.calculateScramblerBits();

        /*
        If the scrambler_u the Client calculates is zero, the connection attempt is terminated.
        If the Client's calculation of publicKey_B modulus modulus_N is zero, the connection attempt is terminated.
        If the Server's calculation of publicKey_A modulus modulus_N is zero, the connection attempt is terminated.
        */
        if(client.checkIfScramblerIsNotZero() && client.checkIfBModNIsNotZero() && server.checkIfAModNIsNotZero()){

            //Both the Client and Server calculate their interleavedSessionKey_K's.
            client.calculateClientIdentityHash();
            client.calculateClientSessionKey_S();
            client.calculateClientInterleavedSessionKey_K();

            server.calculateServerSessionKey_S();
            server.calculateServerInterleavedSessionKey_K();

            /*
              Client calculates its Authenticator M value for Server.
              Then, it sends this value to Server for evaluation.
              Server receive this value from Client and calculates its own
              Authenticator M value to see if they match. If they do,
              Server calculates the Authenticator M response and sends it
              to Client. Once Client receives this value, it calculates
              an Authenticator M that is supposed to match the one sent by
              Server. If they match, authentication is successful between
              Client and Server.
            */
            client.calculateClientAuthenticationValueMForServer();
            server.calculateAuthMMatchingClientAuthM();
            if(server.checkIfClientAuthenticatorMValueMatchesServerAuthenticatorValueM(client.getClientAuthenticationValueMForServer())){
                server.calculateServerAuthenticationValueForClient();
                client.calculateAuthMMatchingServerAuthM();
                if(client.checkIfServerAuthenticatorMValueMatchesServerAuthenticatorValueM(server.getServerAuthenticationValue_M())){
                    System.out.println("\nAuthentication Successful!");
                }
                else {
                    System.out.println("Authentication failed when Client attempted to authenticate Server.");
                }
            }
            else {
                System.out.println("Authentication failed when Server attempted to authenticate Client.");
            }
        }
    }
}

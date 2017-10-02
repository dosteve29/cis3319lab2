import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

public class Server {
    public static void main(String args[]) throws IOException, NoSuchAlgorithmException {
        ServerSocket serverSocket = new ServerSocket(6666); //create server
        Socket socket = serverSocket.accept(); //establish connection

        //Send key
        SecretKey key = sendKey(socket);
        //Send message and HMAC to receiving end
        sendMessage(socket, key);

        //close connection and server
        socket.close();
        serverSocket.close();
    }

    private static SecretKey sendKey(Socket socket) throws NoSuchAlgorithmException, IOException {
        DataOutputStream dataOutputStream = new DataOutputStream(socket.getOutputStream());

        SecretKey key = KeyGenerator.getInstance("HmacSHA1").generateKey();

        String encodedKey = Base64.getEncoder().encodeToString(key.getEncoded());
        System.out.println("Sent Key = " + encodedKey);

        dataOutputStream.writeUTF(encodedKey);

        return key;
    }

    private static void sendMessage(Socket socket, SecretKey key){
        try {
            //Message being sent
            String message = "Hello Client. This is the Server.";

            // Hash-based Message Authentication Code is created by hashing the message using
            // the SHA-1 hashing algorithm and key
            Mac mac = Mac.getInstance("HmacSHA1"); //SHA-1 Algorithm
            mac.init(key); //key

            //This HMAC must be verified by the receiver to ensure authentication and integrity
            byte[] hmac = mac.doFinal(message.getBytes());

            //Send the message first
            DataOutputStream dataOutputStream = new DataOutputStream(socket.getOutputStream());
            dataOutputStream.writeUTF(message);

            System.out.println("Sent message: " + message);

            //Send the HMAC second
            ObjectOutputStream objectOutputStream = new ObjectOutputStream(socket.getOutputStream());
            objectOutputStream.writeObject(hmac);

        } catch (NoSuchAlgorithmException | InvalidKeyException | IOException e) {
            e.printStackTrace();
        }
    }
}

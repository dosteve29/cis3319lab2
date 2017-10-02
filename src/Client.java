import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.net.Socket;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Base64;

public class Client {
    public static void main(String[] args) throws IOException, ClassNotFoundException {
        Socket socket = new Socket("localhost", 6666);

        SecretKey key = receiveKey(socket);
        receiveMessage(socket, key);

        socket.close();
    }

    private static SecretKey receiveKey(Socket socket) throws IOException, ClassNotFoundException {
        DataInputStream dataInputStream = new DataInputStream(socket.getInputStream());

        String encodedKey = dataInputStream.readUTF();
        System.out.println("Received Key = " + encodedKey);
        byte[] decodedKey = Base64.getDecoder().decode(encodedKey);

        return new SecretKeySpec(decodedKey, 0, decodedKey.length, "HmacSHA1");
    }

    private static void receiveMessage(Socket socket, SecretKey key) {
        try {
            //Receive the message first
            DataInputStream dataInputStream = new DataInputStream(socket.getInputStream());
            String message = dataInputStream.readUTF();
            System.out.println("Received message: " + message);

            //Receive the HMAC second
            ObjectInputStream objectInputStream = new ObjectInputStream(socket.getInputStream());
            byte[] hmac = (byte[]) objectInputStream.readObject();
            if (checkHMAC(key, hmac, message)){
                System.out.println("HMAC Confirmed.");
                System.out.println("Here is the message: " + message);
            }
            else{
                System.out.println("There is an error");
            }
        } catch (IOException | ClassNotFoundException | NoSuchAlgorithmException | InvalidKeyException e) {
            e.printStackTrace();
        }
    }

    private static boolean checkHMAC(SecretKey key, byte[] receivedHMAC, String receivedMessage) throws NoSuchAlgorithmException, InvalidKeyException {
        //Generate HMAC from receiving end
        Mac mac = Mac.getInstance("HmacSHA1");
        mac.init(key);
        byte[] generatedHMAC = mac.doFinal(receivedMessage.getBytes());
        return Arrays.equals(generatedHMAC, receivedHMAC);
    }
}

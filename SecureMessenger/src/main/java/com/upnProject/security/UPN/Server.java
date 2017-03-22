package com.upnProject.security.UPN;

import java.net.ServerSocket;
import java.net.Socket;
import java.security.PublicKey;
import javax.crypto.Cipher;
import java.io.*;

public class Server {
	private ServerSocket serverSocket = null;
	private static Socket socket = null;
	private static ObjectInputStream inputStream = null;
	private FileEvent fileEvent;
	private File dstFile = null;
	private FileOutputStream fileOutputStream = null;
	
	public static final String ALGORITHM = "RSA";
	
	public static final String PUBLIC_KEY_FILE = "C:/ServerKeys/publicClient.key";
	
	public static boolean initializationFlagOfServer = true;
	
	public static String symmetricKey="";
	
	public Server() {
	
	}

	public void doConnect() {
		try {
			serverSocket = new ServerSocket(4445);
			socket = serverSocket.accept();
			inputStream = new ObjectInputStream(socket.getInputStream());
		} catch (IOException e) {
			e.printStackTrace();
		}
	}
	
	public void downloadFile() {
		try {
			fileEvent = (FileEvent) inputStream.readObject();
			if (fileEvent.getStatus().equalsIgnoreCase("Error")) {
			System.out.println("Error occurred ..So exiting");
			System.exit(0);
			}
			String outputFile = fileEvent.getDestinationDirectory() + fileEvent.getFilename();
			if (!new File(fileEvent.getDestinationDirectory()).exists()) {
			new File(fileEvent.getDestinationDirectory()).mkdirs();
			}
			dstFile = new File(outputFile);
			fileOutputStream = new FileOutputStream(dstFile);
			fileOutputStream.write(fileEvent.getFileData());
			fileOutputStream.flush();
			fileOutputStream.close();
			System.out.println("Output file : " + outputFile + " is successfully saved ");
		} 
		catch (IOException e) {
			e.printStackTrace();
		} 
		catch (ClassNotFoundException e) {
			e.printStackTrace();
		} 
	}
	
	public static void main(String[] args) throws IOException, ClassNotFoundException {
		EncryptionUtil.generateKey();
		
		Server server = new Server();
		server.doConnect();
		server.downloadFile();
		
		String clientGelen;
        ServerSocket serverSocket = null;
        Socket clientSocket = null;

        try {
        	serverSocket = new ServerSocket(7755);
        } 
        catch (Exception e) {
        	System.out.println("Port Hatası!");
        }
        System.out.println("SERVER NEEDS INITIALIZATION...");
        
        clientSocket = serverSocket.accept();

        PrintWriter out = new PrintWriter(clientSocket.getOutputStream(), true);

        BufferedReader in = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));
             
        while((clientGelen = in.readLine()) != null && initializationFlagOfServer) {
             System.out.println("Client'dan gelen veri = " + clientGelen);
             // Encrypt the string using the public key
             symmetricKey = "OHgREAT!";
             inputStream = new ObjectInputStream(new FileInputStream(PUBLIC_KEY_FILE));
             final PublicKey publicKey = (PublicKey) inputStream.readObject();
             final byte[] cipherText = EncryptionUtil.encrypt(symmetricKey, publicKey);
             sendBytes(cipherText);
             initializationFlagOfServer = false;
        }
        System.out.println("INITIALIZATION COMPLETED...");
                
        out.close();
        in.close();
        clientSocket.close();
        serverSocket.close();
               
        try {
        	serverSocket = new ServerSocket(7760);
        } 
        catch (Exception e) {
        	System.out.println("Port Hatası!");
        }
        System.out.println("SERVER IS READY!");
        
        clientSocket = serverSocket.accept();

        out = new PrintWriter(clientSocket.getOutputStream(), true);

        in = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));
        
        while((clientGelen = in.readLine()) != null) {
            System.out.println("\nClient'dan gelen veri(encrypted with AES) = " + clientGelen);  
            clientGelen = AES.decrypt(clientGelen, symmetricKey) ;
            System.out.println("Client'dan gelen veri(decrypted) = " + clientGelen); 
            clientGelen = clientGelen + "-FROM SERVER";
            System.out.println("Client'a gonderilen veri = " + clientGelen); 
            clientGelen = AES.encrypt(clientGelen, symmetricKey) ;
            System.out.println("Client'a gonderilen veri(encrypted with AES) = " + clientGelen); 
            out.println(clientGelen);
       }
        
       out.close();
       in.close();
       clientSocket.close();
       serverSocket.close();
        
	}
	
	public static void sendBytes(byte[] myByteArray) throws IOException {
	    sendBytes(myByteArray, 0, myByteArray.length);
	}

	public static void sendBytes(byte[] myByteArray, int start, int len) throws IOException {
	    if (len < 0)
	        throw new IllegalArgumentException("Negative length not allowed");
	    if (start < 0 || start >= myByteArray.length)
	        throw new IndexOutOfBoundsException("Out of bounds: " + start);
	    
	    OutputStream out = socket.getOutputStream(); 
	    DataOutputStream dos = new DataOutputStream(out);

	    dos.writeInt(len);
	    if (len > 0) {
	        dos.write(myByteArray, start, len);
	    }
	}
}
package com.upnProject.security.UPN;
import java.io.*;
import java.net.*;
import java.security.PrivateKey;

import javax.crypto.Cipher;

public class Client {
	private static Socket socket = null;
	private ObjectOutputStream outputStream = null;
	private boolean isConnected = false;
	private String sourceFilePath = "c:/ClientKeys/publicClient.key";
	private FileEvent fileEvent = null;
	private String destinationPath = "C:/ServerKeys/";
	public static final String ALGORITHM = "RSA";
	public static final String PRIVATE_KEY_FILE = "c:/ClientKeys/privateClient.key";
	public static boolean initializationFlag = true;
	public static String symmetricKey="";
	public static String plainText = "";
	public Client() {
	
	}
	
	public void connect() {
		while (!isConnected) {
			try {
				socket = new Socket("localHost", 4445);
				outputStream = new ObjectOutputStream(socket.getOutputStream());
				isConnected = true;
			} 
			catch (IOException e) {
				e.printStackTrace();
			}
		}
	}
	
	public void sendFile() throws ClassNotFoundException {
		fileEvent = new FileEvent();
		String fileName = sourceFilePath.substring(sourceFilePath.lastIndexOf("/") + 1, sourceFilePath.length());
		fileEvent.setDestinationDirectory(destinationPath);
		fileEvent.setFilename(fileName);
		fileEvent.setSourceDirectory(sourceFilePath);
		File file = new File(sourceFilePath);
		if (file.isFile()) {
			try {
				@SuppressWarnings("resource")
				DataInputStream diStream = new DataInputStream(new FileInputStream(file));
				long len = (int) file.length();
				byte[] fileBytes = new byte[(int) len];
				int read = 0;
				int numRead = 0;
				while (read < fileBytes.length && (numRead = diStream.read(fileBytes, read, fileBytes.length - read)) >= 0) {
					read = read + numRead;
				}
				fileEvent.setFileSize(len);
				fileEvent.setFileData(fileBytes);
				fileEvent.setStatus("Success");
			} 
			catch (Exception e) {
				e.printStackTrace();
				fileEvent.setStatus("Error");
			}
		} 
		
		else {
			System.out.println("path specified is not pointing to a file");
			fileEvent.setStatus("Error");
		}

		try {
			outputStream.writeObject(fileEvent);
			Thread.sleep(3000);
			islem();
		} 
		catch (IOException e) {
			e.printStackTrace();
		} 
		catch (InterruptedException e) {
			e.printStackTrace();
		}		
	}
	
	public static void main(String[] args) throws IOException, ClassNotFoundException {
		Client client = new Client();
		client.connect();
		client.sendFile();
	}
	
	@SuppressWarnings("resource")
	public static void islem() throws UnknownHostException, IOException, ClassNotFoundException {
        Socket socket = null;
        PrintWriter out = null;
        try {
             socket = new Socket("localhost", 7755);
        } 
        catch (Exception e) {
             System.out.println("Port Hatası!");
        }
        out = new PrintWriter(socket.getOutputStream(), true);
        
        while (initializationFlag) {
        	 out.println("initializationFlag");
	        // Decrypt the cipher text using the private key.
	        ObjectInputStream inputStream = null;
	        inputStream = new ObjectInputStream(new FileInputStream(PRIVATE_KEY_FILE));
	        final PrivateKey privateKey = (PrivateKey) inputStream.readObject();             
	        byte[] a = readBytes();
	        String gelen=a.toString();
	        System.out.println("Symmetric key(encrypted with RSA)): " + gelen);
	        plainText = EncryptionUtil.decrypt(a, privateKey);
	        System.out.println("Symmetric key" + plainText);
	        initializationFlag = false;
        }               
        
        out.close();
        socket.close();
        
        symmetricKey = plainText;
        
        /*String originalString = "howtodoinjava.com";
	    String encryptedString = AES.encrypt(originalString, symmetricKey) ;
	    String decryptedString = AES.decrypt(encryptedString, symmetricKey) ;
	     
	    System.out.println(originalString);
	    System.out.println(encryptedString);
	    System.out.println(decryptedString);*/
	    
        BufferedReader in = null;
        String deger, yanit;
        try {
             socket = new Socket("localhost", 7760);
        } catch (Exception e) {
             System.out.println("Port Hatası!");
        }
	            
        out = new PrintWriter(socket.getOutputStream(), true);
        
        in = new BufferedReader(new InputStreamReader(socket.getInputStream()));

        System.out.println("Server'a gönderilecek mesajı giriniz:");

        BufferedReader data = new BufferedReader(new InputStreamReader(System.in));

        while((deger = data.readLine()) != null) {
        	 System.out.println("Server'a gonderilen veri = " + deger);
        	 deger = AES.encrypt(deger, symmetricKey);
        	 System.out.println("Server'a gonderilen veri(encrypted with AES) = " + deger);
             out.println(deger);
             yanit = in.readLine();
             System.out.println("Server'dan gelen yanıt(encrypted with AES) = " + yanit);
             yanit = AES.decrypt(yanit, symmetricKey);
             System.out.println("Server'dan gelen yanıt(decrypted) = " + yanit);
             System.out.println("\nServer'a gönderilecek mesajı giriniz:");
        }
        
        out.close();
        in.close();
        data.close();
        socket.close();
   }
	
	public static byte[] readBytes() throws IOException {
	    InputStream in = socket.getInputStream();
	    DataInputStream dis = new DataInputStream(in);
	    int len = dis.readInt();
	    byte[] data = new byte[len];
	    if (len > 0) {
	        dis.readFully(data);
	    }
	    return data;
	}
	
}
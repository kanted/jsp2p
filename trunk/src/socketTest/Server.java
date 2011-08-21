package socketTest;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.ServerSocket;
import java.net.Socket;

public class Server {

	private static int byteArrayToInt(byte[] b) { //TODO funzioncina di prova, poi farla seria
		int value = 0;
		for (int i = 0; i < b.length; i++) {
			value += b[i] * Math.pow(2, i);
		}
		return value / 8;
	}

	static Socket mySocket;

	public static void main(String[] args) throws IOException {
		System.out.println("SERVER");
		ServerSocket server = new ServerSocket(8080);
		mySocket = server.accept();
		InputStream in = mySocket.getInputStream();
		OutputStream out = mySocket.getOutputStream();
		byte[] lengthBytes = new byte[128];
		in.read(lengthBytes);
		int length = byteArrayToInt(lengthBytes);
		System.out.println("SERVER HA LETTO LENGTH "+length);
		byte[] b = new byte[length];
		in.read(b);
		System.out.println("SERVER HA LETTO");
		String app = new String(b);
		System.out.println(app);
		byte[] arg0 = "prova".getBytes();
		length = arg0.length;
		out.write(length);
		out.write(arg0);
		System.out.println("SERVER FINE");
	}
}

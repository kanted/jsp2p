package socketTest;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;

public class Client {

	private static int byteArrayToInt(byte[] b) { //TODO funzioncina di prova, poi farla seria
		int value = 0;
		for (int i = 0; i < b.length; i++) {
			value += b[i] * Math.pow(2, i);
		}
		return value / 8;
	}

	static Socket clientSocket;

	public static void main(String[] args) throws IOException {
		System.out.println("CLIENT");
		clientSocket = new Socket("127.0.0.1", 8080);
		InputStream in = clientSocket.getInputStream();
		OutputStream out = clientSocket.getOutputStream();
		byte[] arg0 = "prova".getBytes();
		int length = arg0.length;
		System.out.println("CLIENT SCRIVE length="+length);
		out.write(length);
		out.write(arg0);
		System.out.println("CLIENT SCRIVE");
		byte[] lengthBytes = new byte[128];
		in.read(lengthBytes);
		length = byteArrayToInt(lengthBytes);
		byte[] b = new byte[length];
		in.read(b);
		String app = new String(b);
		System.out.println(app);
		System.out.println("CLIENT FINE");
	}
}

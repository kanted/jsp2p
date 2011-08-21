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
		return value;
	}

	static Socket clientSocket;

	public static void main(String[] args) throws IOException {
		System.out.println("CLIENT");
		clientSocket = new Socket("127.0.0.1", 8080);
		InputStream in = clientSocket.getInputStream();
		OutputStream out = clientSocket.getOutputStream();
		byte[] arg0 = "prova".getBytes();
		byte length = (new Integer(arg0.length)).byteValue();
		System.out.println("CLIENT SCRIVE length="+length);
		out.write(length);
		out.write(arg0);
		System.out.println("CLIENT SCRIVE");
		byte[] stringLength = {0x00};
		in.read(stringLength, 0, 1);
		int inBufferLength = byteArrayToInt(stringLength);
		byte[] b = new byte[inBufferLength];
		in.read(b, 0, inBufferLength);
		String app = new String(b);
		System.out.println(app);
		System.out.println("CLIENT FINE");
	}
}

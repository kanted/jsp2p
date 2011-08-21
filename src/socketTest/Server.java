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
		return value;
	}

	static Socket mySocket;

	public static void main(String[] args) throws IOException {
		System.out.println("SERVER");
		ServerSocket server = new ServerSocket(8080);
		mySocket = server.accept();
		InputStream in = mySocket.getInputStream();
		OutputStream out = mySocket.getOutputStream();
		byte[] length = {0x00};
		in.read(length, 0, 1);
		System.out.println("LETTI "+length[0]);
		byte[] serializedString = new byte[5];
		in.read(serializedString, 0, 5);
		String receivedString = new String(serializedString);
		System.out.println("Stringa ricevuta: " + receivedString);
		String stringToReturn = new String("prova riuscita");
		byte[] arg0 = stringToReturn.getBytes();
		length[0] = (new Integer(arg0.length)).byteValue();
		System.out.println("CLIENT SCRIVE length=" + length[0]);
		out.write(length);
		System.out.println("CLIENT SCRIVE "+ stringToReturn);
		out.write(arg0);
	}
}

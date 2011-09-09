package it.saccosilvestri.jsp2p.utility;

/**
* @author Sacco Cosimo & Silvestri Davide
*/

public class ByteArrayUtility {

	/**
	 * Converte un array di byte nell'intero corrispondente.
	 */
	public static int byteArrayToInt(byte[] b) {
		int value = 0;
		for (int i = 0; i < b.length; i++) {
			value += b[i] * Math.pow(2, i);
		}
		if (value < 0)
			value = -value;
		return value;
	}

}

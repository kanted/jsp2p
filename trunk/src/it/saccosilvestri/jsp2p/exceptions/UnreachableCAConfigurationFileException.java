package it.saccosilvestri.jsp2p.exceptions;

public class UnreachableCAConfigurationFileException extends Exception {

	public String getMessage(){
		return "CA Configuration File not found or not readable";
		
	}
}

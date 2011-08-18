package it.saccosilvestri.jsp2p.exceptions;

public class WrongCAConfigurationFileSyntaxException extends Exception {

	public String getMessage(){
		return "Wrong CA Configuration File syntax.";
		
	}
}

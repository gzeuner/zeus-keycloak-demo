package de.zeus.keycloakdemo.exception;

// Custom exception for invalid tokens
public class InvalidTokenException extends RuntimeException {
    public InvalidTokenException(String message) {
        super(message);
    }
}
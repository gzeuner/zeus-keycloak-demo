package de.zeus.keycloakdemo.exception;

// Custom exception for authorized client unavailable
public class ClientNotFoundException extends RuntimeException {
    public ClientNotFoundException(String message) {
        super(message);
    }
}
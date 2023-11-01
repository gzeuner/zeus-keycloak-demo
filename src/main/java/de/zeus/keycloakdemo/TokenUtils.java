package de.zeus.keycloakdemo;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.*;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.stereotype.Component;

@Component
@Slf4j
public class TokenUtils {

    public static final String REALM_ACCESS = "realm_access";
    public static final String ROLES = "roles";
    public static final String RESOURCE_ACCESS = "resource_access";
    private final OAuth2AuthorizedClientService authorizedClientService;
    private final ObjectMapper objectMapper = new ObjectMapper();
    private static final ThreadLocal<Optional<JsonNode>> currentPayload = ThreadLocal.withInitial(Optional::empty);

    @Value("${spring.security.oauth2.client.registration.external.provider}")
    private String externalOauth2Provider;

    @Value("${token.utils.printUserRolesAndAuthorities}")
    private boolean printUserRolesAndAuthoritiesEnabled;

    @Value("${token.utils.printTokens}")
    private boolean printTokensEnabled;

    public TokenUtils(OAuth2AuthorizedClientService authorizedClientService) {
        this.authorizedClientService = authorizedClientService;

    }

    // Load the payload from a user's token
    public Optional<JsonNode> loadPayload(String userName) {
        OAuth2AuthorizedClient client = loadAuthorizedClient(userName);

        if (client != null) {
            return parsePayload(getPayloadFromAccessToken(client.getAccessToken().getTokenValue()));
        } else {
            log.error("No client found for user: {}", userName);
            throw new ClientNotFoundException("No client found for user: " + userName);
        }
    }

    // Auxiliary method to retrieve the stored payload.
    private Optional<JsonNode> getCurrentPayload() {
        ensureCurrentUserPayloadIsLoaded();
        if(printUserRolesAndAuthoritiesEnabled) {
            printUserRolesAndAuthorities();
        }
        if(printTokensEnabled) {
            printTokens();
        }
        Optional<JsonNode> payload = currentPayload.get();
        if (payload.isEmpty()) {
            log.warn("No payload is currently loaded");
        }
        return payload;
    }

    // This method ensures that the payload is set in the ThreadLocal.
    private void ensureCurrentUserPayloadIsLoaded() {
        if (currentPayload.get().isEmpty()) {
            Authentication auth = SecurityContextHolder.getContext().getAuthentication();
            if (auth != null) {
                Optional<JsonNode> payload = loadPayload(auth.getName());
                currentPayload.set(payload);
            } else {
                currentPayload.set(Optional.empty());
            }
        }
    }

    // Parse the payload and throw a custom exception on failure
    private Optional<JsonNode> parsePayload(Optional<String> payloadOpt) {
        if (payloadOpt.isEmpty()) {
            log.warn("Empty payload provided.");
            return Optional.empty();
        }
        String payload = payloadOpt.get();
        try {
            byte[] decodedPayload = Base64.getUrlDecoder().decode(payload);
            String payloadJson = new String(decodedPayload, StandardCharsets.UTF_8);
            return Optional.of(objectMapper.readTree(payloadJson));
        } catch (IOException e) {
            log.error("Could not parse payload", e);
            throw new PayloadParseException("Could not parse payload", e);
        }
    }

    // Get the payload part from the token
    private Optional<String> getPayloadFromAccessToken(String accessTokenValue) {
        String[] parts = accessTokenValue.split("\\.");
        if (parts.length != 3) {
            log.error("Invalid token format");
            throw new InvalidTokenException("Invalid token format");
        }
        return Optional.of(parts[1]);
    }

    public boolean hasAnyRealmRole(List<String> roles) {
        for (String role : roles) {
            if (hasRealmRole(role)) {
                return true;
            }
        }
        return false;
    }

    public boolean hasRealmRole(String role) {
        return hasRole(REALM_ACCESS + "." + ROLES, role);
    }

    public boolean hasResourceRole(String resource, String role) {
        return hasRole(RESOURCE_ACCESS + "." + resource + "." + ROLES, role);
    }

    // General method to check for a role
    private boolean hasRole(String pathToRoles, String role) {
        JsonNode rolesNode = getCurrentPayload().orElse(null);

        for (String pathElement : pathToRoles.split("\\.")) {
            assert rolesNode != null;
            rolesNode = rolesNode.path(pathElement);
        }

        assert rolesNode != null;
        for (JsonNode roleNode : rolesNode) {
            if (roleNode.asText().equals(role)) {
                return true;
            }
        }

        return false;
    }


    // Check if user has multiple roles across different resources
    public boolean hasMultipleRolesAndResources(Map<String, List<String>> roleResourceMap) {
        Optional<JsonNode> optionalPayload = getCurrentPayload();

        if (optionalPayload.isEmpty()) {
            return false;
        }

        for (Map.Entry<String, List<String>> entry : roleResourceMap.entrySet()) {
            String resource = entry.getKey();
            List<String> roles = entry.getValue();

            for (String role : roles) {
                if (!hasRole(REALM_ACCESS + "." + ROLES, role) &&
                        !hasRole(RESOURCE_ACCESS + "." + resource + "." + ROLES, role)) {
                    return false;
                }
            }
        }
        return true;
    }


    // Prints out the user roles and authorities
    public void printUserRolesAndAuthorities() {
        Optional<JsonNode> optPayload = currentPayload.get();
        String userName = getCurrentUserName(optPayload.orElse(null));

        // Wenn Payload vorhanden, dann drucke Rollen aus
        if (optPayload.isPresent()) {
            JsonNode payload = optPayload.get();

            log.info("Roles and authorities for user: {}", userName);

            JsonNode realmRolesNode = payload.path(REALM_ACCESS).path(ROLES);
            printRoles(realmRolesNode, "User has realm role: ");

            JsonNode resourceRolesNode = payload.path(RESOURCE_ACCESS);
            for (Iterator<String> it = resourceRolesNode.fieldNames(); it.hasNext(); ) {
                String clientName = it.next();
                JsonNode rolesNode = resourceRolesNode.get(clientName).path(ROLES);
                printRoles(rolesNode, "User has resource role: ");
            }
        } else {
            log.error("No payload found for user: {}", userName);
        }
    }

    // Print out the tokens
    public void printTokens() {
        OAuth2AuthorizedClient client = null;

        // Versuche den Authorisierten Client über den Authentication Context zu laden
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication != null) {
            client = loadAuthorizedClient(authentication.getName());
        }

        // Versuche das ID Token aus dem Authentication Principal zu extrahieren
        String idToken = null;
        assert authentication != null;
        if (authentication.getPrincipal() instanceof DefaultOidcUser) {
            DefaultOidcUser oidcUser = (DefaultOidcUser) authentication.getPrincipal();
            idToken = oidcUser.getIdToken().getTokenValue();
        }

        // Logging für den Access Token
        if (client != null) {
            String accessToken = client.getAccessToken().getTokenValue();
            log.info("Access Token: {}", accessToken);
        } else {
            log.error("No client found for user");
        }

        // Logging für das ID Token
        if (idToken != null) {
            log.info("ID Token: {}", idToken);
        } else {
            log.error("ID Token not found for user");
        }
    }


    public String getCurrentUserName(JsonNode payload) {

        // Primary Method
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication != null) {
            return authentication.getName();
        }

        // Fallback: Get username from payload
        if (payload != null && payload.has("preferred_username")) {
            return payload.get("preferred_username").asText();
        }

        return "Unknown";
    }

    // Load authorized client
    private OAuth2AuthorizedClient loadAuthorizedClient(String userName) {
        return authorizedClientService.loadAuthorizedClient(externalOauth2Provider, userName);
    }

    // Helper to print roles
    private void printRoles(JsonNode rolesNode, String messagePrefix) {
        for (JsonNode role : rolesNode) {
            log.info(messagePrefix + role.asText());
        }
    }

    // Custom exception for payload parsing
    public static class PayloadParseException extends RuntimeException {
        public PayloadParseException(String message, Throwable cause) {
            super(message, cause);
        }
    }

    public static class ClientNotFoundException extends RuntimeException {
        public ClientNotFoundException(String message) {
            super(message);
        }
    }

    public static class InvalidTokenException extends RuntimeException {
        public InvalidTokenException(String message) {
            super(message);
        }
    }
}

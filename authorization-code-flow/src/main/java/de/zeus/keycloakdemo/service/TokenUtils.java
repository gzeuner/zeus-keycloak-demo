package de.zeus.keycloakdemo.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.*;

import de.zeus.keycloakdemo.exception.ClientNotFoundException;
import de.zeus.keycloakdemo.exception.InvalidTokenException;
import de.zeus.keycloakdemo.exception.PayloadParseException;
import de.zeus.keycloakdemo.model.TokenPayloadHolder;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
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
    public static final String RESOURCE_ACCESS = "resource_access";
    public static final String ROLES = "roles";
    private final OAuth2AuthorizedClientService authorizedClientService;
    private final ObjectMapper objectMapper = new ObjectMapper();

    @Value("${spring.security.oauth2.client.registration.external.provider}")
    private String externalOauth2Provider;

    @Value("${token.utils.printUserRolesAndAuthorities}")
    private boolean printUserRolesAndAuthoritiesEnabled;

    @Value("${token.utils.printTokens}")
    private boolean printTokensEnabled;

    @Autowired
    private TokenPayloadHolder tokenPayloadHolder;

    // Constructor for TokenUtils class
    public TokenUtils(OAuth2AuthorizedClientService authorizedClientService) {
        this.authorizedClientService = authorizedClientService;

    }

    // Loads the payload data from a user's access token
    public void loadPayload(String userName) {
        OAuth2AuthorizedClient client = loadAuthorizedClient(userName);

        if (client != null) {
            Optional<JsonNode> payloadOpt = parsePayload(getPayloadFromAccessToken(client.getAccessToken().getTokenValue()));
            payloadOpt.ifPresent(tokenPayloadHolder::setPayload);

            // Trigger additional logging if enabled
            if (printUserRolesAndAuthoritiesEnabled) {
                printUserRolesAndAuthorities();
            }
            if (printTokensEnabled) {
                printTokens();
            }
        } else {
            String errMsg = "No client found for user: " + userName;
            log.error(errMsg);
            throw new ClientNotFoundException(errMsg);
        }
    }

    // Fetches the stored payload, loading it if necessary
    private Optional<JsonNode> getCurrentPayload() {
        if (tokenPayloadHolder.getPayload() == null) {
            Authentication auth = SecurityContextHolder.getContext().getAuthentication();
            if (auth != null) {
                loadPayload(auth.getName());
            }
        }
        return Optional.ofNullable(tokenPayloadHolder.getPayload());
    }

    // Parses the payload and throws an exception if parsing fails
    private Optional<JsonNode> parsePayload(Optional<String> payloadOpt) {
        return payloadOpt.flatMap(payload -> {
            try {
                byte[] decodedPayload = Base64.getUrlDecoder().decode(payload);
                String payloadJson = new String(decodedPayload, StandardCharsets.UTF_8);
                return Optional.of(objectMapper.readTree(payloadJson));
            } catch (IOException e) {
                String errMsg = "Could not parse payload";
                log.error(errMsg, e);
                throw new PayloadParseException(errMsg, e);
            }
        });
    }

    // Extracts the payload section from the access token
    private Optional<String> getPayloadFromAccessToken(String accessTokenValue) {
        String[] parts = accessTokenValue.split("\\.");
        if (parts.length != 3) {
            String errMsg = "Invalid token format";
            log.error(errMsg);
            throw new InvalidTokenException(errMsg);
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
        Optional<JsonNode> optPayload = getCurrentPayload();
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

}

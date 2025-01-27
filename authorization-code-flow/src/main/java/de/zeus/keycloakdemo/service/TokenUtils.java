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

    public TokenUtils(OAuth2AuthorizedClientService authorizedClientService) {
        this.authorizedClientService = authorizedClientService;
    }

    // Retrieve authentication once and reuse for all related methods
    private DefaultOidcUser getOidcUser() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication != null && authentication.getPrincipal() instanceof DefaultOidcUser) {
            return (DefaultOidcUser) authentication.getPrincipal();
        }
        log.error("Authentication is null or Principal is not of type DefaultOidcUser.");
        return null;
    }

    // Fetch ID Token from the authenticated user
    public String getIdToken() {
        DefaultOidcUser oidcUser = getOidcUser();
        if (oidcUser != null) {
            String idToken = oidcUser.getIdToken().getTokenValue();
            if (idToken != null) {
                return idToken;
            } else {
                log.error("ID Token is not available in DefaultOidcUser.");
            }
        }
        return null;
    }

    // Fetch Session ID from the authenticated user
    public String getSessionId() {
        DefaultOidcUser oidcUser = getOidcUser();
        if (oidcUser != null) {
            return oidcUser.getAttribute("sid");
        }
        log.error("Session ID could not be retrieved.");
        return null;
    }

    // Fetch User ID from the authenticated user
    public String getUserId() {
        DefaultOidcUser oidcUser = getOidcUser();
        if (oidcUser != null) {
            return oidcUser.getAttribute("sub");
        }
        log.error("User ID could not be retrieved.");
        return null;
    }

    // Fetch Client ID from the authenticated user
    public String getClientId() {
        DefaultOidcUser oidcUser = getOidcUser();
        if (oidcUser != null) {
            List<String> audience = oidcUser.getAttribute("aud");
            if (audience != null && !audience.isEmpty()) {
                return audience.get(0);
            }
        }
        log.error("Client ID could not be retrieved.");
        return null;
    }

    // Load payload data from a user's access token
    public void loadPayload(String userName) {
        OAuth2AuthorizedClient client = loadAuthorizedClient(userName);

        if (client != null) {
            Optional<JsonNode> payloadOpt = parsePayload(getPayloadFromAccessToken(client.getAccessToken().getTokenValue()));
            payloadOpt.ifPresent(tokenPayloadHolder::setPayload);

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

    // General method to check for roles
    private boolean hasRole(String pathToRoles, String role) {
        JsonNode rolesNode = getCurrentPayload().orElse(null);
        for (String pathElement : pathToRoles.split("\\.")) {
            if (rolesNode == null) {
                return false;
            }
            rolesNode = rolesNode.path(pathElement);
        }
        if (rolesNode != null) {
            for (JsonNode roleNode : rolesNode) {
                if (roleNode.asText().equals(role)) {
                    return true;
                }
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

    public boolean hasAnyRealmRole(List<String> roles) {
        return roles.stream().anyMatch(this::hasRealmRole);
    }

    public boolean hasMultipleRolesAndResources(Map<String, List<String>> roleResourceMap) {
        Optional<JsonNode> optionalPayload = getCurrentPayload();

        if (optionalPayload.isEmpty()) {
            return false;
        }

        for (Map.Entry<String, List<String>> entry : roleResourceMap.entrySet()) {
            String resource = entry.getKey();
            List<String> roles = entry.getValue();

            for (String role : roles) {
                boolean hasRealmRole = hasRole(REALM_ACCESS + "." + ROLES, role);
                boolean hasResourceRole = hasRole(RESOURCE_ACCESS + "." + resource + "." + ROLES, role);

                if (!hasRealmRole && !hasResourceRole) {
                    return false;
                }
            }
        }
        return true;
    }

    // Extract payload from access token
    private Optional<String> getPayloadFromAccessToken(String accessTokenValue) {
        String[] parts = accessTokenValue.split("\\.");
        if (parts.length != 3) {
            String errMsg = "Invalid token format";
            log.error(errMsg);
            throw new InvalidTokenException(errMsg);
        }
        return Optional.of(parts[1]);
    }

    // Parse payload into JSON
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

    // Fetch current payload, load if necessary
    private Optional<JsonNode> getCurrentPayload() {
        if (tokenPayloadHolder.getPayload() == null) {
            Authentication auth = SecurityContextHolder.getContext().getAuthentication();
            if (auth != null) {
                loadPayload(auth.getName());
            }
        }
        return Optional.ofNullable(tokenPayloadHolder.getPayload());
    }

    // Print user roles and authorities
    public void printUserRolesAndAuthorities() {
        Optional<JsonNode> optPayload = getCurrentPayload();
        String userName = getCurrentUserName(optPayload.orElse(null));

        if (optPayload.isPresent()) {
            JsonNode payload = optPayload.get();
            log.info("Roles and authorities for user: {}", userName);

            printRoles(payload.path(REALM_ACCESS).path(ROLES), "User has realm role: ");

            JsonNode resourceRolesNode = payload.path(RESOURCE_ACCESS);
            resourceRolesNode.fieldNames().forEachRemaining(clientName -> {
                printRoles(resourceRolesNode.get(clientName).path(ROLES), "User has resource role: ");
            });
        } else {
            log.error("No payload found for user: {}", userName);
        }
    }

    // Print roles helper
    private void printRoles(JsonNode rolesNode, String messagePrefix) {
        for (JsonNode role : rolesNode) {
            log.info(messagePrefix + role.asText());
        }
    }

    // Print tokens for debugging
    public void printTokens() {
        DefaultOidcUser oidcUser = getOidcUser();
        if (oidcUser != null) {
            log.info("ID Token: {}", oidcUser.getIdToken().getTokenValue());
        } else {
            log.error("ID Token not found.");
        }
    }

    public String getCurrentUserName(JsonNode payload) {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication != null) {
            return authentication.getName();
        }
        return payload != null && payload.has("preferred_username")
                ? payload.get("preferred_username").asText()
                : "Unknown";
    }

    // Load authorized client
    private OAuth2AuthorizedClient loadAuthorizedClient(String userName) {
        return authorizedClientService.loadAuthorizedClient(externalOauth2Provider, userName);
    }
}

package de.zeus.keycloakdemo.controller;

import de.zeus.keycloakdemo.service.TokenUtils;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

import java.io.IOException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Slf4j
@Controller
public class DemoController {

    @Autowired
    private OAuth2AuthorizedClientService authorizedClientService;

    @Autowired
    private TokenUtils tokenUtils;

    @Value("${keycloak.logout.url}")
    private String keycloakLogoutUrl;

    @Value("${post.logout.redirect.uri}")
    private String postLogoutRedirectUri;

    @GetMapping("/")
    public String index() {
        return "forward:/index.html";
    }

    @GetMapping("/public")
    public String publicEndpoint() {
        return "forward:/public.html";
    }

    @GetMapping("/secured")
    public String securedEndpoint() {
        return "forward:/secured.html";
    }

    @GetMapping("/realm-admin-realm-user-only")
    public String userOnlyEndpoint() {
        if (tokenUtils.hasAnyRealmRole(List.of("user", "admin"))) {
            return "forward:/realm-user-realm-admin.html";
        } else {
            return "forward:/error/403.html";
        }
    }

    @GetMapping("/realm-admin-only")
    public String realmAdminOnlyEndpoint() {
        if (tokenUtils.hasRealmRole("admin")) {
            return "forward:/realm-admin.html";
        } else {
            return "forward:/error/403.html";
        }
    }

    @GetMapping("/resource-admin-only")
    public String resourceAdminOnlyEndpoint() {
        if (tokenUtils.hasResourceRole("athen", "client_admin")) {
            return "forward:/resource-admin.html";
        } else {
            return "forward:/error/403.html";
        }
    }


    @GetMapping("/composite-role-endpoint")
    public String compositeRoleEndpoint() {
        Map<String, List<String>> roleResourceMap = new HashMap<>();
        roleResourceMap.put("athen", List.of("client_admin"));
        roleResourceMap.put("olymp", List.of("admin"));

        if (tokenUtils.hasMultipleRolesAndResources(roleResourceMap)) {
            return "forward:/composite-role.html";
        } else {
            return "forward:/error/403.html";
        }
    }

    @GetMapping("/logout")
    public String logout(HttpServletRequest request, HttpServletResponse response) {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth != null) {
            new SecurityContextLogoutHandler().logout(request, response, auth);
        }
        return "redirect:/index.html";
    }

    @GetMapping("/logoutWithoutConfirmation")
    public void logoutWithoutConfirmation(HttpServletRequest request, HttpServletResponse response) throws IOException {
        // Extract required parameters
        String idToken = tokenUtils.getIdToken();
        String sessionId = tokenUtils.getSessionId();
        String clientId = tokenUtils.getClientId();
        String userId = tokenUtils.getUserId();

        if (idToken == null || sessionId == null || clientId == null || userId == null) {
            log.error("Missing required information for logout: idToken={}, sessionId={}, clientId={}, userId={}",
                    idToken, sessionId, clientId, userId);
            throw new IllegalStateException("Missing required information for logout.");
        }

        // Dynamically build the Keycloak logout URL
        String logoutUrl = String.format(
                "%s?id_token_hint=%s&sid=%s&client_id=%s&user_id=%s&post_logout_redirect_uri=%s",
                keycloakLogoutUrl,
                idToken,
                sessionId,
                clientId,
                userId,
                postLogoutRedirectUri
        );

        // Invalidate the Spring Security context and session
        SecurityContextLogoutHandler logoutHandler = new SecurityContextLogoutHandler();
        logoutHandler.logout(request, response, null);

        boolean sessionInvalidated = request.getSession(false) == null;
        log.info("Spring Session invalidated: {}", sessionInvalidated);

        // Redirect to Keycloak logout URL
        response.sendRedirect(logoutUrl);
    }

}

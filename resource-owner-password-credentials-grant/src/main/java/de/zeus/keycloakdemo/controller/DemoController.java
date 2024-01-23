package de.zeus.keycloakdemo.controller;

import de.zeus.keycloakdemo.annotation.CompositeRoles;
import de.zeus.keycloakdemo.annotation.CustomRolesAllowed;
import de.zeus.keycloakdemo.annotation.ResourceAdminOnly;
import de.zeus.keycloakdemo.annotation.RealmAdminOnly;
import de.zeus.keycloakdemo.service.TokenUtils;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class DemoController {

    @Autowired
    private OAuth2AuthorizedClientService authorizedClientService;

    @Autowired
    private TokenUtils tokenUtils;

    @GetMapping("/")
    public ResponseEntity<String> index() {
        return ResponseEntity.ok("{\"message\":\"Welcome to the Index Page\"}");
    }

    @GetMapping("/public")
    public ResponseEntity<String> publicEndpoint() {
        return ResponseEntity.ok("{\"message\":\"Public Content\"}");
    }

    @GetMapping("/secured")
    public ResponseEntity<String> securedEndpoint() {
        return ResponseEntity.ok("{\"message\":\"Secured Content\"}");
    }

    @GetMapping("/realm-admin-realm-user-only")
    @CustomRolesAllowed({"admin", "user"})
    public ResponseEntity<String> userOnlyEndpoint() {
        return ResponseEntity.ok("{\"message\":\"Content for Users with Admin or User Roles\"}");
    }

    @GetMapping("/realm-admin-only")
    @RealmAdminOnly
    public ResponseEntity<String> realmAdminOnlyEndpoint() {
        return ResponseEntity.ok("{\"message\":\"Content for Realm Admins Only\"}");
    }

    @GetMapping("/resource-admin-only")
    @ResourceAdminOnly(resource = "athen", role = "client_admin")
    public ResponseEntity<String> resourceAdminOnlyEndpoint() {
        return ResponseEntity.ok("{\"message\":\"Content for Resource Admins Only\"}");
    }

    @GetMapping("/composite-role-endpoint")
    @CompositeRoles({"athen:client_admin", "olymp:admin"})
    public ResponseEntity<String> compositeRoleEndpoint() {
        return ResponseEntity.ok("{\"message\":\"Content for Composite Role\"}");
    }

    @GetMapping("/logout")
    public ResponseEntity<String> logout(HttpServletRequest request, HttpServletResponse response) {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth != null) {
            new SecurityContextLogoutHandler().logout(request, response, auth);
        }
        return ResponseEntity.ok("{\"message\":\"Logged out successfully\"}");
    }
}

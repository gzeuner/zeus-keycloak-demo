package de.zeus.keycloakdemo;

import com.fasterxml.jackson.databind.JsonNode;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.annotation.security.RolesAllowed;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ResponseBody;

import java.util.HashMap;
import java.util.List;
import java.util.Map;


@Controller
public class DemoController {

    @Autowired
    private OAuth2AuthorizedClientService authorizedClientService;

    @Autowired
    private TokenUtils tokenUtils;

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
}

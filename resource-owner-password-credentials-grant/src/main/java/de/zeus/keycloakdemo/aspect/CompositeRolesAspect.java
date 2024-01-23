package de.zeus.keycloakdemo.aspect;

import de.zeus.keycloakdemo.annotation.CompositeRoles;
import de.zeus.keycloakdemo.service.TokenUtils;
import lombok.extern.slf4j.Slf4j;
import org.aspectj.lang.JoinPoint;
import org.aspectj.lang.annotation.Aspect;
import org.aspectj.lang.annotation.Before;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Aspect
@Component
@Slf4j
public class CompositeRolesAspect {

    @Autowired
    private TokenUtils tokenUtils;

    @Before("@annotation(compositeRoles)")
    public void checkCompositeRoles(JoinPoint joinPoint, CompositeRoles compositeRoles) {

        log.info("Checking roles for method: " + joinPoint.getSignature().getName());

        Map<String, List<String>> roleResourceMap = new HashMap<>();

        for (String entry : compositeRoles.value()) {
            String[] parts = entry.split(":");
            String resource = parts[0];
            String role = parts[1];
            roleResourceMap.computeIfAbsent(resource, k -> new ArrayList<>()).add(role);
        }

        if (!tokenUtils.hasMultipleRolesAndResources(roleResourceMap)) {
            log.warn("User does not have required roles. Throwing AccessDeniedException.");
            throw new AccessDeniedException("Not authorized");
        }
        log.info("Roles check passed");
    }
}

package de.zeus.keycloakdemo.aspect;

import de.zeus.keycloakdemo.annotation.ResourceAdminOnly;
import de.zeus.keycloakdemo.service.TokenUtils;
import lombok.extern.slf4j.Slf4j;
import org.aspectj.lang.JoinPoint;
import org.aspectj.lang.annotation.Aspect;
import org.aspectj.lang.annotation.Before;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.stereotype.Component;

@Aspect
@Component
@Slf4j
public class ResourceAdminOnlyAspect {

    @Autowired
    private TokenUtils tokenUtils;

    @Before("@annotation(resourceAdminOnly)")
    public void checkResourceAdminRole(JoinPoint joinPoint, ResourceAdminOnly resourceAdminOnly) {

        log.info("Checking roles for method: " + joinPoint.getSignature().getName());

        if (!tokenUtils.hasResourceRole(resourceAdminOnly.resource(), resourceAdminOnly.role())) {
            log.warn("User does not have required roles. Throwing AccessDeniedException.");
            throw new AccessDeniedException("Not authorized");
        }

        log.info("Roles check passed.");
    }
}

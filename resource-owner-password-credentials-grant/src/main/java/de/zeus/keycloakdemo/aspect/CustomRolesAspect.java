package de.zeus.keycloakdemo.aspect;

import de.zeus.keycloakdemo.annotation.CustomRolesAllowed;
import de.zeus.keycloakdemo.service.TokenUtils;
import lombok.extern.slf4j.Slf4j;
import org.aspectj.lang.JoinPoint;
import org.aspectj.lang.annotation.Aspect;
import org.aspectj.lang.annotation.Before;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.stereotype.Component;

import java.util.Arrays;

@Aspect
@Component
@Slf4j
public class CustomRolesAspect {

    @Autowired
    private TokenUtils tokenUtils;

    @Before("@annotation(customRolesAllowed)")
    public void checkRoles(JoinPoint joinPoint, CustomRolesAllowed customRolesAllowed) {

        log.info("Checking roles for method: " + joinPoint.getSignature().getName());

        if (!tokenUtils.hasAnyRealmRole(Arrays.asList(customRolesAllowed.value()))) {
            log.warn("User does not have required roles. Throwing AccessDeniedException.");
            throw new AccessDeniedException("Not authorized");
        }

        log.info("Roles check passed");
    }
}

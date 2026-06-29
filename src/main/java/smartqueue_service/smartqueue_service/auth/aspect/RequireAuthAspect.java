package smartqueue_service.smartqueue_service.auth.aspect;
import jakarta.security.auth.message.AuthException;
import lombok.extern.slf4j.Slf4j;
import org.aspectj.lang.ProceedingJoinPoint;
import org.aspectj.lang.annotation.Around;
import org.aspectj.lang.annotation.Aspect;
import org.aspectj.lang.reflect.MethodSignature;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import smartqueue_service.smartqueue_service.auth.dto.Role;
import smartqueue_service.smartqueue_service.auth.annotation.RequireAuth;
import smartqueue_service.smartqueue_service.auth.exception.ForbiddenException;

import java.lang.reflect.Method;
import java.util.Arrays;
import java.util.Set;
import java.util.stream.Collectors;

@Slf4j
@Aspect
@Component
public class RequireAuthAspect {

    @Around("@annotation(com.smartqueue.auth.annotation.RequireAuth) || " +
            "@within(com.smartqueue.auth.annotation.RequireAuth)")
    public Object checkAuth(ProceedingJoinPoint joinPoint) throws Throwable {

        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        if (authentication == null || !authentication.isAuthenticated() ||
                "anonymousUser".equals(authentication.getPrincipal())) {
            throw new AuthException("Authentication required");
        }

        // Resolve annotation — method-level takes priority over class-level
        RequireAuth requireAuth = resolveAnnotation(joinPoint);

        Role[] requiredRoles = requireAuth.roles();

        if (requiredRoles.length > 0) {
            Set<String> userAuthorities = authentication.getAuthorities().stream()
                    .map(GrantedAuthority::getAuthority)
                    .collect(Collectors.toSet());

            boolean hasRole = Arrays.stream(requiredRoles)
                    .anyMatch(role -> userAuthorities.contains("ROLE_" + role.name()));

            if (!hasRole) {
                log.warn("Access denied for user {} — required roles: {}",
                        authentication.getName(), Arrays.toString(requiredRoles));
                throw new ForbiddenException("You do not have permission to perform this action");
            }
        }

        return joinPoint.proceed();
    }

    private RequireAuth resolveAnnotation(ProceedingJoinPoint joinPoint) {
        MethodSignature signature = (MethodSignature) joinPoint.getSignature();
        Method method = signature.getMethod();

        // Method-level annotation takes priority
        RequireAuth methodAnnotation = method.getAnnotation(RequireAuth.class);
        if (methodAnnotation != null) return methodAnnotation;

        // Fall back to class-level
        return joinPoint.getTarget().getClass().getAnnotation(RequireAuth.class);
    }
}
package smartqueue_service.smartqueue_service.auth.annotation;

import smartqueue_service.smartqueue_service.auth.dto.Role;

import java.lang.annotation.*;

@Target({ElementType.METHOD, ElementType.TYPE})
@Retention(RetentionPolicy.RUNTIME)
@Documented
public @interface RequireAuth {

    /**
     * Roles allowed to access this resolver.
     * Empty = any authenticated user.
     */
    Role[] roles() default {};
}
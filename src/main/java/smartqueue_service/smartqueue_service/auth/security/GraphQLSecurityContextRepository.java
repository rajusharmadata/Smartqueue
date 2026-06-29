package smartqueue_service.smartqueue_service.auth.security;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.context.HttpRequestResponseHolder;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.stereotype.Component;

/**
 * Stateless SecurityContextRepository for GraphQL.
 * JWT filter sets the context per request — no session needed.
 */
@Component
@RequiredArgsConstructor
public class GraphQLSecurityContextRepository implements SecurityContextRepository {

    @Override
    public SecurityContext loadContext(HttpRequestResponseHolder requestResponseHolder) {
        return SecurityContextHolder.getContext();
    }

    @Override
    public void saveContext(SecurityContext context,
                            HttpServletRequest request,
                            HttpServletResponse response) {
        // Stateless — nothing to save
    }

    @Override
    public boolean containsContext(HttpServletRequest request) {
        return false;
    }
}
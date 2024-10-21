package com.blue.api_gateway.filter;

import com.blue.api_gateway.exception.CustomException;
import com.blue.api_gateway.security.JwtHelper;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.MalformedJwtException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestTemplate;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;

@Component
public class AuthenticationFilter extends AbstractGatewayFilterFactory<AuthenticationFilter.Config> {

    @Autowired
    private RouteValidator validator;
    @Autowired
    private JwtHelper jwtHelper;
//    @Autowired
//    private UserDetailsService userDetailsService;


//    @Autowired
//    private RestTemplate template;

    public AuthenticationFilter() {
        super(Config.class);
    }

    @Override
    public GatewayFilter apply(Config config) {
        return (exchange, chain) -> {
            if (validator.isSecured.test(exchange.getRequest())) {
                if (!exchange.getRequest().getHeaders().containsKey(HttpHeaders.AUTHORIZATION)) {
                    throw new CustomException("Missing authorization header");
                }

                String authHeader = exchange.getRequest().getHeaders().getFirst(HttpHeaders.AUTHORIZATION);
                System.out.println(authHeader);
                if (authHeader != null && authHeader.startsWith("Bearer ")) {
                    String token = authHeader.substring(7);
                    try {
                        System.out.println(authHeader);
                         jwtHelper.valiDateToken(token);
                         Claims c = jwtHelper.getAllClaimsFromToken(token);
                         System.out.println(c);

                         Object rolesObject =c.get("roles");
                         List<String> roles = new ArrayList<>();

                        List<Map<String, String>> authorities  = (List<Map<String, String>>) rolesObject;
                        System.out.println("555555555");
                        System.out.println(authorities.getFirst().get("authority"));
                        roles.add(authorities.getFirst().get("authority"));

                        System.out.println(roles);
                        System.out.println(config.getRole());
                        System.out.println(c.getAudience());

                        if (roles == null || !hasRequiredRole(roles,config.getRole() )) {
                            throw new CustomException("Insufficient role");
                        }
//                        Jws<Claims> o =  jwtHelper.getClaimFromToken(token);
//                        System.out.println(o.getSignature());
                    } catch (ExpiredJwtException e) {
                        System.out.println("JWT Token has expired: " + e.getMessage());
                        throw new CustomException("JWT Token has expired: " + e.getMessage());
                    } catch (MalformedJwtException e) {
                        throw new CustomException("JWT Token is malformed: " + e.getMessage());
                    } catch (Exception e) {
                        System.out.println("JWT Token validation error: " + e.getMessage());

                        throw new CustomException("Unauthorized access to application  "+e.getMessage());
                    }
                } else {
                    System.out.println("Invalid Authorization header format");
                    throw new CustomException("Invalid Authorization header format");
                }



            }


            return chain.filter(exchange);
        };
    }
    private boolean hasRequiredRole(List<String> userRoles ,Set<String> requiredRoles){
        for (String role : requiredRoles) {
            if (userRoles.contains(role)) {
                return true;
                 }
            }
            return false;
        }

    public static class Config {

        private Set<String> role;

        public Set<String>  getRole() {
            return role;
        }

        public void setRole(Set<String>  role) {
            this.role = role;
        }
    }
}

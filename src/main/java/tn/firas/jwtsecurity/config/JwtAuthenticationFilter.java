package tn.firas.jwtsecurity.config;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import tn.firas.jwtsecurity.token.TokenRepository;

import java.io.IOException;

@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtService jwtService;
    private final UserDetailsService userDetailsService;
    private final TokenRepository tokenRepository;
    //in order to make it a filter
    //we want this filter to
    //be active every time we get a request so
    //every time the user sends a request we
    //want our filter to get fired and do all
    //the job that we want that we wanted to do
    //so this one we need to extend
    //a class called once per request filter
    @Override
    protected void doFilterInternal(
            //Three parameters SHould not be null
            @NonNull HttpServletRequest request,
            @NonNull HttpServletResponse response,
            @NonNull FilterChain filterChain
            //the filter chain is the chain of responsibility
            //design pattern so it will it contains
            //the list of the other filters that we
            //need to execute so when we call
            //this filter chain doInternalFilter
            //or doFilter it will call the next
            //filter within the chain
    ) throws ServletException, IOException {
        //because when we make a call we need to
        // pass the JWT authentication token within the header
    final String authHeader = request.getHeader("Authorization");
    final String jwt;
    final String userEmail;
    //check the Jwt Token
        if (authHeader == null ||!authHeader.startsWith("Bearer ")) {
            filterChain.doFilter(request, response);
            return;//we don't want to continue with the execution of the rest
        }
    //Extract the token from this header
        jwt = authHeader.substring(7);
        //Extract userEmail from Jwt token
        userEmail= jwtService.extractUsername(jwt);

        if (userEmail != null && SecurityContextHolder.getContext().getAuthentication() == null) {
            UserDetails userDetails = this.userDetailsService.loadUserByUsername(userEmail);
            var isTokenValid = tokenRepository.findByToken(jwt)
                    .map(token -> !token.isExpired() && !token.isRevoked())
                    .orElse(false);
            //Validate and check if the token is valid
            if (jwtService.isTokenValid(jwt,userDetails) && isTokenValid){
                //if the token is valid We need to update the security context Holder
                UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
                        userDetails,
                        null,
                        userDetails.getAuthorities()
                );
                authToken.setDetails(
                        new WebAuthenticationDetailsSource().buildDetails(request)
                );
                SecurityContextHolder.getContext().setAuthentication(authToken);
            }
        }
        //We need to pass to the next filter
        filterChain.doFilter(request,response);
    }
}

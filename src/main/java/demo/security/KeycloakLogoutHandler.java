package demo.security;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriComponentsBuilder;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class KeycloakLogoutHandler extends SecurityContextLogoutHandler
{
  private static final String ID_TOKEN_PARAM = "id_token_hint";
  private static final String LOGOUT_PATH = "/protocol/openid-connect/logout";

  private static final Logger log = LoggerFactory.getLogger( KeycloakLogoutHandler.class );

  private final RestTemplate restTemplate;

  public KeycloakLogoutHandler(RestTemplate restTemplate) {
    this.restTemplate = restTemplate;
  }

  @Override
  public void logout( HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
    super.logout(request, response, authentication);

    authServerLogout((OidcUser) authentication.getPrincipal());
  }

  private void authServerLogout(OidcUser user) {
    ResponseEntity<String> logoutResponse =
            restTemplate.getForEntity(endpointUri(user), String.class);
    logStatus( logoutResponse.getStatusCode() );
  }

  private String endpointUri(OidcUser user) {
    return UriComponentsBuilder
            .fromUriString( endSessionEndpoint(user) )
            .queryParam( ID_TOKEN_PARAM, idToken(user))
            .toUriString();
  }

  private String endSessionEndpoint(OidcUser user) {
    return user.getIssuer() + LOGOUT_PATH;
  }

  private String idToken(OidcUser user) {
    return user.getIdToken().getTokenValue();
  }

  private void logStatus( HttpStatus status )
  {
    if (status.is2xxSuccessful()) {
      log.info("Successfully logged out in Keycloak");
    } else {
      log.info("Could not logout in Keycloak");
    }
  }
}

package demo.security;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.authority.mapping.GrantedAuthoritiesMapper;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserService;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoderJwkSupport;

import java.util.Collection;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

public class KeycloakOidcUserService extends OidcUserService
{
  private static final String RESOURCE_ACCESS = "resource_access";
  private static final String ROLES = "roles";
  private static final String NAME_ATTRIBUTE_KEY = "preferred_username";

  private final OAuth2Error INVALID_REQUEST = new OAuth2Error( OAuth2ErrorCodes.INVALID_REQUEST);

  private final GrantedAuthoritiesMapper authoritiesMapper;

  public KeycloakOidcUserService( GrantedAuthoritiesMapper authoritiesMapper )
  {
    this.authoritiesMapper = authoritiesMapper;
  }

  @Override
  public OidcUser loadUser(OidcUserRequest userRequest) throws OAuth2AuthenticationException
  {
    OidcUser user = super.loadUser(userRequest);
    Set<GrantedAuthority> authorities = extractAuthorities( userRequest, user );
    return new DefaultOidcUser(authorities, userRequest.getIdToken(), user.getUserInfo(), NAME_ATTRIBUTE_KEY );
  }

  private Set<GrantedAuthority> extractAuthorities( OidcUserRequest userRequest, OidcUser user )
  {
    Set<GrantedAuthority> authorities = new LinkedHashSet<>();
    authorities.addAll(user.getAuthorities());
    authorities.addAll(extractKeycloakAuthorities(userRequest));
    return authorities;
  }

  private Collection<? extends GrantedAuthority> extractKeycloakAuthorities(OidcUserRequest userRequest)
  {
    List<String> clientRoles = extractClientRoles( getClientId( userRequest ), getToken( userRequest ) );
    Collection<? extends GrantedAuthority> authorities =
            clientRoles.stream().map( SimpleGrantedAuthority::new ).collect( Collectors.toList() );
    return authoritiesMapper.mapAuthorities(authorities);
  }

  private Jwt getToken( OidcUserRequest userRequest )
  {
    JwtDecoder jwtDecoder = new NimbusJwtDecoderJwkSupport(
            userRequest.getClientRegistration().getProviderDetails().getJwkSetUri());
    return parseJwt(jwtDecoder, userRequest.getAccessToken().getTokenValue());
  }

  private Jwt parseJwt(JwtDecoder jwtDecoder, String accessTokenValue) {
    try {
      return jwtDecoder.decode(accessTokenValue);
    } catch ( JwtException e) {
      throw new OAuth2AuthenticationException(INVALID_REQUEST, e);
    }
  }

  private String getClientId(OidcUserRequest userRequest) {
    return userRequest.getClientRegistration().getClientId();
  }

  @SuppressWarnings("unchecked")
  private List<String> extractClientRoles(String clientId, Jwt token) {
    return Optional.of( (Map<String, Object>) token.getClaims().get( RESOURCE_ACCESS ) )
            .map( accessClaims -> (Map<String, Map<String, Object>>) accessClaims.get( clientId ) )
            .map( claims -> (List<String>) claims.get( ROLES ) )
            .orElseGet( Collections::emptyList );
  }
}

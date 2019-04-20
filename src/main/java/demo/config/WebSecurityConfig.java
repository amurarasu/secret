package demo.config;

import demo.security.KeycloakLogoutHandler;
import demo.security.KeycloakOidcUserService;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;

import static org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestRedirectFilter.DEFAULT_AUTHORIZATION_REQUEST_BASE_URI;

@EnableGlobalMethodSecurity(prePostEnabled = true)
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

  private String realm;
  private KeycloakOidcUserService userService;
  private KeycloakLogoutHandler logoutHandler;

  public WebSecurityConfig(@Value("${kc.realm}") String realm,
          KeycloakOidcUserService userService, KeycloakLogoutHandler logoutHandler ) {
    this.realm = realm;
    this.userService = userService;
    this.logoutHandler = logoutHandler;
  }

  @Override
  protected void configure(HttpSecurity http) throws Exception {
    http
      // Configure session management to your needs. Use Session API to store the session within a DB
      // like Redis or Hazelcast if you want the storage to be distributed so that you can have multiple
      // modules using the same session.
      .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED).and()
      // Depends on your taste. You can configure single paths here
      // or allow everything and then use method based security as in here
      .authorizeRequests().anyRequest().permitAll().and()
      // Propagate logouts via /logout to Keycloak, there will be built-in support from spring security 5.2.0
      .logout().addLogoutHandler(logoutHandler).and()
      // Enhance the user service to map user authorities
      .oauth2Login().userInfoEndpoint().oidcUserService(userService).and()
      //realm identifies the oauth client registration configs in application properties
      .loginPage(DEFAULT_AUTHORIZATION_REQUEST_BASE_URI + "/" + realm);
  }

}

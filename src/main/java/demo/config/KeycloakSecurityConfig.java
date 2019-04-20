package demo.config;

import demo.security.KeycloakLogoutHandler;
import demo.security.KeycloakOidcUserService;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.core.authority.mapping.SimpleAuthorityMapper;
import org.springframework.web.client.RestTemplate;

@Configuration
public class KeycloakSecurityConfig
{
  @Bean
  public KeycloakOidcUserService userService() {
    SimpleAuthorityMapper authoritiesMapper = new SimpleAuthorityMapper();
    authoritiesMapper.setConvertToUpperCase(true);

    return new KeycloakOidcUserService(authoritiesMapper);
  }

  @Bean
  public KeycloakLogoutHandler logoutHandler() {
    return new KeycloakLogoutHandler(new RestTemplate());
  }
}

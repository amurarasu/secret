package demo.web.rest;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.servlet.ModelAndView;

import java.security.Principal;
import java.util.Collections;

@Controller
public class TechRadarController {

  @PreAuthorize("hasRole('USER')")
  @GetMapping("/tech-cards")
  public ModelAndView cardsPage( Principal principal) {
    return new ModelAndView("tech-cards", Collections.singletonMap("principal", principal));
  }

  @PreAuthorize("hasRole('ADMIN')")
  @GetMapping("/admin")
  public ModelAndView adminPage(Principal principal) {
    return new ModelAndView("admin", Collections.singletonMap("principal", principal));
  }

  @GetMapping("/")
  public String homePage( Model model, Principal principal) {
    model.addAttribute("principal", principal);
    return "index";
  }

  @GetMapping("/account")
  public String redirectToAccountPage(@AuthenticationPrincipal OAuth2AuthenticationToken authToken) {
    if (authToken == null) {
      return "redirect:/";
    }

    OidcUser user = (OidcUser) authToken.getPrincipal();

    // Provides a back-link to the application
    return "redirect:" + user.getIssuer() + "/account?referrer=" + user.getIdToken().getAuthorizedParty();
  }
}
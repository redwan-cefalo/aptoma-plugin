package no.nettavisen.aptoma.plugin.controller;

import org.springframework.ui.ModelMap;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;

/**
 * Author: redwan
 * Date: 12/24/13
 * Time: 5:35 PM
 */
public class PluginController {
    @RequestMapping(value = "/dashboard", method = RequestMethod.GET)
    public String welcomeAdmin(ModelMap model) {
        Authentication auth = getLoggedinUserInfo();
        model.addAttribute("loggedInUser", auth.getName());
        arrangeActionButtons(model);
        return getDashboardView(model);
    }
}

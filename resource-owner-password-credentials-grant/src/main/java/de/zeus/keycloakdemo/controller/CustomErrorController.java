package de.zeus.keycloakdemo.controller;

import jakarta.servlet.RequestDispatcher;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.boot.web.servlet.error.ErrorController;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;

@Controller
public class CustomErrorController implements ErrorController {

    @RequestMapping("/error")
    public String handleError(HttpServletRequest request) {
        Object status = request.getAttribute(RequestDispatcher.ERROR_STATUS_CODE);

        if (status != null) {
            int statusCode = Integer.parseInt(status.toString());

            if(statusCode == HttpStatus.FORBIDDEN.value()) {
                return "error/403.html";
            }
            if(statusCode == HttpStatus.NOT_FOUND.value()) {
                return "error/404.html";
            }
            // Add more custom error pages here if needed
        }
        return "error"; // Default error page
    }

}

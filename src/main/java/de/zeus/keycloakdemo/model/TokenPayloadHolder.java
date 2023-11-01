package de.zeus.keycloakdemo.model;

import com.fasterxml.jackson.databind.JsonNode;
import org.springframework.web.context.annotation.RequestScope;
import org.springframework.stereotype.Component;

@RequestScope
@Component
public class TokenPayloadHolder {
    private JsonNode payload;

    public JsonNode getPayload() {
        return payload;
    }

    public void setPayload(JsonNode payload) {
        this.payload = payload;
    }
}

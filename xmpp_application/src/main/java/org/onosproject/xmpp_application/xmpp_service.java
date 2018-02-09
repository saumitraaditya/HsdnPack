package org.onosproject.xmpp_application;

public interface xmpp_service {

    //public void send(String target,  String query);

    public void send(String target, String setup, String query, String response, String tag);

}

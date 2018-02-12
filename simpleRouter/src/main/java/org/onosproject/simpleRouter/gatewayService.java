package org.onosproject.simpleRouter;

public interface gatewayService {
    public void do_something();
    public void allow_access(long port, String address);
    public void populate_arped_addresseses(String address);
    public void translate_address(String match_address, String new_address, Boolean incoming);
}

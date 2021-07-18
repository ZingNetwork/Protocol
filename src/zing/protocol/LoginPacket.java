package zing.protocol;

public class LoginPacket extends Protocol {

    public LoginPacket(String address) {
        super(address);
        pid = LOGIN_PACKET;
    }
}

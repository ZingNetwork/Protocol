package zing.protocol;

import com.google.gson.GsonBuilder;
import zing.protocol.algorithm.RSA;

import java.security.PrivateKey;

public class Protocol {

    public static final int VERSION = 1;

    public int version = VERSION;

    public long time_stamp;

    public String sign;

    public String zingAddress;

    public short pid = 0;

    public Packet packet;

    public Protocol() {
        this("");
    }

    public Protocol(String address) {
        zingAddress = address;
        time_stamp = System.currentTimeMillis();
    }

    public final static short LOGIN_PACKET = 1;
    public final static short AUTH_PACKET = 2;

    public short pid() {
        return pid;
    }

    public static String format(Protocol protocol) {
        return protocol.time_stamp + ";" +
                protocol.packet.nonce + ";" +
                protocol.packet.message + ";" +
                protocol.packet.nickname;
    }

    public void encode(PrivateKey key) throws Exception {
        sign = RSA.sign(Protocol.format(this), key);
    }

    public String getSimpleAddress() {
        return zingAddress.substring(0, 16) + "... ";
    }

    @Override
    public String toString() {
        return new GsonBuilder().setPrettyPrinting().create().toJson(this, Protocol.class);
    }
}

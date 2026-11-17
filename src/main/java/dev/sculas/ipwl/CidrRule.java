package dev.sculas.ipwl;

import com.google.common.net.InetAddresses;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.Arrays;

public record CidrRule(byte[] network, int prefix, String note) {
    public static CidrRule parse(String input, String note) {
        String text = input.trim();
        String addr = text;
        int prefix = -1;
        int slash = text.indexOf('/');
        if (slash >= 0) {
            addr = text.substring(0, slash);
            try {
                prefix = Integer.parseInt(text.substring(slash + 1));
            } catch (NumberFormatException e) {
                throw new IllegalArgumentException("Invalid prefix length in '" + input + "'");
            }
        }

        if (!InetAddresses.isInetAddress(addr)) {
            throw new IllegalArgumentException("'" + addr + "' is not a valid IPv4/IPv6 address");
        }
        byte[] bytes = normalize(InetAddresses.forString(addr)).getAddress();
        int max = bytes.length * 8;
        if (prefix < 0) prefix = max;
        if (prefix > max) {
            throw new IllegalArgumentException("Prefix /" + prefix + " is too long for '" + addr + "'");
        }
        for (int bit = prefix; bit < max; bit++) {
            bytes[bit / 8] &= (byte) ~(0x80 >>> (bit % 8));
        }
        return new CidrRule(bytes, prefix, note == null || note.isBlank() ? null : note.trim());
    }

    public static InetAddress normalize(InetAddress address) {
        try {
            return InetAddress.getByAddress(address.getAddress());
        } catch (UnknownHostException e) {
            throw new IllegalStateException(e);
        }
    }

    public boolean isV4() {
        return network.length == 4;
    }

    public boolean matches(InetAddress address) {
        byte[] b = normalize(address).getAddress();
        if (b.length != network.length) return false;
        int full = prefix / 8;
        for (int i = 0; i < full; i++) {
            if (b[i] != network[i]) return false;
        }
        int rem = prefix % 8;
        if (rem == 0) return true;
        int mask = (0xFF << (8 - rem)) & 0xFF;
        return (b[full] & mask) == (network[full] & mask);
    }

    int word(int i) {
        return ((network[i * 4] & 0xFF) << 24) | ((network[i * 4 + 1] & 0xFF) << 16)
                | ((network[i * 4 + 2] & 0xFF) << 8) | (network[i * 4 + 3] & 0xFF);
    }

    int wordMask(int i) {
        int bits = Math.max(0, Math.min(32, prefix - i * 32));
        return bits == 0 ? 0 : (int) (0xFFFFFFFFL << (32 - bits));
    }

    public String cidr() {
        String addr;
        try {
            addr = InetAddresses.toAddrString(InetAddress.getByAddress(network));
        } catch (UnknownHostException e) {
            throw new IllegalStateException(e);
        }
        return prefix == network.length * 8 ? addr : addr + "/" + prefix;
    }

    @Override
    public boolean equals(Object o) {
        return o instanceof CidrRule r && r.prefix == prefix && Arrays.equals(r.network, network);
    }

    @Override
    public int hashCode() {
        return 31 * Arrays.hashCode(network) + prefix;
    }

    @Override
    public String toString() {
        return note == null ? cidr() : cidr() + " (" + note + ")";
    }
}

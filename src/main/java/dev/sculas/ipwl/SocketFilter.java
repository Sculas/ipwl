package dev.sculas.ipwl;

import com.sun.jna.Function;
import com.sun.jna.LastErrorException;
import com.sun.jna.Memory;
import com.sun.jna.Native;
import com.sun.jna.Platform;
import org.slf4j.Logger;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Stream;

public final class SocketFilter {
    private static final int SOL_SOCKET = 1;
    private static final int SO_ATTACH_FILTER = 26;

    public record Target(int port, boolean tcp, String name) {}

    private final Logger logger;
    private final Set<Target> targets = new HashSet<>();

    private final Map<Integer, Long> attached = new HashMap<>();
    private final boolean supported;
    private Function setsockopt;
    private List<BpfProgram.Insn> program = BpfProgram.acceptAll();
    private String lastError;
    private final Set<String> errorsLogged = new HashSet<>();

    public SocketFilter(Logger logger) {
        this.logger = logger;
        this.supported = Platform.isLinux() && Files.isDirectory(Path.of("/proc/self/fd"));
        if (!supported) {
            logger.warn("Kernel filtering needs Linux. ipwl will close rejected connections in Java, and scanners can still see the port");
        }
    }

    public boolean isSupported() {
        return supported;
    }

    public synchronized int attachedCount() {
        return attached.size();
    }

    public synchronized String lastError() {
        return lastError;
    }

    public synchronized Set<Target> targets() {
        return Set.copyOf(targets);
    }

    public synchronized void setProgram(List<BpfProgram.Insn> program) {
        this.program = program;
        sync(true);
    }

    public synchronized void protect(Target target) {
        targets.add(target);
        sync(false);
    }

    public synchronized void clear() {
        targets.clear();
        attached.clear();
        errorsLogged.clear();
        lastError = null;
    }

    public synchronized void sync(boolean force) {
        if (!supported || targets.isEmpty()) return;
        String error = null;
        try {
            Map<Long, Target> inodes = findInodes();
            Map<Integer, Long> seen = new HashMap<>();
            try (Stream<Path> fds = Files.list(Path.of("/proc/self/fd"))) {
                for (Path p : (Iterable<Path>) fds::iterator) {
                    long inode = socketInode(p);
                    Target t = inodes.get(inode);
                    if (t == null) continue;
                    int fd = Integer.parseInt(p.getFileName().toString());
                    Long prev = attached.get(fd);
                    if (!force && prev != null && prev == inode) {
                        seen.put(fd, inode);
                        continue;
                    }
                    String where = t.name() + " socket (port " + t.port() + "/" + (t.tcp() ? "tcp" : "udp") + ", fd " + fd + ")";
                    try {
                        attach(fd);
                        seen.put(fd, inode);
                        if (prev == null || prev != inode) logger.info("Allowlist filter attached to {}", where);
                    } catch (RuntimeException e) {
                        error = e.getMessage();
                        if (errorsLogged.add(where + error)) {
                            logger.error("Could not attach the allowlist filter to {}, {}. ipwl still closes rejected "
                                    + "connections, but scanners can see the port.{}", where, error,
                                    error.contains("errno 1") ? " Give the server process CAP_NET_ADMIN." : "");
                        }
                    }
                }
            }
            attached.clear();
            attached.putAll(seen);
            for (Target t : targets) {
                if (!inodes.containsValue(t)) logger.warn("No {} socket found on port {}", t.name(), t.port());
            }
        } catch (IOException | RuntimeException e) {
            error = e.toString();
            logger.error("Failed to scan sockets for the allowlist filter", e);
        }
        lastError = error;
    }

    private Map<Long, Target> findInodes() throws IOException {
        Map<Long, Target> result = new HashMap<>();
        for (Target t : targets) {
            for (String f : t.tcp() ? new String[]{"tcp", "tcp6"} : new String[]{"udp", "udp6"}) {
                Path path = Path.of("/proc/self/net", f);
                if (!Files.exists(path)) continue;
                List<String> lines = Files.readAllLines(path);
                for (int i = 1; i < lines.size(); i++) {
                    String[] c = lines.get(i).trim().split("\\s+");
                    if (c.length < 10) continue;
                    String local = c[1];
                    int port = Integer.parseInt(local.substring(local.lastIndexOf(':') + 1), 16);
                    if (port != t.port()) continue;
                    if (t.tcp() && !c[3].equals("0A")) continue;
                    long inode = Long.parseLong(c[9]);
                    if (inode != 0) result.put(inode, t);
                }
            }
        }
        return result;
    }

    private static long socketInode(Path fdLink) {
        try {
            String target = Files.readSymbolicLink(fdLink).toString();
            if (target.startsWith("socket:[") && target.endsWith("]")) {
                return Long.parseLong(target.substring(8, target.length() - 1));
            }
        } catch (IOException | UnsupportedOperationException | NumberFormatException ignored) {
        }
        return -1;
    }

    private void attach(int fd) {
        attach(fd, program);
    }

    void attach(int fd, List<BpfProgram.Insn> prog) {
        if (setsockopt == null) setsockopt = Function.getFunction("c", "setsockopt", Function.THROW_LAST_ERROR);
        Memory filter = new Memory(8L * prog.size());
        for (int i = 0; i < prog.size(); i++) {
            BpfProgram.Insn in = prog.get(i);
            long off = 8L * i;
            filter.setShort(off, (short) in.code());
            filter.setByte(off + 2, (byte) in.jt());
            filter.setByte(off + 3, (byte) in.jf());
            filter.setInt(off + 4, in.k());
        }
        int ptr = Native.POINTER_SIZE;
        Memory fprog = new Memory(2L * ptr);
        fprog.clear();
        fprog.setShort(0, (short) prog.size());
        fprog.setPointer(ptr, filter);
        try {
            setsockopt.invokeInt(new Object[]{fd, SOL_SOCKET, SO_ATTACH_FILTER, fprog, (int) fprog.size()});
        } catch (LastErrorException e) {
            throw new IllegalStateException("setsockopt(SO_ATTACH_FILTER) on fd " + fd + " failed: errno " + e.getErrorCode(), e);
        }
    }

    public synchronized List<String> describe() {
        List<String> out = new ArrayList<>();
        for (Target t : targets) out.add(t.name() + " " + t.port() + "/" + (t.tcp() ? "tcp" : "udp"));
        return out;
    }
}

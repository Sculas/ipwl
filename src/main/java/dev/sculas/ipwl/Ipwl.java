package dev.sculas.ipwl;

import com.mojang.logging.LogUtils;
import io.netty.channel.Channel;
import net.minecraft.network.chat.Component;
import net.minecraft.server.MinecraftServer;
import net.minecraft.server.dedicated.DedicatedServer;
import net.minecraft.server.dedicated.DedicatedServerProperties;
import net.minecraft.server.level.ServerPlayer;
import net.neoforged.api.distmarker.Dist;
import net.neoforged.fml.common.Mod;
import net.neoforged.fml.loading.FMLPaths;
import net.neoforged.neoforge.common.NeoForge;
import net.neoforged.neoforge.event.RegisterCommandsEvent;
import net.neoforged.neoforge.event.server.ServerStartedEvent;
import net.neoforged.neoforge.event.server.ServerStoppedEvent;
import net.neoforged.neoforge.event.tick.ServerTickEvent;
import org.slf4j.Logger;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.util.ArrayList;
import java.util.List;

@Mod(value = Ipwl.MOD_ID, dist = Dist.DEDICATED_SERVER)
public final class Ipwl {
    public static final String MOD_ID = "ipwl";
    public static final Logger LOGGER = LogUtils.getLogger();
    private static final int RESYNC_INTERVAL_TICKS = 20 * 30;

    private static AllowList allowList;
    private static SocketFilter socketFilter;
    private static MinecraftServer server;
    private static int ticks;

    public Ipwl() {
        allowList = new AllowList(FMLPaths.CONFIGDIR.get().resolve("ipwl.json"), LOGGER);
        try {
            allowList.load();
        } catch (IOException | RuntimeException e) {
            throw new IllegalStateException("Failed to load config/ipwl.json", e);
        }
        socketFilter = new SocketFilter(LOGGER);
        updateProgram();
        LOGGER.info("IP allowlist {} with {} entries", allowList.isEnabled() ? "enabled" : "disabled", allowList.rules().size());

        NeoForge.EVENT_BUS.addListener(RegisterCommandsEvent.class, e -> IpwlCommands.register(e.getDispatcher()));
        NeoForge.EVENT_BUS.addListener(ServerStartedEvent.class, e -> onServerStarted(e.getServer()));
        NeoForge.EVENT_BUS.addListener(ServerStoppedEvent.class, e -> {
            socketFilter.clear();
            server = null;
        });
        NeoForge.EVENT_BUS.addListener(ServerTickEvent.Post.class, e -> {
            if (++ticks % RESYNC_INTERVAL_TICKS == 0) socketFilter.sync(false);
        });
    }

    public static AllowList allowList() {
        return allowList;
    }

    public static SocketFilter socketFilter() {
        return socketFilter;
    }

    public static void protectGameListener(Channel channel, int port) {
        if (socketFilter == null) return;
        int boundPort = channel.localAddress() instanceof InetSocketAddress a ? a.getPort() : port;
        socketFilter.protect(new SocketFilter.Target(boundPort, true, "game"));
    }

    private static void onServerStarted(MinecraftServer srv) {
        server = srv;
        if (srv instanceof DedicatedServer ds) {
            DedicatedServerProperties props = ds.getProperties();
            if (props.enableRcon) socketFilter.protect(new SocketFilter.Target(props.rconPort, true, "RCON"));
            if (props.enableQuery) socketFilter.protect(new SocketFilter.Target(props.queryPort, false, "query"));
        }
    }

    public static boolean isAllowed(SocketAddress address) {
        if (allowList == null || !(address instanceof InetSocketAddress isa)) return true;
        InetAddress ip = isa.getAddress();
        return ip == null || allowList.isAllowed(ip);
    }

    static void updateProgram() {
        List<BpfProgram.Insn> program;
        if (allowList.isEnabled()) {
            List<CidrRule> all = new ArrayList<>(AllowList.LOOPBACK);
            all.addAll(allowList.rules());
            program = BpfProgram.compile(all);
        } else {
            program = BpfProgram.acceptAll();
        }
        socketFilter.setProgram(program);
    }

    static int kickDisallowed() {
        if (server == null) return 0;
        int kicked = 0;
        for (ServerPlayer p : List.copyOf(server.getPlayerList().getPlayers())) {
            if (!isAllowed(p.connection.getConnection().getRemoteAddress())) {
                p.connection.disconnect(Component.literal("Your IP address is no longer allowlisted"));
                kicked++;
            }
        }
        return kicked;
    }

    static void checkedIo(IoAction action) {
        try {
            action.run();
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    @FunctionalInterface
    interface IoAction {
        void run() throws IOException;
    }
}

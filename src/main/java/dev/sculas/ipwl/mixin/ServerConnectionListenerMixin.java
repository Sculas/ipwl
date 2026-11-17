package dev.sculas.ipwl.mixin;

import dev.sculas.ipwl.Ipwl;
import io.netty.channel.ChannelFuture;
import net.minecraft.server.network.ServerConnectionListener;
import org.spongepowered.asm.mixin.Final;
import org.spongepowered.asm.mixin.Mixin;
import org.spongepowered.asm.mixin.Shadow;
import org.spongepowered.asm.mixin.injection.At;
import org.spongepowered.asm.mixin.injection.Inject;
import org.spongepowered.asm.mixin.injection.callback.CallbackInfo;

import java.net.InetAddress;
import java.util.List;

@Mixin(ServerConnectionListener.class)
public abstract class ServerConnectionListenerMixin {
    @Shadow
    @Final
    private List<ChannelFuture> channels;

    @Inject(method = "startTcpServerListener", at = @At("TAIL"))
    private void ipwl$protectListener(InetAddress address, int port, CallbackInfo ci) {
        synchronized (channels) {
            if (!channels.isEmpty()) {
                Ipwl.protectGameListener(channels.get(channels.size() - 1).channel(), port);
            }
        }
    }
}

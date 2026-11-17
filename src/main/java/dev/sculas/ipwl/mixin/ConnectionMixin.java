package dev.sculas.ipwl.mixin;

import dev.sculas.ipwl.Ipwl;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelOption;
import net.minecraft.network.Connection;
import net.minecraft.network.protocol.PacketFlow;
import org.spongepowered.asm.mixin.Final;
import org.spongepowered.asm.mixin.Mixin;
import org.spongepowered.asm.mixin.Shadow;
import org.spongepowered.asm.mixin.injection.At;
import org.spongepowered.asm.mixin.injection.Inject;
import org.spongepowered.asm.mixin.injection.callback.CallbackInfo;

@Mixin(Connection.class)
public abstract class ConnectionMixin {
    @Shadow
    @Final
    private PacketFlow receiving;

    @Inject(method = "channelActive", at = @At("TAIL"))
    private void ipwl$rejectDisallowed(ChannelHandlerContext ctx, CallbackInfo ci) {
        if (receiving != PacketFlow.SERVERBOUND || Ipwl.isAllowed(ctx.channel().remoteAddress())) return;
        try {
            ctx.channel().config().setOption(ChannelOption.SO_LINGER, 0);
        } catch (RuntimeException ignored) {
        }
        ctx.channel().close();
    }
}

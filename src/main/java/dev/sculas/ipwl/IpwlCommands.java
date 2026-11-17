package dev.sculas.ipwl;

import com.mojang.brigadier.CommandDispatcher;
import com.mojang.brigadier.arguments.StringArgumentType;
import com.mojang.brigadier.context.CommandContext;
import com.mojang.brigadier.exceptions.CommandSyntaxException;
import com.mojang.brigadier.exceptions.SimpleCommandExceptionType;
import net.minecraft.ChatFormatting;
import net.minecraft.commands.CommandSourceStack;
import net.minecraft.commands.Commands;
import net.minecraft.commands.SharedSuggestionProvider;
import net.minecraft.commands.arguments.EntityArgument;
import net.minecraft.network.chat.Component;
import net.minecraft.server.level.ServerPlayer;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.util.List;

final class IpwlCommands {
    private IpwlCommands() {}

    static void register(CommandDispatcher<CommandSourceStack> dispatcher) {
        dispatcher.register(Commands.literal("ipwl")
                .requires(s -> s.hasPermission(Commands.LEVEL_ADMINS))
                .then(Commands.literal("add")
                        .then(Commands.argument("entry", StringArgumentType.greedyString())
                                .executes(IpwlCommands::add)))
                .then(Commands.literal("remove")
                        .then(Commands.argument("entry", StringArgumentType.greedyString())
                                .suggests((ctx, b) -> SharedSuggestionProvider.suggest(
                                        Ipwl.allowList().rules().stream().map(CidrRule::cidr), b))
                                .executes(IpwlCommands::remove)))
                .then(Commands.literal("addplayer")
                        .then(Commands.argument("player", EntityArgument.player())
                                .executes(ctx -> addPlayer(ctx, null))
                                .then(Commands.argument("note", StringArgumentType.greedyString())
                                        .executes(ctx -> addPlayer(ctx, StringArgumentType.getString(ctx, "note"))))))
                .then(Commands.literal("list").executes(IpwlCommands::list))
                .then(Commands.literal("status").executes(IpwlCommands::status))
                .then(Commands.literal("on").executes(ctx -> setEnabled(ctx, true)))
                .then(Commands.literal("off").executes(ctx -> setEnabled(ctx, false)))
                .then(Commands.literal("reload").executes(IpwlCommands::reload)));
    }

    private static CommandSyntaxException error(String msg) {
        return new SimpleCommandExceptionType(Component.literal(msg)).create();
    }

    private static CidrRule parse(String text, String note) throws CommandSyntaxException {
        try {
            return CidrRule.parse(text, note);
        } catch (IllegalArgumentException e) {
            throw error(e.getMessage());
        }
    }

    private static int add(CommandContext<CommandSourceStack> ctx) throws CommandSyntaxException {
        String[] parts = StringArgumentType.getString(ctx, "entry").trim().split("\\s+", 2);
        return addRule(ctx, parse(parts[0], parts.length > 1 ? parts[1] : null));
    }

    private static int addPlayer(CommandContext<CommandSourceStack> ctx, String note) throws CommandSyntaxException {
        ServerPlayer player = EntityArgument.getPlayer(ctx, "player");
        SocketAddress addr = player.connection.getConnection().getRemoteAddress();
        if (!(addr instanceof InetSocketAddress isa) || isa.getAddress() == null) {
            throw error(player.getGameProfile().getName() + " has no IP address");
        }
        String ip = CidrRule.normalize(isa.getAddress()).getHostAddress();
        return addRule(ctx, parse(ip, note != null ? note : player.getGameProfile().getName()));
    }

    private static int addRule(CommandContext<CommandSourceStack> ctx, CidrRule rule) throws CommandSyntaxException {
        try {
            if (!Ipwl.allowList().add(rule)) throw error(rule.cidr() + " is already allowlisted");
            applyOrRollback(() -> Ipwl.allowList().remove(rule));
        } catch (IOException e) {
            throw error("Failed to save config: " + e.getMessage());
        }
        ctx.getSource().sendSuccess(() -> Component.literal("Allowlisted " + rule), true);
        return 1;
    }

    private static int remove(CommandContext<CommandSourceStack> ctx) throws CommandSyntaxException {
        CidrRule rule = parse(StringArgumentType.getString(ctx, "entry").trim(), null);
        CidrRule removed;
        try {
            removed = Ipwl.allowList().remove(rule);
        } catch (IOException e) {
            throw error("Failed to save config: " + e.getMessage());
        }
        if (removed == null) throw error(rule.cidr() + " is not in the allowlist");
        Ipwl.updateProgram();
        int kicked = Ipwl.kickDisallowed();
        ctx.getSource().sendSuccess(() -> Component.literal("Removed " + removed
                + (kicked > 0 ? " and disconnected " + kicked + " player(s)" : "")), true);
        return 1;
    }

    private static int list(CommandContext<CommandSourceStack> ctx) {
        List<CidrRule> rules = Ipwl.allowList().rules();
        CommandSourceStack src = ctx.getSource();
        src.sendSuccess(() -> Component.literal("Allowlist with " + rules.size() + " entries, localhost always allowed:")
                .withStyle(ChatFormatting.GOLD), false);
        for (CidrRule r : rules) {
            src.sendSuccess(() -> Component.literal(" - " + r), false);
        }
        return rules.size();
    }

    private static int status(CommandContext<CommandSourceStack> ctx) {
        AllowList al = Ipwl.allowList();
        SocketFilter sf = Ipwl.socketFilter();
        String mode = !sf.isSupported() ? "The kernel filter only works on Linux"
                : sf.lastError() != null ? "The kernel filter failed with " + sf.lastError()
                : sf.attachedCount() == 0 ? "The kernel filter is not attached to any socket yet"
                : "The kernel filter is active on " + String.join(", ", sf.describe());
        ctx.getSource().sendSuccess(() -> Component.literal("Allowlist " + (al.isEnabled() ? "enabled" : "disabled")
                + " with " + al.rules().size() + " entries. " + mode), false);
        return al.isEnabled() ? 1 : 0;
    }

    private static int setEnabled(CommandContext<CommandSourceStack> ctx, boolean value) throws CommandSyntaxException {
        try {
            Ipwl.allowList().setEnabled(value);
        } catch (IOException e) {
            throw error("Failed to save config: " + e.getMessage());
        }
        Ipwl.updateProgram();
        int kicked = value ? Ipwl.kickDisallowed() : 0;
        ctx.getSource().sendSuccess(() -> Component.literal("Allowlist " + (value ? "enabled" : "disabled")
                + (kicked > 0 ? ", disconnected " + kicked + " player(s)" : "")), true);
        return 1;
    }

    private static int reload(CommandContext<CommandSourceStack> ctx) throws CommandSyntaxException {
        try {
            Ipwl.allowList().load();
        } catch (IOException | RuntimeException e) {
            throw error("Failed to reload config, keeping the current allowlist. " + e.getMessage());
        }
        Ipwl.updateProgram();
        int kicked = Ipwl.kickDisallowed();
        ctx.getSource().sendSuccess(() -> Component.literal("Reloaded " + Ipwl.allowList().rules().size() + " entries"
                + (kicked > 0 ? ", disconnected " + kicked + " player(s)" : "")), true);
        return 1;
    }

    private static void applyOrRollback(Ipwl.IoAction rollback) throws IOException, CommandSyntaxException {
        try {
            Ipwl.updateProgram();
        } catch (IllegalStateException e) {
            rollback.run();
            Ipwl.updateProgram();
            throw error(e.getMessage());
        }
    }
}

package dev.sculas.ipwl;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import org.slf4j.Logger;

import java.io.IOException;
import java.net.InetAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.ArrayList;
import java.util.List;

public final class AllowList {
    public static final List<CidrRule> LOOPBACK = List.of(
            CidrRule.parse("127.0.0.0/8", "loopback"),
            CidrRule.parse("::1", "loopback"));

    private static final Gson GSON = new GsonBuilder().setPrettyPrinting().disableHtmlEscaping().create();

    private final Path file;
    private final Logger logger;
    private volatile boolean enabled = true;
    private volatile List<CidrRule> rules = List.of();

    public AllowList(Path file, Logger logger) {
        this.file = file;
        this.logger = logger;
    }

    public boolean isEnabled() {
        return enabled;
    }

    public List<CidrRule> rules() {
        return rules;
    }

    public boolean isAllowed(InetAddress address) {
        if (!enabled) return true;
        for (CidrRule r : LOOPBACK) if (r.matches(address)) return true;
        for (CidrRule r : rules) if (r.matches(address)) return true;
        return false;
    }

    public synchronized void load() throws IOException {
        if (!Files.exists(file)) {
            save();
            logger.info("Created {}", file);
            return;
        }
        JsonObject root = JsonParser.parseString(Files.readString(file, StandardCharsets.UTF_8)).getAsJsonObject();
        boolean en = !root.has("enabled") || root.get("enabled").getAsBoolean();
        List<CidrRule> list = new ArrayList<>();
        if (root.has("entries")) {
            for (JsonElement e : root.getAsJsonArray("entries")) {
                try {
                    if (e.isJsonPrimitive()) {
                        add(list, CidrRule.parse(e.getAsString(), null));
                    } else {
                        JsonObject o = e.getAsJsonObject();
                        String note = o.has("note") && !o.get("note").isJsonNull() ? o.get("note").getAsString() : null;
                        add(list, CidrRule.parse(o.get("address").getAsString(), note));
                    }
                } catch (RuntimeException ex) {
                    logger.error("Skipping invalid allowlist entry {}: {}", e, ex.getMessage());
                }
            }
        }
        this.enabled = en;
        this.rules = List.copyOf(list);
    }

    private static void add(List<CidrRule> list, CidrRule rule) {
        if (!list.contains(rule)) list.add(rule);
    }

    public synchronized void save() throws IOException {
        JsonObject root = new JsonObject();
        root.addProperty("enabled", enabled);
        JsonArray entries = new JsonArray();
        for (CidrRule r : rules) {
            JsonObject o = new JsonObject();
            o.addProperty("address", r.cidr());
            if (r.note() != null) o.addProperty("note", r.note());
            entries.add(o);
        }
        root.add("entries", entries);
        Files.createDirectories(file.getParent());
        Path tmp = file.resolveSibling(file.getFileName() + ".tmp");
        Files.writeString(tmp, GSON.toJson(root) + "\n", StandardCharsets.UTF_8);
        Files.move(tmp, file, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
    }

    public synchronized boolean add(CidrRule rule) throws IOException {
        if (rules.contains(rule)) return false;
        List<CidrRule> list = new ArrayList<>(rules);
        list.add(rule);
        List<CidrRule> old = rules;
        rules = List.copyOf(list);
        try {
            save();
        } catch (IOException e) {
            rules = old;
            throw e;
        }
        return true;
    }

    public synchronized CidrRule remove(CidrRule rule) throws IOException {
        int idx = rules.indexOf(rule);
        if (idx < 0) return null;
        List<CidrRule> list = new ArrayList<>(rules);
        CidrRule removed = list.remove(idx);
        List<CidrRule> old = rules;
        rules = List.copyOf(list);
        try {
            save();
        } catch (IOException e) {
            rules = old;
            throw e;
        }
        return removed;
    }

    public synchronized void setEnabled(boolean value) throws IOException {
        boolean old = enabled;
        enabled = value;
        try {
            save();
        } catch (IOException e) {
            enabled = old;
            throw e;
        }
    }
}

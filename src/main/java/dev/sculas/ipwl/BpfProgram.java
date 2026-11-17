package dev.sculas.ipwl;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public final class BpfProgram {
    private static final int LD_W_ABS = 0x20;
    private static final int ALU_AND_K = 0x54;
    private static final int JMP_JA = 0x05;
    private static final int JMP_JEQ_K = 0x15;
    private static final int RET_K = 0x06;

    private static final int SKF_AD_PROTOCOL = 0xFFFFF000;
    private static final int SKF_NET_OFF = 0xFFF00000;
    private static final int ETH_P_IP = 0x0800;
    private static final int ETH_P_IPV6 = 0x86DD;
    private static final int IPV4_SRC = 12;
    private static final int IPV6_SRC = 8;
    private static final int ACCEPT = 0xFFFFFFFF;
    private static final int DROP = 0;

    public static final int MAX_INSNS = 4096;

    public record Insn(int code, int jt, int jf, int k) {}

    private final List<Insn> insns = new ArrayList<>();
    private final List<String> jaTargets = new ArrayList<>();
    private final Map<String, Integer> labels = new HashMap<>();

    private BpfProgram() {}

    public static List<Insn> acceptAll() {
        return List.of(new Insn(RET_K, 0, 0, ACCEPT));
    }

    public static List<Insn> compile(List<CidrRule> rules) {
        BpfProgram p = new BpfProgram();
        p.emit(LD_W_ABS, 0, 0, SKF_AD_PROTOCOL);
        p.emit(JMP_JEQ_K, 0, 1, ETH_P_IP);
        p.ja("v4");
        p.emit(JMP_JEQ_K, 0, 1, ETH_P_IPV6);
        p.ja("v6");
        p.emit(RET_K, 0, 0, DROP);

        p.label("v4");
        for (CidrRule r : rules) {
            if (!r.isV4()) continue;
            if (r.prefix() > 0) {
                p.emit(LD_W_ABS, 0, 0, SKF_NET_OFF + IPV4_SRC);
                if (r.prefix() < 32) p.emit(ALU_AND_K, 0, 0, r.wordMask(0));
                p.emit(JMP_JEQ_K, 0, 1, r.word(0));
            }
            p.ja("accept");
        }
        p.emit(RET_K, 0, 0, DROP);

        p.label("v6");
        for (CidrRule r : rules) {
            if (r.isV4()) continue;
            List<Insn> block = new ArrayList<>();
            List<Integer> jeqs = new ArrayList<>();
            for (int w = 0; w < 4 && r.wordMask(w) != 0; w++) {
                block.add(new Insn(LD_W_ABS, 0, 0, SKF_NET_OFF + IPV6_SRC + w * 4));
                if (r.wordMask(w) != 0xFFFFFFFF) block.add(new Insn(ALU_AND_K, 0, 0, r.wordMask(w)));
                jeqs.add(block.size());
                block.add(new Insn(JMP_JEQ_K, 0, 0, r.word(w)));
            }
            int len = block.size() + 1;
            for (int idx : jeqs) {
                Insn j = block.get(idx);
                block.set(idx, new Insn(j.code(), 0, len - 1 - idx, j.k()));
            }
            for (Insn i : block) p.emit(i.code(), i.jt(), i.jf(), i.k());
            p.ja("accept");
        }
        p.emit(RET_K, 0, 0, DROP);

        p.label("accept");
        p.emit(RET_K, 0, 0, ACCEPT);
        return p.resolve();
    }

    private void emit(int code, int jt, int jf, int k) {
        insns.add(new Insn(code, jt, jf, k));
        jaTargets.add(null);
    }

    private void ja(String label) {
        insns.add(new Insn(JMP_JA, 0, 0, 0));
        jaTargets.add(label);
    }

    private void label(String name) {
        labels.put(name, insns.size());
    }

    private List<Insn> resolve() {
        if (insns.size() > MAX_INSNS) {
            throw new IllegalStateException("The allowlist needs " + insns.size() + " BPF instructions and the limit is " + MAX_INSNS);
        }
        List<Insn> out = new ArrayList<>(insns.size());
        for (int i = 0; i < insns.size(); i++) {
            String target = jaTargets.get(i);
            out.add(target == null ? insns.get(i) : new Insn(JMP_JA, 0, 0, labels.get(target) - (i + 1)));
        }
        return out;
    }
}

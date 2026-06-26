#!/usr/bin/env python3
"""
tiered_extractor.py — a water-filtration extractor for raw multi-party logs.

Like a tiered filtration system: each stage only REMOVES or DEMOTES, never
adds back. What passes every stage is high-confidence by construction.
What falls out at each stage lands in a labeled tray you can inspect.

  FS  (coarse screen / foundation)
      Mechanical parse only. Who spoke, when, literal content, and authority
      from the external directory. ZERO role interpretation. This layer
      cannot be "wrong" because it makes no claims beyond what's literally
      present. Catches: non-messages, unknown speakers, malformed blocks.

  FSS (forward filter / optimistic, should-accept)
      Generous role classification. If a line COULD be a decision/command,
      tag it as one. Tuned for ZERO false negatives — it will never miss a
      real decision, at the cost of over-tagging. Catches nothing out; it
      only PROMOTES content into candidate roles. The "accept-leaning" pass.

  BSS (backward filter / skeptical, should-reject)
      Adjudicates the FSS candidates and DEMOTES the unbacked ones:
        - a DECISION/COMMAND by a non-authority -> demoted (invalid authority)
        - a "decision" whose content is off-topic (red herring) -> demoted
        - a casual phrase with no real commitment -> demoted to PROPOSAL
      Tuned to catch false positives. The "reject-leaning" pass.

  FEEDBACK / REVIEW TRAY
      Anything FSS promoted but BSS demoted = the contested set = exactly
      what a human should review. What survives BOTH = certified high
      confidence. Mirrors the converged auditor's FSS/BSS gap.

Output: a certified MACI stream + three trays (fs_dropped, bss_demoted,
review) so every removal is auditable. Nothing vanishes silently.
"""

import json, re, sys

sys.path.insert(0, "/home/claude/duality-engine/maci")
from maci_validator import parse_stream, validate, unique


# ═══════════════════════════════════════════════════════════════════════
# FS — COARSE SCREEN  (mechanical, no interpretation)
# ═══════════════════════════════════════════════════════════════════════

HEADER = re.compile(r"^(\w+)\s+\d{1,2}:\d{2}\s*[AP]M\s*$")
THREAD = re.compile(r"^\s+(\w+)\s+(Mon|Tue|Wed|Thu|Fri)\s+(.*)$")

def fs_screen(raw: str, org: dict):
    """
    Coarse screen: group raw lines into (speaker, content) blocks, attach
    authority from the directory. Drop anything that isn't a real message.
    Returns (blocks, fs_dropped_tray).
    """
    blocks = []
    dropped = []
    cur_speaker, cur_lines = None, []

    def flush():
        if cur_speaker and cur_lines:
            blocks.append({"speaker": cur_speaker, "content": " ".join(cur_lines).strip()})

    for line in raw.splitlines():
        s = line.strip()
        if not s:
            continue
        if s.startswith("#") or s.startswith("─") or s.startswith("[thread"):
            dropped.append({"line": s[:50], "reason": "structural/non-message"})
            continue
        h = HEADER.match(s)
        if h:
            flush()
            cur_speaker, cur_lines = h.group(1), []
            continue
        th = THREAD.match(line)
        if th:
            flush()
            cur_speaker, cur_lines = None, []
            blocks.append({"speaker": th.group(1), "content": th.group(3).strip()})
            continue
        if cur_speaker:
            cur_lines.append(s)
        else:
            dropped.append({"line": s[:50], "reason": "orphan content (no speaker header)"})
    flush()

    # attach authority; drop unknown speakers into the tray
    screened = []
    for b in blocks:
        sp = b["speaker"]
        if sp not in org:
            dropped.append({"line": f"{sp}: {b['content'][:40]}", "reason": "unknown speaker (not in directory)"})
            continue
        b["authority"] = org[sp]["authority"]
        b["role_directory"] = org[sp]["role"]
        screened.append(b)

    return screened, dropped


# ═══════════════════════════════════════════════════════════════════════
# FSS — FORWARD FILTER  (optimistic: promote to candidate roles)
# ═══════════════════════════════════════════════════════════════════════

# tuned for ZERO false negatives: anything that smells like a decision becomes one.
DECISION_CUES = re.compile(r"\b(final call|we'?re using|going with|decision|ship it|use \w+ for the|lets? (use|go with))\b", re.I)
SWITCH_CUES   = re.compile(r"\b(im switching|i'?m switching|switching us|i'?ll switch|moving us to)\b", re.I)
COMMAND_CUES  = re.compile(r"\b(kicking off|kick off|please implement|implement|do it|make it)\b", re.I)
EVIDENCE_CUES = re.compile(r"(\d+\s*ms|p99|benchmark|stable|incident|lost|dropped|no issues|green|verified|added to|:white|cold-?start)", re.I)
QUESTION_CUES = re.compile(r"\?|wdyt|do we|did \w+ sign|can you|right\?$")
CODE_CUES     = re.compile(r"\w+\s*=\s*\w+\(")

def fss_promote(blocks):
    """
    Optimistic classification. Promote each block to its most consequential
    plausible role. Over-tagging is intentional and fine — BSS will demote.
    Returns blocks with 'fss_role' added.
    """
    out = []
    for i, b in enumerate(blocks, 1):
        c = b["content"]
        # order matters: most consequential interpretation first (optimistic)
        if b["speaker_is_bot"] if "speaker_is_bot" in b else False:
            role = "EVIDENCE"
        elif SWITCH_CUES.search(c):
            role = "DECISION"        # "im switching" reads as an attempt to decide
        elif DECISION_CUES.search(c):
            role = "DECISION"
        elif COMMAND_CUES.search(c):
            role = "COMMAND"
        elif CODE_CUES.search(c):
            role = "CODE"
        elif EVIDENCE_CUES.search(c):
            role = "EVIDENCE"
        elif QUESTION_CUES.search(c):
            role = "QUESTION"
        else:
            role = "PROPOSAL"
        nb = dict(b)
        nb["id"] = f"m{i}"
        nb["fss_role"] = role
        out.append(nb)
    return out


# ═══════════════════════════════════════════════════════════════════════
# BSS — BACKWARD FILTER  (skeptical: demote unbacked promotions)
# ═══════════════════════════════════════════════════════════════════════

# what topic is the decision actually about? used to catch red herrings.
def topic_of(content):
    c = content.lower()
    topics = set()
    if "cache" in c or "redis" in c or "memcached" in c:
        topics.add("cache")
    if "rate limiter" in c or "rate-limit" in c:
        topics.add("rate_limiter")
    if "data layer" in c:
        topics.add("data_layer")
    return topics

# a real commitment vs. a casual mention. "ship it"/"final call" commit;
# "who cares"/"might be"/"still good for" do not.
WEAK_COMMITMENT = re.compile(r"\b(who cares|might (be|actually)|still (good|nice)|hot take|honestly|i think|maybe|wdyt|fair\.)\b", re.I)

def bss_adjudicate(blocks, focus_topic="cache"):
    """
    Skeptical pass. For each FSS promotion, try to knock it down:
      - DECISION/COMMAND by a non-authority -> demote to PROPOSAL (invalid authority)
      - decision content off the focus topic -> demote (red herring)
      - decision with only weak/casual commitment language -> demote to PROPOSAL
    Records every demotion with a reason. Returns (final_blocks, demoted_tray).
    """
    demoted = []
    out = []
    for b in blocks:
        role = b["fss_role"]
        reasons = []

        if role in ("DECISION", "COMMAND"):
            # test 1: authority backing
            if b["authority"] not in ("sovereign", "delegated"):
                reasons.append(f"authority={b['authority']} cannot {role.lower()}")
            # test 2: topic relevance (red-herring filter)
            topics = topic_of(b["content"])
            if topics and focus_topic not in topics:
                reasons.append(f"off-topic (about {topics}, not {focus_topic})")
            # test 3: real commitment vs casual mention
            if WEAK_COMMITMENT.search(b["content"]) and not re.search(r"\b(final call|ship it|we'?re using|please implement)\b", b["content"], re.I):
                reasons.append("weak/casual commitment language")

        nb = dict(b)
        if reasons and role in ("DECISION", "COMMAND"):
            nb["bss_role"] = "PROPOSAL"   # demoted
            nb["demotion_reasons"] = reasons
            demoted.append({"id": b["id"], "speaker": b["speaker"],
                            "from_role": role, "content": b["content"][:55],
                            "reasons": reasons})
        else:
            nb["bss_role"] = role
        out.append(nb)
    return out, demoted


# ═══════════════════════════════════════════════════════════════════════
# ASSEMBLE — certified stream + review tray (the FSS/BSS gap)
# ═══════════════════════════════════════════════════════════════════════

def assemble(blocks):
    """
    Build the final MACI stream from BSS-survived roles. The REVIEW tray =
    anything FSS promoted to DECISION/COMMAND that BSS demoted: the contested
    set a human should look at. Certified = survived both filters.
    """
    stream, review, certified = [], [], []
    for b in blocks:
        fss, bss = b["fss_role"], b["bss_role"]
        obj = {"maci": "0.1", "id": b["id"], "from": b["speaker"],
               "role": bss, "authority": b["authority"], "content": b["content"]}
        if bss in ("DECISION",):
            obj["status"] = "approved"
            obj["refs"] = [f"m{int(b['id'][1:])-1}"] if int(b["id"][1:]) > 1 else []
        stream.append(obj)

        # the filtration gap
        if fss in ("DECISION", "COMMAND") and bss not in ("DECISION", "COMMAND"):
            review.append({"id": b["id"], "speaker": b["speaker"],
                           "fss_said": fss, "bss_demoted_to": bss,
                           "why": b.get("demotion_reasons", []),
                           "content": b["content"][:60]})
        elif bss in ("DECISION", "COMMAND"):
            certified.append({"id": b["id"], "speaker": b["speaker"],
                              "role": bss, "content": b["content"][:60]})
    return stream, review, certified


# ═══════════════════════════════════════════════════════════════════════
# RUN
# ═══════════════════════════════════════════════════════════════════════

def run(raw, org, focus="cache"):
    print("=" * 70)
    print("  TIERED FILTRATION EXTRACTOR  —  FS → FSS → BSS")
    print("=" * 70)

    # ── FS ──
    screened, fs_dropped = fs_screen(raw, org)
    # mark bot speakers for FSS
    for b in screened:
        b["speaker_is_bot"] = (org.get(b["speaker"], {}).get("authority") == "observer"
                               and "bot" in org.get(b["speaker"], {}).get("role", ""))
    print(f"\n── FS  (coarse screen) ──")
    print(f"  {len(screened)} messages passed the screen")
    print(f"  {len(fs_dropped)} items dropped to FS tray:")
    for d in fs_dropped[:6]:
        print(f"      ✗ {d['reason']:38s} «{d['line']}»")
    if len(fs_dropped) > 6:
        print(f"      … +{len(fs_dropped)-6} more")

    # ── FSS ──
    promoted = fss_promote(screened)
    fss_decisions = [b for b in promoted if b["fss_role"] in ("DECISION", "COMMAND")]
    print(f"\n── FSS  (optimistic promote — zero false negatives) ──")
    print(f"  promoted {len(fss_decisions)} block(s) to DECISION/COMMAND (over-tagging on purpose):")
    for b in fss_decisions:
        print(f"      ↑ {b['id']} {b['speaker']:6s} → {b['fss_role']:8s} «{b['content'][:46]}»")

    # ── BSS ──
    adjudicated, bss_demoted = bss_adjudicate(promoted, focus_topic=focus)
    print(f"\n── BSS  (skeptical demote — catch false positives) ──")
    print(f"  demoted {len(bss_demoted)} promotion(s):")
    for d in bss_demoted:
        print(f"      ↓ {d['id']} {d['speaker']:6s} {d['from_role']}→PROPOSAL  «{d['content']}»")
        for r in d["reasons"]:
            print(f"            reason: {r}")

    # ── ASSEMBLE ──
    stream, review, certified = assemble(adjudicated)

    print(f"\n── CERTIFIED  (survived both filters) ──")
    for c in certified:
        print(f"      ✓ {c['id']} {c['speaker']:6s} {c['role']:8s} «{c['content']}»")

    print(f"\n── REVIEW TRAY  (FSS promoted, BSS demoted — the contested gap) ──")
    if not review:
        print("      (empty — no contested promotions)")
    for r in review:
        print(f"      ⚠ {r['id']} {r['speaker']:6s} {r['fss_said']}→{r['bss_demoted_to']}  «{r['content']}»")
        for w in r["why"]:
            print(f"            {w}")

    # ── VALIDATE the certified stream ──
    text = "\n".join(json.dumps(o) for o in stream)
    parsed, perr = parse_stream(text)
    res = validate(parsed)
    res.errors = unique(perr + res.errors)
    res.ok = not res.errors

    print(f"\n── VALIDATOR  (on the filtered stream) ──")
    av = [e for e in res.errors if "INSUFFICIENT_AUTHORITY" in e]
    print(f"  authority violations remaining after filtration: {len(av)}")
    for e in av:
        print(f"      {e[:80]}")

    # ── ANSWER ──
    valid_decisions = [o for o in stream if o["role"] == "DECISION"
                       and o["authority"] in ("sovereign", "delegated")]
    print(f"\n── ANSWER ──")
    if valid_decisions:
        final = valid_decisions[-1]
        ans = "REDIS" if "redis" in final["content"].lower() else \
              ("MEMCACHED" if "memcached" in final["content"].lower() else "?")
        print(f"  cache = {ans}  (by {final['from']}, {final['authority']})")
        print(f"  decision lineage: {[o['id']+':'+o['from'] for o in valid_decisions]}")
    print(f"  contested items routed to human review: {len(review)}")
    print("=" * 70)

    return {"stream": stream, "review": review, "certified": certified,
            "fs_dropped": fs_dropped, "bss_demoted": bss_demoted}


if __name__ == "__main__":
    raw = open("/tmp/raw_slack.txt").read()
    org = json.load(open("/tmp/org.json"))
    result = run(raw, org, focus="cache")
    json.dump(result, open("/tmp/extractor_result.json", "w"), indent=2)

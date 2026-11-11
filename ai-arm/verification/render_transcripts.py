# Operator tool (not part of the AI arm).
# Renders each run's raw transcript log (ai-arm/runN/transcript/transcript-raw.jsonl)
# as readable Markdown (transcript.md), and scans every tool call for paths outside
# the run's own folder (isolation check).
#
# Usage, from the repository root:  python ai-arm/verification/render_transcripts.py
import hashlib
import json
import re
from pathlib import Path

ARM = Path(__file__).resolve().parents[1]          # .../ai-arm
FENCE = "~~~~"                                      # cannot clash with ``` in content
PATH_RE = re.compile(r"[A-Za-z]:\\[^\s\"'`;|,)>]+")


def sha256(p: Path) -> str:
    return hashlib.sha256(p.read_bytes()).hexdigest().upper()


for run in ("run1", "run2", "run3"):
    tdir = ARM / run / "transcript"
    raw = tdir / "transcript-raw.jsonl"
    recs = [json.loads(l) for l in raw.read_text(encoding="utf-8").splitlines() if l.strip()]

    # Paths each run was allowed to touch: its own working folder and the shared interpreter.
    allowed = [f"c:\\unsw-runs\\{run}", "c:\\unsw-runs\\env\\scripts\\python.exe"]
    outside = []
    md = [f"# {run} transcript", "",
          f"Rendered from `transcript-raw.jsonl` (SHA256 {sha256(raw)}) by "
          "`ai-arm/verification/render_transcripts.py`. Only formatting was added.",
          "Personal and tool-identifying strings were redacted before rendering (see `ai-arm/README.md`).",
          "The opening prompt is not stored in the log; it is in `../prompt-sent.txt`.",
          "Reasoning entries shown as `...` were redacted by the platform.", ""]
    for r in recs:
        p, ts, t = r["payload"], r["timestamp"], r["payload"].get("type")
        if t == "steering_inclusion":
            md += [f"## [{ts}] Context file injected by the platform", "",
                   *[f"- `{d}`" for d in p.get("documents", [])], ""]
        elif t == "assistant":
            kind = "Final message" if p.get("operationType") == "Say" else "Reasoning summary"
            md += [f"## [{ts}] Assistant: {kind}", "", p.get("content", ""), ""]
        elif t == "tool_call":
            args = p.get("args", {})
            md += [f"## [{ts}] Tool call: `{p.get('toolName')}` (status: {p.get('status')})", "",
                   FENCE + "json", json.dumps(args, indent=2, ensure_ascii=False), FENCE, ""]
            if p.get("toolName") == "execute_pwsh":
                touched = PATH_RE.findall(str(args.get("command", ""))) + ([args["cwd"]] if args.get("cwd") else [])
            else:  # file tools: the target path only, not the file contents
                touched = [str(args[k]) for k in ("path", "targetFile", "file_path") if k in args]
                touched += [str(p["filePath"])] if p.get("filePath") else []
            outside += [(p.get("toolName"), m) for m in touched
                        if not any(m.lower().startswith(a) for a in allowed)]
        elif t == "tool_result":
            md += [f"## [{ts}] Tool result (success: {p.get('success')})", "",
                   FENCE + "text", str(p.get("content", "")), FENCE, ""]
        else:
            md += [f"## [{ts}] {t}", "", FENCE + "json", json.dumps(p, indent=2), FENCE, ""]
    (tdir / "transcript.md").write_text("\n".join(md), encoding="utf-8")
    calls = sum(1 for r in recs if r["payload"].get("type") == "tool_call")
    print(f"{run}: {len(recs)} records, {calls} tool calls, raw SHA256 {sha256(raw)}, "
          f"paths outside own folder: {outside or 'none'}")

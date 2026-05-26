import { useState } from "react";
import CodeMirror from "@uiw/react-codemirror";
import { cpp } from "@codemirror/lang-cpp";
import { oneDark } from "@codemirror/theme-one-dark";
import type { InterruptPoint } from "@/api/client";

type FileTab = "driver.c" | "slice.c" | "assertions.c";

interface Props {
  interrupt: InterruptPoint;
  modifiedFiles: Map<string, string>;
}

export function ManualHarnessEditor({ modifiedFiles }: Props) {
  const [activeTab, setActiveTab] = useState<FileTab>("driver.c");

  const tabs: FileTab[] = ["driver.c", "slice.c", "assertions.c"];

  function getContent(tab: FileTab): string {
    const b64 = modifiedFiles.get(tab);
    if (!b64) return `// ${tab}\n// Write your ${tab.replace(".c", "")} here\n`;
    try {
      return decodeURIComponent(escape(atob(b64)));
    } catch {
      return atob(b64);
    }
  }

  return (
    <div className="space-y-3">
      <p className="text-xs font-semibold text-muted-foreground uppercase tracking-wider">
        Manual Harness Editor (LLM Disabled)
      </p>

      <p className="text-xs text-muted-foreground">
        Write all three files manually. All three must compile before you can submit.
        Turn counter still increments on each submit.
      </p>

      <div className="flex gap-1">
        {tabs.map((tab) => (
          <button
            key={tab}
            onClick={() => setActiveTab(tab)}
            className={`px-2 py-1 text-xs rounded transition-colors ${
              activeTab === tab
                ? "bg-primary text-primary-foreground"
                : "bg-secondary hover:bg-accent"
            }`}
          >
            {tab}
            {modifiedFiles.has(tab) && <span className="ml-1 text-yellow-300">*</span>}
          </button>
        ))}
      </div>

      <p className="text-xs text-muted-foreground">
        Use the [Edit] buttons in the file rows above to modify each file.
        The editor tabs show the current content for reference.
      </p>

      <div className="border border-border rounded overflow-hidden">
        <CodeMirror
          value={getContent(activeTab)}
          extensions={[cpp()]}
          theme={oneDark}
          readOnly
          height="200px"
          basicSetup={{ lineNumbers: true }}
        />
      </div>

      <p className="text-xs text-blue-300">
        ℹ "Submit manual harness" = click "Resume with current inputs" once all files are edited.
      </p>
    </div>
  );
}

import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import CodeMirror from "@uiw/react-codemirror";
import { cpp } from "@codemirror/lang-cpp";
import { json } from "@codemirror/lang-json";
import { oneDark } from "@codemirror/theme-one-dark";
import { getArtifactTree, getArtifactUrl } from "@/api/artifacts";
import type { ArtifactNode } from "@/lib/types";
import { cn } from "@/lib/cn";

interface Props { runId: string; specId: string }

export function ArtifactTree({ runId, specId }: Props) {
  const [selectedPath, setSelectedPath] = useState<string | null>(null);
  const [fileContent, setFileContent] = useState<string>("");
  const [loadingFile, setLoadingFile] = useState(false);

  const { data: tree, isLoading } = useQuery({
    queryKey: ["artifacts", runId, specId],
    queryFn: () => getArtifactTree(runId, specId),
  });

  async function openFile(path: string) {
    setSelectedPath(path);
    setLoadingFile(true);
    try {
      const url = await getArtifactUrl(runId, specId, path);
      const res = await fetch(url);
      const text = await res.text();
      setFileContent(text);
    } catch {
      setFileContent("(failed to load file)");
    } finally {
      setLoadingFile(false);
    }
  }

  const lang = selectedPath?.endsWith(".json") ? json() : cpp();

  if (isLoading) {
    return <div className="h-32 bg-muted rounded animate-pulse" />;
  }

  return (
    <div className="flex gap-3 h-80">
      {/* File tree */}
      <div className="w-48 shrink-0 bg-card border border-border rounded overflow-auto">
        <div className="p-2 border-b border-border text-xs text-muted-foreground font-semibold">
          Artifacts
        </div>
        {tree?.map((node) => (
          <TreeNode
            key={node.path}
            node={node}
            selected={selectedPath}
            onSelect={openFile}
          />
        ))}
        {!tree?.length && (
          <p className="text-xs text-muted-foreground p-2">No artifacts yet</p>
        )}
      </div>

      {/* File viewer */}
      <div className="flex-1 bg-card border border-border rounded overflow-hidden">
        {selectedPath ? (
          <div className="h-full flex flex-col">
            <div className="px-3 py-1.5 border-b border-border text-xs text-muted-foreground flex justify-between">
              <span>{selectedPath}</span>
              <button
                onClick={() => void (async () => {
                  const url = await getArtifactUrl(runId, specId, selectedPath);
                  window.open(url, "_blank");
                })()}
                className="text-primary hover:underline"
              >
                Download
              </button>
            </div>
            {loadingFile ? (
              <div className="flex-1 animate-pulse bg-muted" />
            ) : (
              <div className="flex-1 overflow-auto">
                <CodeMirror
                  value={fileContent}
                  extensions={[lang]}
                  theme={oneDark}
                  readOnly
                  height="100%"
                  basicSetup={{ lineNumbers: true, foldGutter: false }}
                />
              </div>
            )}
          </div>
        ) : (
          <div className="flex items-center justify-center h-full text-xs text-muted-foreground">
            Select a file to view
          </div>
        )}
      </div>
    </div>
  );
}

function TreeNode({
  node,
  selected,
  onSelect,
  depth = 0,
}: {
  node: ArtifactNode;
  selected: string | null;
  onSelect: (path: string) => void;
  depth?: number;
}) {
  const [open, setOpen] = useState(depth === 0);

  if (node.type === "directory") {
    return (
      <div>
        <button
          className="w-full text-left px-2 py-1 text-xs text-muted-foreground hover:bg-accent/20 flex items-center gap-1"
          style={{ paddingLeft: `${8 + depth * 12}px` }}
          onClick={() => setOpen(!open)}
        >
          <span>{open ? "▾" : "▸"}</span>
          {node.name}/
        </button>
        {open && node.children?.map((child) => (
          <TreeNode
            key={child.path}
            node={child}
            selected={selected}
            onSelect={onSelect}
            depth={depth + 1}
          />
        ))}
      </div>
    );
  }

  return (
    <button
      className={cn(
        "w-full text-left px-2 py-1 text-xs hover:bg-accent/20 transition-colors",
        selected === node.path ? "bg-primary/10 text-primary" : "text-foreground"
      )}
      style={{ paddingLeft: `${8 + depth * 12}px` }}
      onClick={() => onSelect(node.path)}
    >
      {node.name}
    </button>
  );
}

import { useState, useRef } from "react";
import CodeMirror from "@uiw/react-codemirror";
import { json } from "@codemirror/lang-json";
import { cpp } from "@codemirror/lang-cpp";
import { oneDark } from "@codemirror/theme-one-dark";
import { FileValidationBanner } from "./FileValidationBanner";
import { validateFile, type ValidationResult } from "@/api/client";

interface InputFile {
  name: string;
  size: number;
  content_type: string;
  artifact_url: string;
}

interface Props {
  file: InputFile;
  interruptId: string;
  onModified: (name: string, contentBase64: string) => void;
}

function isCFile(name: string) {
  return name.endsWith(".c") || name.endsWith(".h");
}

function isJsonFile(name: string) {
  return name.endsWith(".json") || name.endsWith(".sarif");
}

function isEditable(name: string) {
  return isCFile(name) || isJsonFile(name) || name.endsWith(".ql") || name.endsWith(".md");
}

function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes}B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)}KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)}MB`;
}

export function InterruptFileRow({ file, onModified }: Props) {
  const [viewOpen, setViewOpen] = useState(false);
  const [editOpen, setEditOpen] = useState(false);
  const [content, setContent] = useState<string | null>(null);
  const [editContent, setEditContent] = useState("");
  const [loadingContent, setLoadingContent] = useState(false);
  const [validation, setValidation] = useState<ValidationResult | null>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const extensions = isCFile(file.name)
    ? [cpp()]
    : isJsonFile(file.name)
    ? [json()]
    : [];

  async function fetchContent() {
    if (content !== null) return;
    setLoadingContent(true);
    try {
      const resp = await fetch(file.artifact_url);
      const text = await resp.text();
      setContent(text);
      setEditContent(text);
    } finally {
      setLoadingContent(false);
    }
  }

  async function handleView() {
    await fetchContent();
    setViewOpen(true);
  }

  async function handleEdit() {
    await fetchContent();
    setEditOpen(true);
  }

  async function handleSaveEdit() {
    const b64 = btoa(unescape(encodeURIComponent(editContent)));
    const result = await validateFile(file.name, b64);
    setValidation(result);
    if (result.severity !== "error") {
      onModified(file.name, b64);
      setEditOpen(false);
    }
  }

  async function handleReplace(e: React.ChangeEvent<HTMLInputElement>) {
    const f = e.target.files?.[0];
    if (!f) return;
    const reader = new FileReader();
    reader.onload = async () => {
      const b64 = (reader.result as string).split(",")[1] ?? "";
      const result = await validateFile(file.name, b64);
      setValidation(result);
      if (result.severity !== "error") {
        onModified(file.name, b64);
      }
    };
    reader.readAsDataURL(f);
  }

  return (
    <div className="space-y-1">
      <div className="flex items-center gap-2 py-1.5 px-2 bg-secondary/30 rounded text-xs">
        <span className="text-muted-foreground">📄</span>
        <span className="font-mono flex-1 truncate text-foreground">{file.name}</span>
        <span className="text-muted-foreground">{formatBytes(file.size)}</span>
        <span className="text-muted-foreground">{file.content_type}</span>

        <button
          onClick={() => void handleView()}
          className="px-2 py-0.5 bg-secondary hover:bg-accent rounded transition-colors"
        >
          View
        </button>

        {isEditable(file.name) && (
          <button
            onClick={() => void handleEdit()}
            className="px-2 py-0.5 bg-secondary hover:bg-accent rounded transition-colors"
          >
            Edit
          </button>
        )}

        <button
          onClick={() => fileInputRef.current?.click()}
          className="px-2 py-0.5 bg-secondary hover:bg-accent rounded transition-colors"
        >
          Replace ↑
        </button>
        <input
          ref={fileInputRef}
          type="file"
          className="hidden"
          onChange={(e) => void handleReplace(e)}
        />

        <a
          href={file.artifact_url}
          download={file.name}
          className="px-2 py-0.5 bg-secondary hover:bg-accent rounded transition-colors"
        >
          ↓
        </a>
      </div>

      {validation && (
        <FileValidationBanner
          severity={validation.severity}
          message={validation.message}
          detectedFormat={validation.detected_format}
        />
      )}

      {/* View modal */}
      {viewOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70">
          <div className="bg-card border border-border rounded-xl w-full max-w-3xl max-h-[80vh] flex flex-col">
            <div className="flex items-center justify-between px-4 py-2 border-b border-border">
              <span className="text-sm font-semibold text-foreground">{file.name}</span>
              <button onClick={() => setViewOpen(false)} className="text-muted-foreground hover:text-foreground">✕</button>
            </div>
            <div className="flex-1 overflow-auto">
              {loadingContent ? (
                <div className="p-4 text-xs text-muted-foreground">Loading…</div>
              ) : (
                <CodeMirror
                  value={content ?? ""}
                  extensions={extensions}
                  theme={oneDark}
                  readOnly
                  height="60vh"
                  basicSetup={{ lineNumbers: true, foldGutter: true }}
                />
              )}
            </div>
          </div>
        </div>
      )}

      {/* Edit modal */}
      {editOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70">
          <div className="bg-card border border-border rounded-xl w-full max-w-3xl max-h-[80vh] flex flex-col">
            <div className="flex items-center justify-between px-4 py-2 border-b border-border">
              <span className="text-sm font-semibold text-foreground">Edit {file.name}</span>
              <button onClick={() => setEditOpen(false)} className="text-muted-foreground hover:text-foreground">✕</button>
            </div>
            <div className="flex-1 overflow-auto">
              <CodeMirror
                value={editContent}
                onChange={setEditContent}
                extensions={extensions}
                theme={oneDark}
                height="55vh"
                basicSetup={{ lineNumbers: true }}
              />
            </div>
            {validation && (
              <div className="px-4 py-2">
                <FileValidationBanner
                  severity={validation.severity}
                  message={validation.message}
                  detectedFormat={validation.detected_format}
                />
              </div>
            )}
            <div className="px-4 py-2 border-t border-border flex justify-end gap-2">
              <button
                onClick={() => setEditOpen(false)}
                className="px-3 py-1.5 text-xs bg-secondary rounded"
              >
                Cancel
              </button>
              <button
                onClick={() => void handleSaveEdit()}
                className="px-3 py-1.5 text-xs bg-primary text-primary-foreground rounded"
              >
                Save & include
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

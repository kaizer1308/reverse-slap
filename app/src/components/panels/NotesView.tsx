// app/src/components/panels/NotesView.tsx
// Comments, bookmarks for the current binary

import { useEffect, useState } from "react";
import { Bookmark, MessageSquare, RefreshCw } from "lucide-react";
import { call } from "@/lib/rpc";

type Comment = { address: string; text: string };
type BookmarkEntry = { address: string; label: string };

export default function NotesView() {
  const [tab, setTab] = useState<"comments" | "bookmarks">("comments");
  const [comments, setComments] = useState<Comment[]>([]);
  const [bookmarks, setBookmarks] = useState<BookmarkEntry[]>([]);
  const [addr, setAddr] = useState("");
  const [text, setText] = useState("");
  const [busy, setBusy] = useState(false);

  const refreshComments = async () => {
    try {
      const r = await call<{ comments: Comment[] }>("notes", "comments");
      setComments(r.comments);
    } catch { /* ignore */ }
  };

  const refreshBookmarks = async () => {
    try {
      const r = await call<{ bookmarks: BookmarkEntry[] }>("notes", "bookmarks");
      setBookmarks(r.bookmarks);
    } catch { /* ignore */ }
  };

  const addComment = async () => {
    if (!addr.trim() || !text.trim()) return;
    setBusy(true);
    try {
      await call("notes", "set_comment", { addr, text });
      setAddr(""); setText(""); void refreshComments();
    } catch { /* ignore */ }
    setBusy(false);
  };

  const toggleBookmark = async (address: string) => {
    await call("notes", "bookmark_toggle", { addr: address });
    void refreshBookmarks();
  };

  useEffect(() => { void refreshComments(); void refreshBookmarks(); }, []);

  return (
    <div className="stack">
      <div className="view-bar">
        <button className="row-action" data-active={tab === "comments"} onClick={() => setTab("comments")}>
          <MessageSquare size={11} style={{ marginRight: 4 }} />Comments
        </button>
        <button className="row-action" data-active={tab === "bookmarks"} onClick={() => setTab("bookmarks")}>
          <Bookmark size={11} style={{ marginRight: 4 }} />Bookmarks
        </button>
        <div className="spacer" />
        <button className="icon-button" onClick={() => { void refreshComments(); void refreshBookmarks(); }}>
          <RefreshCw size={12} />
        </button>
      </div>
      <div className="panel-body" style={{ overflow: "auto", padding: "var(--pad-md)" }}>
        {tab === "comments" && (
          <>
            <div style={{ display: "flex", gap: "var(--pad-sm)", marginBottom: "var(--pad-md)" }}>
              <input className="addr-input" placeholder="address" value={addr} onChange={(e) => setAddr(e.target.value)} style={{ width: 140 }} />
              <input className="addr-input" placeholder="comment" value={text} onChange={(e) => setText(e.target.value)} style={{ flex: 1 }} />
              <button className="row-action" disabled={busy} onClick={() => void addComment()}>Add</button>
            </div>
            <table className="table">
              <thead><tr><th>Address</th><th>Comment</th></tr></thead>
              <tbody>
                {comments.map((c, i) => <tr key={i}><td className="mono">{c.address}</td><td>{c.text}</td></tr>)}
              </tbody>
            </table>
          </>
        )}

        {tab === "bookmarks" && (
          <table className="table">
            <thead><tr><th>Address</th><th>Label</th><th></th></tr></thead>
            <tbody>
              {bookmarks.map((b, i) => (
                <tr key={i}>
                  <td className="mono">{b.address}</td><td>{b.label}</td>
                  <td><button className="row-action" onClick={() => void toggleBookmark(b.address)}>✗</button></td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}

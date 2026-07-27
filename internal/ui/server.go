package ui

import (
	_ "embed"

	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"html/template"
	"log"
	"math"
	"net"
	"net/http"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/syndichan/maniwani/storage-client/internal/store"
)

// The site's own logo, compiled into the binary. Embedded rather than fetched
// because this node runs behind I2P and must never reach the web server for an
// asset -- and a volunteer's dashboard should not phone home to render.
//
//go:embed icon.png
var IconPNG []byte

type NodeInfo interface {
	ID() string
	Addresses() []string
	// PeerCount is a live gauge: volunteers are dial-in only, so it falls to
	// zero whenever a connection lapses and recovers on the next retry.
	PeerCount() int
}

type Server struct {
	store    *store.Store
	node     NodeInfo
	csrf     string
	logger   *log.Logger
	template *template.Template
	dataDir  string
	saveDir  func(string) error
}

// SetStoragePaths tells the dashboard where shards live and how to persist a
// change. Kept off New() so existing callers and tests are unaffected.
func (s *Server) SetStoragePaths(dataDir string, save func(string) error) {
	s.dataDir = dataDir
	s.saveDir = save
}

func New(storage *store.Store, node NodeInfo, logger *log.Logger) *Server {
	tokenBytes := make([]byte, 32)
	if _, err := rand.Read(tokenBytes); err != nil {
		panic(err)
	}
	return &Server{
		store: storage, node: node,
		csrf: base64.RawURLEncoding.EncodeToString(tokenBytes), logger: logger,
		template: template.Must(template.New("dashboard").Parse(pageHTML)),
	}
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if !validDashboardHost(r.Host) {
		http.Error(w, "invalid dashboard host", http.StatusMisdirectedRequest)
		return
	}
	w.Header().Set("Content-Security-Policy", "default-src 'self'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; object-src 'none'; frame-ancestors 'none'")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("Cache-Control", "no-store")
	switch {
	case r.URL.Path == "/" && r.Method == http.MethodGet:
		s.dashboard(w)
	case r.URL.Path == "/favicon.png" && r.Method == http.MethodGet:
		w.Header().Set("Content-Type", "image/png")
		w.Header().Set("Cache-Control", "public, max-age=86400")
		_, _ = w.Write(IconPNG)
	case r.URL.Path == "/api/status" && r.Method == http.MethodGet:
		s.status(w)
	case r.URL.Path == "/api/items" && r.Method == http.MethodGet:
		s.items(w)
	case r.URL.Path == "/reject" && r.Method == http.MethodPost:
		s.reject(w, r)
	case r.URL.Path == "/capacity" && r.Method == http.MethodPost:
		s.setCapacity(w, r)
	case r.URL.Path == "/storage-dir" && r.Method == http.MethodPost:
		s.setStorageDir(w, r)
	default:
		http.NotFound(w, r)
	}
}

func validDashboardHost(value string) bool {
	host, _, err := net.SplitHostPort(value)
	if err != nil {
		host = value
	}
	host = strings.Trim(host, "[]")
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func (s *Server) dashboard(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = s.template.Execute(w, map[string]string{"CSRF": s.csrf})
}

func (s *Server) status(w http.ResponseWriter) {
	used, _ := s.store.UsedBytes()
	writeJSON(w, map[string]any{
		"node_id": s.node.ID(), "addresses": s.node.Addresses(),
		"used_bytes": used, "capacity_bytes": s.store.Capacity(),
		"peers": s.node.PeerCount(), "i2p_address": i2pAddress(s.node.Addresses()),
		"data_dir": s.dataDir,
	})
}

func (s *Server) setCapacity(w http.ResponseWriter, r *http.Request) {
	if subtle.ConstantTimeCompare([]byte(r.FormValue("csrf")), []byte(s.csrf)) != 1 {
		http.Error(w, "invalid request token", http.StatusForbidden)
		return
	}
	gib, err := strconv.ParseFloat(r.FormValue("capacity_gib"), 64)
	if err != nil || math.IsNaN(gib) || math.IsInf(gib, 0) || gib <= 0 ||
		gib > float64(store.MaxCapacityBytes)/(1<<30) {
		http.Error(w, "invalid storage allocation", http.StatusBadRequest)
		return
	}
	capacity := int64(math.Round(gib * (1 << 30)))
	if err := s.store.SetCapacity(capacity); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	s.logger.Printf("user changed storage allocation to %d bytes", capacity)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (s *Server) items(w http.ResponseWriter) {
	items, err := s.store.ListStored()
	if err != nil {
		http.Error(w, "could not list stored data", http.StatusInternalServerError)
		return
	}
	writeJSON(w, map[string]any{"items": items})
}

func (s *Server) reject(w http.ResponseWriter, r *http.Request) {
	if subtle.ConstantTimeCompare([]byte(r.FormValue("csrf")), []byte(s.csrf)) != 1 {
		http.Error(w, "invalid request token", http.StatusForbidden)
		return
	}
	kind, id := r.FormValue("kind"), r.FormValue("id")
	if err := s.store.RejectAndRemove(kind, id); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	s.logger.Printf("user rejected stored %s %s", kind, id)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// i2pAddress pulls the .b32.i2p host out of a /garlic32/<b32>/p2p/<id>
// multiaddr, which is the form a person can actually read and share.
func i2pAddress(addresses []string) string {
	for _, address := range addresses {
		parts := strings.Split(address, "/")
		for index, part := range parts {
			if part == "garlic32" && index+1 < len(parts) && parts[index+1] != "" {
				return parts[index+1] + ".b32.i2p"
			}
		}
	}
	return ""
}

func (s *Server) setStorageDir(w http.ResponseWriter, r *http.Request) {
	if subtle.ConstantTimeCompare([]byte(r.FormValue("csrf")), []byte(s.csrf)) != 1 {
		http.Error(w, "invalid request token", http.StatusForbidden)
		return
	}
	if s.saveDir == nil {
		http.Error(w, "storage location is not configurable here", http.StatusBadRequest)
		return
	}
	target := strings.TrimSpace(r.FormValue("data_dir"))
	if target == "" || !filepath.IsAbs(target) {
		http.Error(w, "enter an absolute path", http.StatusBadRequest)
		return
	}
	// Persist only. The shard store and its bolt database are OPEN right now;
	// moving them under a running process risks corrupting both, so the change
	// takes effect on the next start and the page says so.
	if err := s.saveDir(target); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	s.logger.Printf("user set storage location to %s (effective next start)", target)
	http.Redirect(w, r, "/?moved=1", http.StatusSeeOther)
}

func writeJSON(w http.ResponseWriter, value any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(value)
}

const pageHTML = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Syndichan Storage Node</title>
<link rel="icon" type="image/png" href="/favicon.png">
<style>
/* Palette mirrors the site's dark themes and uses the same --sc-* naming
   convention. It is duplicated rather than imported on purpose: this node runs
   offline behind I2P and must never reach out to the web server for an asset. */
:root{
  --sc-bg:#0e1116; --sc-panel:#161b22; --sc-panel-2:#1b2230; --sc-border:#2b3440;
  --sc-fg:#d7e0ea; --sc-muted:#8b9bad; --sc-accent:#4ba3e3; --sc-accent-dim:#2b6ea3;
  --sc-ok:#3fa45e; --sc-danger:#a72b3a; --sc-warn:#c9922f;
  --sc-mono:ui-monospace,SFMono-Regular,Menlo,Consolas,"Liberation Mono",monospace;
}
*,*::before,*::after{box-sizing:border-box}
body{margin:0;background:var(--sc-bg);color:var(--sc-fg);
  font:15px/1.5 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
header{background:var(--sc-panel);border-bottom:1px solid var(--sc-border);padding:14px 20px}
header .wrap{max-width:1060px;margin:auto;display:flex;align-items:baseline;gap:12px;flex-wrap:wrap}
header h1{margin:0;font-size:1.15rem;letter-spacing:.02em}
header .tag{color:var(--sc-muted);font-size:.85rem}
main{max-width:1060px;margin:auto;padding:20px}
.panel{background:var(--sc-panel);border:1px solid var(--sc-border);border-radius:8px;
  padding:16px 18px;margin:0 0 16px}
.panel h2{margin:0 0 4px;font-size:1rem;color:var(--sc-fg)}
.muted{color:var(--sc-muted);font-size:.9rem}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:14px;margin-top:12px}
.stat{background:var(--sc-panel-2);border:1px solid var(--sc-border);border-radius:6px;padding:12px}
.stat .k{color:var(--sc-muted);font-size:.78rem;text-transform:uppercase;letter-spacing:.06em}
.stat .v{font-size:1.5rem;margin-top:2px}
.stat .v.small{font-size:.95rem;font-family:var(--sc-mono);word-break:break-all;line-height:1.35}
.dot{display:inline-block;width:9px;height:9px;border-radius:50%;margin-right:6px;vertical-align:baseline}
.dot.on{background:var(--sc-ok)}.dot.off{background:var(--sc-danger)}
.bar{height:10px;background:var(--sc-panel-2);border:1px solid var(--sc-border);
  border-radius:6px;overflow:hidden;margin-top:8px}
.bar span{display:block;height:100%;background:var(--sc-accent)}
form{display:flex;gap:10px;align-items:center;flex-wrap:wrap;margin-top:10px}
input{background:var(--sc-bg);color:var(--sc-fg);border:1px solid var(--sc-border);
  border-radius:5px;padding:7px 9px;font:inherit}
input[type=number]{width:9rem}input[name=data_dir]{flex:1;min-width:16rem;font-family:var(--sc-mono);font-size:.9rem}
button{border:0;border-radius:5px;padding:8px 12px;cursor:pointer;font:inherit;color:#fff;
  background:var(--sc-accent-dim)}
button:hover{background:var(--sc-accent)}
button.danger{background:var(--sc-danger)}
table{width:100%;border-collapse:collapse;margin-top:10px}
th,td{text-align:left;padding:9px 8px;border-bottom:1px solid var(--sc-border);vertical-align:top}
th{color:var(--sc-muted);font-size:.78rem;text-transform:uppercase;letter-spacing:.05em}
td code{font-family:var(--sc-mono);font-size:.82rem;color:var(--sc-muted);word-break:break-all}
.notice{border-left:3px solid var(--sc-warn);background:var(--sc-panel-2);padding:9px 12px;
  border-radius:0 5px 5px 0;margin-top:10px;font-size:.9rem}
.copy{background:transparent;border:1px solid var(--sc-border);color:var(--sc-muted);padding:3px 8px;font-size:.78rem}
@media(max-width:560px){.stat .v{font-size:1.2rem}}
</style>
</head>
<body>
<header><div class="wrap"><img src="/favicon.png" alt="" width="24" height="24" style="border-radius:4px"><h1>Syndichan</h1><span class="tag">Storage Node</span></div></header>
<main>
<p class="muted">Only encrypted shards are stored here. Nothing is readable without the
site's keys, and rejecting an item deletes its bytes and refuses that content ID in future.</p>

<section class="panel">
  <h2>Node</h2>
  <div class="grid" id="stats">
    <div class="stat"><div class="k">Peers connected</div><div class="v" id="peers">&mdash;</div></div>
    <div class="stat"><div class="k">Stored</div><div class="v" id="used">&mdash;</div>
      <div class="bar"><span id="bar" style="width:0"></span></div></div>
    <div class="stat"><div class="k">Your I2P address</div>
      <div class="v small" id="i2p">&mdash;</div>
      <button class="copy" type="button" id="copy">Copy</button></div>
    <div class="stat"><div class="k">Node ID</div><div class="v small" id="nodeid">&mdash;</div></div>
  </div>
</section>

<section class="panel">
  <h2>Where shards are stored</h2>
  <p class="muted">Absolute path. Pick a drive with room to spare &mdash; this is where
  encrypted shards accumulate.</p>
  <form method="post" action="/storage-dir">
    <input type="hidden" name="csrf" value="{{.CSRF}}">
    <input name="data_dir" id="datadir" placeholder="/media/drive/syndichan" required>
    <button type="submit">Save location</button>
  </form>
  <div class="notice">Changing this takes effect the next time the node starts, and existing
  shards are not moved for you &mdash; the store is open right now and relocating it underneath
  a running process would risk corrupting it. Copy the old folder across before restarting.</div>
</section>

<section class="panel">
  <h2>Donated disk space</h2>
  <p class="muted">The most disk this node may use. Lowering it never deletes anything on its own.</p>
  <form method="post" action="/capacity">
    <input type="hidden" name="csrf" value="{{.CSRF}}">
    <label>Allocation <input id="capacity" type="number" name="capacity_gib"
      min="0.0625" max="8388608" step="0.25" required></label> GiB
    <button type="submit">Save allocation</button>
  </form>
</section>

<section class="panel">
  <h2>Stored shards</h2>
  <div id="items" class="muted">Loading&hellip;</div>
</section>
</main>
<script>
const csrf={{printf "%q" .CSRF}};
function bytes(n){if(!n)return "0 B";const u=["B","KiB","MiB","GiB","TiB"];let i=0;
  while(n>=1024&&i<u.length-1){n/=1024;i++}return n.toFixed(i?1:0)+" "+u[i]}
function esc(v){const d=document.createElement("div");d.textContent=String(v);return d.innerHTML}
function el(id){return document.getElementById(id)}

function render(s,data){
  const on=(s.peers||0)>0;
  el("peers").innerHTML='<span class="dot '+(on?"on":"off")+'"></span>'+(s.peers||0);
  el("used").textContent=bytes(s.used_bytes)+" / "+bytes(s.capacity_bytes);
  el("bar").style.width=(s.capacity_bytes?Math.min(100,s.used_bytes/s.capacity_bytes*100):0)+"%";
  el("i2p").textContent=s.i2p_address||"not published yet";
  el("nodeid").textContent=s.node_id||"";
  if(s.data_dir&&!el("datadir").value)el("datadir").value=s.data_dir;
  el("capacity").value=(s.capacity_bytes/1073741824).toFixed(2).replace(/\.?0+$/,"");
  const items=data.items||[];
  el("items").innerHTML=items.length?
    "<table><thead><tr><th>Shard</th><th>Type</th><th>Size</th><th></th></tr></thead><tbody>"+
    items.map(i=>"<tr><td>"+esc(i.display_name)+"<br><code>"+esc(i.id)+"</code></td><td>"+
      esc(i.kind)+"</td><td>"+bytes(i.size)+"</td>"+
      "<td><form method=post action=/reject onsubmit=\"return confirm('Remove and reject this item?')\">"+
      "<input type=hidden name=csrf value='"+csrf+"'>"+
      "<input type=hidden name=kind value='"+esc(i.kind)+"'>"+
      "<input type=hidden name=id value='"+esc(i.id)+"'>"+
      "<button class=danger>Reject</button></form></td></tr>").join("")+"</tbody></table>"
    :"<p class=muted>Nothing stored yet. Shards arrive once a peer connects.</p>";
}
function refresh(){
  Promise.all([fetch("/api/status").then(r=>r.json()),fetch("/api/items").then(r=>r.json())])
    .then(([s,d])=>render(s,d))
    .catch(()=>{el("peers").textContent="?";el("items").textContent="Status unavailable."});
}
el("copy").addEventListener("click",()=>{
  const v=el("i2p").textContent;
  if(v&&navigator.clipboard)navigator.clipboard.writeText(v).then(()=>{
    el("copy").textContent="Copied";setTimeout(()=>el("copy").textContent="Copy",1200)})});
refresh();
// Peers and shard count move on their own; poll so the page reflects reality
// without the user reloading to find out whether anything connected.
setInterval(refresh,10000);
</script></body></html>`

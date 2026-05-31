// Command api-catalog-gen generates a machine-readable catalog of dock's
// HTTP API by static analysis (go/ast) of internal/app/dock — no runtime
// reflection, no per-route annotations. For each registered route it
// recovers the request-body fields, query/path/header params, and the
// auth middleware, so the API surface is queryable instead of grepped.
//
// It's a companion to the runtime `GET /api/_routes` (meta_handlers.go):
// that endpoint is authoritative for method+path (it reads the live gin
// router); this generator supplies the *contracts*, joined by handler.
//
// Output: a JSON array of endpoint entries, written to both
//   - internal/app/dock/api_catalog.gen.json  (go:embed → served at /api/_catalog)
//   - doc/api/catalog.json                     (committed, for offline read)
//
// Best-effort by design: it covers the dominant handler pattern
// (`var req struct{...}` / named type + c.ShouldBindJSON, plus direct
// c.Query/c.Param/c.GetHeader literals). Params read indirectly (via
// helpers, loops, variables) are not recovered — the route still appears
// with an empty body, which is still better than grepping.
//
// Usage: go run ./cmd/api-catalog-gen [-dock <dir>] [-out <file>] [-doc <file>]
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"go/ast"
	"go/parser"
	"go/printer"
	"go/token"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
)

// ---- output shapes ----

type field struct {
	Name     string `json:"name"`
	Type     string `json:"type"`
	Required bool   `json:"required,omitempty"`
}

type endpoint struct {
	Method  string  `json:"method"`
	Path    string  `json:"path"`
	Handler string  `json:"handler"`
	Auth    string  `json:"auth,omitempty"` // e.g. "user", "admin", "" (open) / "plugin-hmac"
	Body    []field `json:"body"`
	Query   []field `json:"query"`
	PathP   []field `json:"path_params,omitempty"`
	Headers []field `json:"headers,omitempty"`
}

// contract is the per-handler extract (body+query+path+headers), keyed by
// handler name and later joined onto routes.
type contract struct {
	body    []field
	query   []field
	path    []field
	headers []field
}

type routeReg struct {
	method, path, handler string
	middleware            []string
}

// recvType is the handler receiver type name. dock uses "*Server"; plugin
// modules use "*Plugin" — pass -recv to point the same tool at any module.
var recvType = "Server"

func main() {
	dockDir := flag.String("dock", "internal/app/dock", "package dir to scan")
	out := flag.String("out", "internal/app/dock/api_catalog.gen.json", "embed JSON output")
	docOut := flag.String("doc", "doc/api/catalog.json", "committed doc JSON output")
	recv := flag.String("recv", "Server", "handler receiver type (Server for dock, Plugin for modules)")
	flag.Parse()
	recvType = *recv

	fset := token.NewFileSet()
	pkg, err := parsePackage(fset, *dockDir)
	if err != nil {
		fatal("parse: %v", err)
	}

	namedStructs := collectNamedStructs(pkg)           // type X struct{...}
	contracts := collectContracts(fset, pkg, namedStructs)
	routes := collectRoutes(pkg)

	eps := make([]endpoint, 0, len(routes))
	for _, r := range routes {
		c := contracts[r.handler] // zero value ok (empty contract)
		eps = append(eps, endpoint{
			Method:  r.method,
			Path:    r.path,
			Handler: r.handler,
			Auth:    authOf(r.middleware),
			Body:    nz(c.body),
			Query:   nz(c.query),
			PathP:   c.path,
			Headers: c.headers,
		})
	}
	sort.Slice(eps, func(i, j int) bool {
		if eps[i].Path != eps[j].Path {
			return eps[i].Path < eps[j].Path
		}
		return eps[i].Method < eps[j].Method
	})

	blob, _ := json.MarshalIndent(map[string]any{"count": len(eps), "endpoints": eps}, "", "  ")
	blob = append(blob, '\n')
	writeFile(*out, blob)
	writeFile(*docOut, blob)
	fmt.Printf("api-catalog-gen: %d endpoints (%d with body contracts) → %s, %s\n",
		len(eps), countWithBody(eps), *out, *docOut)
}

// ---- parsing ----

func parsePackage(fset *token.FileSet, dir string) ([]*ast.File, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var files []*ast.File
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, filepath.Join(dir, name), nil, parser.SkipObjectResolution)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", name, err)
		}
		files = append(files, f)
	}
	return files, nil
}

// collectNamedStructs maps "TypeName" → its StructType for package-level
// `type X struct{...}` decls, so a `var req NamedReq` handler can be resolved.
func collectNamedStructs(files []*ast.File) map[string]*ast.StructType {
	out := map[string]*ast.StructType{}
	for _, f := range files {
		for _, d := range f.Decls {
			gd, ok := d.(*ast.GenDecl)
			if !ok || gd.Tok != token.TYPE {
				continue
			}
			for _, spec := range gd.Specs {
				ts, ok := spec.(*ast.TypeSpec)
				if !ok {
					continue
				}
				if st, ok := ts.Type.(*ast.StructType); ok {
					out[ts.Name.Name] = st
				}
			}
		}
	}
	return out
}

// collectContracts walks every `func (s *Server) handleX(c *gin.Context)`
// and recovers its input contract.
func collectContracts(fset *token.FileSet, files []*ast.File, named map[string]*ast.StructType) map[string]contract {
	out := map[string]contract{}
	for _, f := range files {
		for _, d := range f.Decls {
			fn, ok := d.(*ast.FuncDecl)
			if !ok || fn.Body == nil || fn.Recv == nil {
				continue
			}
			if !isServerMethod(fn) {
				continue
			}
			ctxName := ginContextParam(fn)
			if ctxName == "" {
				continue
			}
			out[fn.Name.Name] = extractContract(fset, fn, ctxName, named)
		}
	}
	return out
}

func extractContract(fset *token.FileSet, fn *ast.FuncDecl, ctxName string, named map[string]*ast.StructType) contract {
	var c contract
	// 1) collect local `var <id> ...` decls so a bind target resolves.
	localVars := map[string]ast.Expr{}
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		gd, ok := n.(*ast.GenDecl)
		if !ok || gd.Tok != token.VAR {
			return true
		}
		for _, spec := range gd.Specs {
			vs, ok := spec.(*ast.ValueSpec)
			if !ok || vs.Type == nil {
				continue
			}
			for _, nm := range vs.Names {
				localVars[nm.Name] = vs.Type
			}
		}
		return true
	})

	seenQ, seenP, seenH := map[string]bool{}, map[string]bool{}, map[string]bool{}
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		recv, ok := sel.X.(*ast.Ident)
		method := sel.Sel.Name
		switch {
		case ok && recv.Name == ctxName && (method == "ShouldBindJSON" || method == "BindJSON" || method == "ShouldBind"):
			if len(call.Args) == 1 {
				if id := bindTargetIdent(call.Args[0]); id != "" {
					if t, ok := localVars[id]; ok {
						c.body = fieldsFromType(fset, t, named)
					}
				}
			}
		case ok && recv.Name == ctxName && (method == "Query" || method == "DefaultQuery" || method == "GetQuery"):
			if name := firstStringLit(call.Args); name != "" && !seenQ[name] {
				seenQ[name] = true
				c.query = append(c.query, field{Name: name, Type: "string"})
			}
		case ok && recv.Name == ctxName && method == "Param":
			if name := firstStringLit(call.Args); name != "" && !seenP[name] {
				seenP[name] = true
				c.path = append(c.path, field{Name: name, Type: "string"})
			}
		case ok && recv.Name == ctxName && method == "GetHeader":
			if name := firstStringLit(call.Args); name != "" && !seenH[name] {
				seenH[name] = true
				c.headers = append(c.headers, field{Name: name, Type: "string"})
			}
		}
		return true
	})
	return c
}

// fieldsFromType renders a struct's JSON fields. The type expr is either an
// inline *ast.StructType (`var req struct{...}`) or an *ast.Ident naming a
// package-level struct.
func fieldsFromType(fset *token.FileSet, t ast.Expr, named map[string]*ast.StructType) []field {
	var st *ast.StructType
	switch v := t.(type) {
	case *ast.StructType:
		st = v
	case *ast.Ident:
		st = named[v.Name]
	case *ast.StarExpr:
		if id, ok := v.X.(*ast.Ident); ok {
			st = named[id.Name]
		}
	}
	if st == nil {
		return nil
	}
	var out []field
	for _, fl := range st.Fields.List {
		jsonName, required, skip := tagInfo(fl.Tag)
		if skip {
			continue
		}
		name := jsonName
		if name == "" && len(fl.Names) > 0 {
			name = lowerFirst(fl.Names[0].Name)
		}
		if name == "" { // embedded field w/o json tag — skip
			continue
		}
		out = append(out, field{Name: name, Type: exprString(fset, fl.Type), Required: required})
	}
	return out
}

var httpMethods = map[string]bool{"GET": true, "POST": true, "PUT": true, "PATCH": true, "DELETE": true, "HEAD": true, "OPTIONS": true}

// collectRoutes resolves route paths across the package, following both
// local groups (`x := api.Group("/sub")`) and helper functions that take
// the group as a param (`s.registerAssetRoutes(api)` → routes inside use
// `api`'s prefix). Resolution is recursive from the setup func.
func collectRoutes(files []*ast.File) []routeReg {
	funcs := map[string]*ast.FuncDecl{}
	groupParam := map[string]string{} // funcName → its *gin.RouterGroup param name
	for _, f := range files {
		for _, d := range f.Decls {
			fn, ok := d.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			funcs[fn.Name.Name] = fn
			if p := routerGroupParam(fn); p != "" {
				groupParam[fn.Name.Name] = p
			}
		}
	}

	var routes []routeReg
	visited := map[string]bool{}
	var resolve func(fnName string, env map[string]string)
	resolve = func(fnName string, env map[string]string) {
		fn := funcs[fnName]
		if fn == nil {
			return
		}
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			switch node := n.(type) {
			case *ast.AssignStmt: // x := <recv>.Group("/p")
				if len(node.Lhs) == 1 && len(node.Rhs) == 1 {
					if lhs, ok := node.Lhs[0].(*ast.Ident); ok {
						if call, ok := node.Rhs[0].(*ast.CallExpr); ok {
							if sel, ok := call.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == "Group" {
								env[lhs.Name] = prefixOfReceiver(sel.X, env) + firstStringLit(call.Args)
							}
						}
					}
				}
			case *ast.CallExpr:
				sel, ok := node.Fun.(*ast.SelectorExpr)
				if ok && httpMethods[sel.Sel.Name] && len(node.Args) >= 1 {
					if path := firstStringLit(node.Args[:1]); strings.HasPrefix(path, "/") {
						if handler, mids := handlerAndMiddleware(node.Args[1:]); handler != "" {
							routes = append(routes, routeReg{sel.Sel.Name, prefixOfReceiver(sel.X, env) + path, handler, mids})
						}
					}
				}
				// follow `register*(api)` helpers, propagating the group prefix.
				if callee := calleeName(node.Fun); callee != "" {
					if param, isGroupFn := groupParam[callee]; isGroupFn && !visited[callee] && len(node.Args) >= 1 {
						if pfx, ok := argGroupPrefix(node.Args[0], env); ok {
							visited[callee] = true
							resolve(callee, map[string]string{param: pfx})
						}
					}
				}
			}
			return true
		})
	}

	// Entry points are funcs that are NOT themselves group-param helpers
	// (those get reached via recursion with the right prefix).
	for name := range funcs {
		if _, isGroupFn := groupParam[name]; isGroupFn {
			continue
		}
		resolve(name, map[string]string{})
	}
	return dedupRoutes(routes)
}

// routerGroupParam returns the name of a func's *gin.RouterGroup param, or "".
func routerGroupParam(fn *ast.FuncDecl) string {
	if fn.Type.Params == nil {
		return ""
	}
	for _, p := range fn.Type.Params.List {
		star, ok := p.Type.(*ast.StarExpr)
		if !ok {
			continue
		}
		if sel, ok := star.X.(*ast.SelectorExpr); ok && sel.Sel.Name == "RouterGroup" && len(p.Names) > 0 {
			return p.Names[0].Name
		}
	}
	return ""
}

// prefixOfReceiver resolves the path prefix a route/group receiver carries:
// a known group var → its prefix; `s.router` → "" (root). Default "".
func prefixOfReceiver(x ast.Expr, env map[string]string) string {
	if id, ok := x.(*ast.Ident); ok {
		return env[id.Name]
	}
	return "" // s.router (SelectorExpr) or anything else → root
}

func argGroupPrefix(arg ast.Expr, env map[string]string) (string, bool) {
	if id, ok := arg.(*ast.Ident); ok {
		if p, has := env[id.Name]; has {
			return p, true
		}
	}
	if _, ok := arg.(*ast.SelectorExpr); ok { // s.router passed directly → root
		return "", true
	}
	return "", false
}

func calleeName(fun ast.Expr) string {
	switch v := fun.(type) {
	case *ast.SelectorExpr: // s.registerX
		return v.Sel.Name
	case *ast.Ident: // registerX
		return v.Name
	}
	return ""
}

func dedupRoutes(in []routeReg) []routeReg {
	seen := map[string]bool{}
	out := in[:0]
	for _, r := range in {
		k := r.method + " " + r.path + " " + r.handler
		if seen[k] {
			continue
		}
		seen[k] = true
		out = append(out, r)
	}
	return out
}

// handlerAndMiddleware splits the trailing handler args of a route call.
// The LAST `s.handlerX` (or bare `handlerX`) is the handler; the preceding
// `s.AuthMiddleware()` / `s.AdminMiddleware()` calls are middleware.
func handlerAndMiddleware(args []ast.Expr) (handler string, middleware []string) {
	names := make([]string, 0, len(args))
	for _, a := range args {
		switch v := a.(type) {
		case *ast.SelectorExpr: // s.handleX
			names = append(names, v.Sel.Name)
		case *ast.CallExpr: // s.AuthMiddleware()
			if sel, ok := v.Fun.(*ast.SelectorExpr); ok {
				names = append(names, sel.Sel.Name)
			} else {
				names = append(names, "")
			}
		case *ast.Ident: // bare handler
			names = append(names, v.Name)
		default:
			names = append(names, "")
		}
	}
	if len(names) == 0 {
		return "", nil
	}
	handler = names[len(names)-1]
	middleware = names[:len(names)-1]
	return handler, middleware
}

// authOf summarizes a route's middleware chain into a coarse label.
func authOf(mids []string) string {
	hasAdmin, hasAuth := false, false
	for _, m := range mids {
		switch {
		case strings.Contains(m, "Admin"):
			hasAdmin = true
		case strings.Contains(m, "Auth"):
			hasAuth = true
		}
	}
	switch {
	case hasAdmin:
		return "admin"
	case hasAuth:
		return "user"
	default:
		return ""
	}
}

// ---- small helpers ----

func isServerMethod(fn *ast.FuncDecl) bool {
	if fn.Recv == nil || len(fn.Recv.List) != 1 {
		return false
	}
	star, ok := fn.Recv.List[0].Type.(*ast.StarExpr)
	if !ok {
		return false
	}
	id, ok := star.X.(*ast.Ident)
	return ok && id.Name == recvType
}

// ginContextParam returns the name of the *gin.Context param, or "".
func ginContextParam(fn *ast.FuncDecl) string {
	if fn.Type.Params == nil {
		return ""
	}
	for _, p := range fn.Type.Params.List {
		star, ok := p.Type.(*ast.StarExpr)
		if !ok {
			continue
		}
		sel, ok := star.X.(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != "Context" {
			continue
		}
		if pkg, ok := sel.X.(*ast.Ident); ok && pkg.Name == "gin" && len(p.Names) > 0 {
			return p.Names[0].Name
		}
	}
	return ""
}

func bindTargetIdent(arg ast.Expr) string {
	u, ok := arg.(*ast.UnaryExpr) // &req
	if !ok || u.Op != token.AND {
		if id, ok := arg.(*ast.Ident); ok {
			return id.Name
		}
		return ""
	}
	if id, ok := u.X.(*ast.Ident); ok {
		return id.Name
	}
	return ""
}

func firstStringLit(args []ast.Expr) string {
	for _, a := range args {
		if lit, ok := a.(*ast.BasicLit); ok && lit.Kind == token.STRING {
			s, err := unquote(lit.Value)
			if err == nil {
				return s
			}
		}
		break // only the first arg
	}
	return ""
}

func unquote(s string) (string, error) {
	if len(s) >= 2 && (s[0] == '"' || s[0] == '`') {
		return s[1 : len(s)-1], nil
	}
	return s, nil
}

func tagInfo(tag *ast.BasicLit) (jsonName string, required, skip bool) {
	if tag == nil {
		return "", false, false
	}
	st := reflect.StructTag(strings.Trim(tag.Value, "`"))
	j := st.Get("json")
	parts := strings.Split(j, ",")
	jsonName = parts[0]
	if jsonName == "-" {
		return "", false, true
	}
	required = strings.Contains(st.Get("binding"), "required")
	return jsonName, required, false
}

func exprString(fset *token.FileSet, e ast.Expr) string {
	var buf bytes.Buffer
	_ = printer.Fprint(&buf, fset, e)
	return buf.String()
}

func lowerFirst(s string) string {
	if s == "" {
		return s
	}
	return strings.ToLower(s[:1]) + s[1:]
}

func nz(f []field) []field {
	if f == nil {
		return []field{}
	}
	return f
}

func countWithBody(eps []endpoint) int {
	n := 0
	for _, e := range eps {
		if len(e.Body) > 0 {
			n++
		}
	}
	return n
}

func writeFile(path string, b []byte) {
	if dir := filepath.Dir(path); dir != "" {
		_ = os.MkdirAll(dir, 0o755)
	}
	if err := os.WriteFile(path, b, 0o644); err != nil {
		fatal("write %s: %v", path, err)
	}
}

func fatal(f string, a ...any) {
	fmt.Fprintf(os.Stderr, "api-catalog-gen: "+f+"\n", a...)
	os.Exit(1)
}

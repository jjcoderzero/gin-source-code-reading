package gin

import (
	"fmt"
	"html/template"
	"net"
	"net/http"
	"os"
	"path"
	"sync"

	"github.com/gin-gonic/gin/internal/bytesconv"
	"github.com/gin-gonic/gin/render"
)

const defaultMultipartMemory = 32 << 20 // 32 MB

var (
	default404Body = []byte("404 page not found")
	default405Body = []byte("405 method not allowed")
)

var defaultAppEngine bool

// HandlerFunc 将gin中间件使用的处理程序定义为返回值
type HandlerFunc func(*Context)

// HandlersChain 定义一个HandlerFunc数组.
type HandlersChain []HandlerFunc

// Last 返回链中的最后一个处理程序。ie。最后一个处理程序是主处理程序.
func (c HandlersChain) Last() HandlerFunc {
	if length := len(c); length > 0 {
		return c[length-1]
	}
	return nil
}

// RouteInfo 表示包含方法、路径及其处理程序的请求路由的规范.
type RouteInfo struct {
	Method      string //
	Path        string
	Handler     string
	HandlerFunc HandlerFunc
}

// RoutesInfo 定义一个RouteInfo数组.
type RoutesInfo []RouteInfo

// Engine 是框架的实例，它包含muxer，middleware和配置设置。
// 使用New()或者Default()创建一个Engine实例。
type Engine struct {
	RouterGroup

	// 如果无法匹配当前路由，但存在带有(没有)尾斜杠的路径处理程序，则启用自动重定向。
	// For example if /foo/ is requested but a route only exists for /foo, the
	// client is redirected to /foo with http status code 301 for GET requests
	// and 307 for all other request methods.
	RedirectTrailingSlash bool

	// 如果启用，路由器尝试修复当前请求路径，如果没有为它注册句柄
	// 首先是多余的路径元素，如../或//被删除。然后，路由器对被清理的路径进行不区分大小写的查找。如果可以找到这个路由的句柄，路由器用状态代码301为GET请求和307为所有其他请求方法重定向到正确的路径。
	// For example /FOO and /..//Foo could be redirected to /foo.
	// RedirectTrailingSlash 与这个选项无关.
	RedirectFixedPath bool

	// 如果启用，路由器检查当前路由是否允许另一种方法，如果当前请求不能被路由。如果是这种情况，则用“Method Not Allowed”和HTTP状态码405回答该请求。如果不允许使用其他方法，则将请求委托给NotFound处理程序。
	HandleMethodNotAllowed bool
	ForwardedByClientIP    bool

	// #726 #755 If enabled, it will thrust some headers starting with
	// 'X-AppEngine...' for better integration with that PaaS.
	AppEngine bool

	// 如果启用，url.RawPath将用于查找参数
	UseRawPath bool

	// 如果为真，路径值将不会转义。
	// 如果UseRawPath为false(默认情况下)，则UnescapePathValues作为url有效地为true。路径会被使用，它已经没有转义了。
	UnescapePathValues bool

	// Value of 'maxMemory' param that is given to http.Request's ParseMultipartForm
	// method call.
	MaxMultipartMemory int64

	// RemoveExtraSlash a parameter can be parsed from the URL even with extra slashes.
	// See the PR #1817 and issue #1644
	RemoveExtraSlash bool

	delims           render.Delims
	secureJSONPrefix string
	HTMLRender       render.HTMLRender
	FuncMap          template.FuncMap
	allNoRoute       HandlersChain
	allNoMethod      HandlersChain
	noRoute          HandlersChain
	noMethod         HandlersChain
	pool             sync.Pool
	trees            methodTrees
	maxParams        uint16
}

var _ IRouter = &Engine{}

// New返回一个新的空白引擎实例，不附带任何中间件.
// By default the configuration is:
// - RedirectTrailingSlash:  true
// - RedirectFixedPath:      false
// - HandleMethodNotAllowed: false
// - ForwardedByClientIP:    true
// - UseRawPath:             false
// - UnescapePathValues:     true
func New() *Engine {
	debugPrintWARNINGNew()
	engine := &Engine{
		RouterGroup: RouterGroup{
			Handlers: nil,
			basePath: "/",
			root:     true,
		},
		FuncMap:                template.FuncMap{},
		RedirectTrailingSlash:  true,
		RedirectFixedPath:      false,
		HandleMethodNotAllowed: false,
		ForwardedByClientIP:    true,
		AppEngine:              defaultAppEngine,
		UseRawPath:             false,
		RemoveExtraSlash:       false,
		UnescapePathValues:     true,
		MaxMultipartMemory:     defaultMultipartMemory,
		trees:                  make(methodTrees, 0, 9),
		delims:                 render.Delims{Left: "{{", Right: "}}"},
		secureJSONPrefix:       "while(1);",
	}
	engine.RouterGroup.engine = engine
	engine.pool.New = func() interface{} {
		return engine.allocateContext()
	}
	return engine
}

// Default返回一个Engine实例，其中已经附加了日志记录器和恢复中间件.
func Default() *Engine {
	debugPrintWARNINGDefault()
	engine := New()
	engine.Use(Logger(), Recovery())
	return engine
}

func (engine *Engine) allocateContext() *Context {
	v := make(Params, 0, engine.maxParams)
	return &Context{engine: engine, params: &v}
}

// Delims 设置模板左边和右边的delims，并返回一个引擎实例.
func (engine *Engine) Delims(left, right string) *Engine {
	engine.delims = render.Delims{Left: left, Right: right}
	return engine
}

// SecureJsonPrefix 设置Context.SecureJSON中使用的secureJSONPrefix.
func (engine *Engine) SecureJsonPrefix(prefix string) *Engine {
	engine.secureJSONPrefix = prefix
	return engine
}

// LoadHTMLGlob 加载由glob模式识别的HTML文件，并将结果与HTML渲染器关联.
func (engine *Engine) LoadHTMLGlob(pattern string) {
	left := engine.delims.Left
	right := engine.delims.Right
	templ := template.Must(template.New("").Delims(left, right).Funcs(engine.FuncMap).ParseGlob(pattern))

	if IsDebugging() {
		debugPrintLoadTemplate(templ)
		engine.HTMLRender = render.HTMLDebug{Glob: pattern, FuncMap: engine.FuncMap, Delims: engine.delims}
		return
	}

	engine.SetHTMLTemplate(templ)
}

// LoadHTMLFiles 加载一个HTML文件切片，并将结果与HTML渲染器关联.
func (engine *Engine) LoadHTMLFiles(files ...string) {
	if IsDebugging() {
		engine.HTMLRender = render.HTMLDebug{Files: files, FuncMap: engine.FuncMap, Delims: engine.delims}
		return
	}

	templ := template.Must(template.New("").Delims(engine.delims.Left, engine.delims.Right).Funcs(engine.FuncMap).ParseFiles(files...))
	engine.SetHTMLTemplate(templ)
}

// SetHTMLTemplate 将模板与HTML渲染器关联.
func (engine *Engine) SetHTMLTemplate(templ *template.Template) {
	if len(engine.trees) > 0 {
		debugPrintWARNINGSetHTMLTemplate()
	}

	engine.HTMLRender = render.HTMLProduction{Template: templ.Funcs(engine.FuncMap)}
}

// SetFuncMap sets the FuncMap used for template.FuncMap.
func (engine *Engine) SetFuncMap(funcMap template.FuncMap) {
	engine.FuncMap = funcMap
}

// NoRoute 为NoRoute添加处理程序。默认情况下，它返回404代码.
func (engine *Engine) NoRoute(handlers ...HandlerFunc) {
	engine.noRoute = handlers
	engine.rebuild404Handlers()
}

// NoMethod sets the handlers called when... TODO.
func (engine *Engine) NoMethod(handlers ...HandlerFunc) {
	engine.noMethod = handlers
	engine.rebuild405Handlers()
}

// Use将一个全局中间件连接到路由器。ie。通过Use()附加的中间件将包含在每个请求的处理程序链中。甚至404 405,静态文件…
// For example, this is the right place for a logger or error management middleware.
func (engine *Engine) Use(middleware ...HandlerFunc) IRoutes {
	engine.RouterGroup.Use(middleware...)
	engine.rebuild404Handlers()
	engine.rebuild405Handlers()
	return engine
}

func (engine *Engine) rebuild404Handlers() {
	engine.allNoRoute = engine.combineHandlers(engine.noRoute)
}

func (engine *Engine) rebuild405Handlers() {
	engine.allNoMethod = engine.combineHandlers(engine.noMethod)
}

func (engine *Engine) addRoute(method, path string, handlers HandlersChain) {
	assert1(path[0] == '/', "path must begin with '/'")
	assert1(method != "", "HTTP method can not be empty")
	assert1(len(handlers) > 0, "there must be at least one handler")

	debugPrintRoute(method, path, handlers)

	root := engine.trees.get(method)
	if root == nil {
		root = new(node)
		root.fullPath = "/"
		engine.trees = append(engine.trees, methodTree{method: method, root: root})
	}
	root.addRoute(path, handlers)

	// Update maxParams
	if paramsCount := countParams(path); paramsCount > engine.maxParams {
		engine.maxParams = paramsCount
	}
}

// Routes 返回已注册路由的一部分，包括一些有用的信息, such as: the http method, path and the handler name.
func (engine *Engine) Routes() (routes RoutesInfo) {
	for _, tree := range engine.trees {
		routes = iterate("", tree.method, routes, tree.root)
	}
	return routes
}

func iterate(path, method string, routes RoutesInfo, root *node) RoutesInfo {
	path += root.path
	if len(root.handlers) > 0 {
		handlerFunc := root.handlers.Last()
		routes = append(routes, RouteInfo{
			Method:      method,
			Path:        path,
			Handler:     nameOfFunction(handlerFunc),
			HandlerFunc: handlerFunc,
		})
	}
	for _, child := range root.children {
		routes = iterate(path, method, routes, child)
	}
	return routes
}

// Run 将路由器连接到http.Server并且开始监听和服务HTTP请求。他是http.ListenAndServer(addr, router)快捷方法。
// 注意: 此方法将无限期地阻止调用goroutine，除非发生错误。
func (engine *Engine) Run(addr ...string) (err error) {
	defer func() { debugPrintError(err) }()

	address := resolveAddress(addr)
	debugPrint("Listening and serving HTTP on %s\n", address)
	err = http.ListenAndServe(address, engine)
	return
}

//RunTLS 将路由器连接到http.Server并且开始监听和服务HTTPS(secure)请求.他是http.ListenAndServeTLS(addr, certFile, keyFile, router)快捷方法。
// 注意: 此方法将无限期地阻止调用goroutine，除非发生错误。
func (engine *Engine) RunTLS(addr, certFile, keyFile string) (err error) {
	debugPrint("Listening and serving HTTPS on %s\n", addr)
	defer func() { debugPrintError(err) }()

	err = http.ListenAndServeTLS(addr, certFile, keyFile, engine)
	return
}

// RunUnix 通过指定unix socket(ie. a file)将路由器连接到http.Server并且开始监听和服务HTTP请求.
// 注意: 此方法将无限期地阻止调用goroutine，除非发生错误。
func (engine *Engine) RunUnix(file string) (err error) {
	debugPrint("Listening and serving HTTP on unix:/%s", file)
	defer func() { debugPrintError(err) }()

	listener, err := net.Listen("unix", file)
	if err != nil {
		return
	}
	defer listener.Close()
	defer os.Remove(file)

	err = http.Serve(listener, engine)
	return
}

// RunFd 通过指定文件描述符将路由器连接到http.Server并且开始监听和服务HTTP请求.
// 注意: 此方法将无限期地阻止调用goroutine，除非发生错误。
func (engine *Engine) RunFd(fd int) (err error) {
	debugPrint("Listening and serving HTTP on fd@%d", fd)
	defer func() { debugPrintError(err) }()

	f := os.NewFile(uintptr(fd), fmt.Sprintf("fd@%d", fd))
	listener, err := net.FileListener(f)
	if err != nil {
		return
	}
	defer listener.Close()
	err = engine.RunListener(listener)
	return
}

// RunListener 通过指定net.Listener将路由器连接到http.Server并且开始监听和服务HTTP请求.
func (engine *Engine) RunListener(listener net.Listener) (err error) {
	debugPrint("Listening and serving HTTP on listener what's bind with address@%s", listener.Addr())
	defer func() { debugPrintError(err) }()
	err = http.Serve(listener, engine)
	return
}

// ServeHTTP conforms to the http.Handler interface.
func (engine *Engine) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	c := engine.pool.Get().(*Context)
	c.writermem.reset(w)
	c.Request = req
	c.reset()

	engine.handleHTTPRequest(c)

	engine.pool.Put(c)
}

// HandleContext重新输入一个已经重写的上下文。 这可以通过设置c.Request.URL.Path来达到新的目的。
//免责声明:你可以用这个把自己套死，请明智使用。
func (engine *Engine) HandleContext(c *Context) {
	oldIndexValue := c.index
	c.reset()
	engine.handleHTTPRequest(c)

	c.index = oldIndexValue
}

func (engine *Engine) handleHTTPRequest(c *Context) {
	httpMethod := c.Request.Method
	rPath := c.Request.URL.Path
	unescape := false
	if engine.UseRawPath && len(c.Request.URL.RawPath) > 0 {
		rPath = c.Request.URL.RawPath
		unescape = engine.UnescapePathValues
	}

	if engine.RemoveExtraSlash {
		rPath = cleanPath(rPath)
	}

	// Find root of the tree for the given HTTP method
	t := engine.trees
	for i, tl := 0, len(t); i < tl; i++ {
		if t[i].method != httpMethod {
			continue
		}
		root := t[i].root
		// Find route in tree
		value := root.getValue(rPath, c.params, unescape)
		if value.params != nil {
			c.Params = *value.params
		}
		if value.handlers != nil {
			c.handlers = value.handlers
			c.fullPath = value.fullPath
			c.Next()
			c.writermem.WriteHeaderNow()
			return
		}
		if httpMethod != "CONNECT" && rPath != "/" {
			if value.tsr && engine.RedirectTrailingSlash {
				redirectTrailingSlash(c)
				return
			}
			if engine.RedirectFixedPath && redirectFixedPath(c, root, engine.RedirectFixedPath) {
				return
			}
		}
		break
	}

	if engine.HandleMethodNotAllowed {
		for _, tree := range engine.trees {
			if tree.method == httpMethod {
				continue
			}
			if value := tree.root.getValue(rPath, nil, unescape); value.handlers != nil {
				c.handlers = engine.allNoMethod
				serveError(c, http.StatusMethodNotAllowed, default405Body)
				return
			}
		}
	}
	c.handlers = engine.allNoRoute
	serveError(c, http.StatusNotFound, default404Body)
}

var mimePlain = []string{MIMEPlain}

func serveError(c *Context, code int, defaultMessage []byte) {
	c.writermem.status = code
	c.Next()
	if c.writermem.Written() {
		return
	}
	if c.writermem.Status() == code {
		c.writermem.Header()["Content-Type"] = mimePlain
		_, err := c.Writer.Write(defaultMessage)
		if err != nil {
			debugPrint("cannot write message to writer during serve error: %v", err)
		}
		return
	}
	c.writermem.WriteHeaderNow()
}

func redirectTrailingSlash(c *Context) {
	req := c.Request
	p := req.URL.Path
	if prefix := path.Clean(c.Request.Header.Get("X-Forwarded-Prefix")); prefix != "." {
		p = prefix + "/" + req.URL.Path
	}
	req.URL.Path = p + "/"
	if length := len(p); length > 1 && p[length-1] == '/' {
		req.URL.Path = p[:length-1]
	}
	redirectRequest(c)
}

func redirectFixedPath(c *Context, root *node, trailingSlash bool) bool {
	req := c.Request
	rPath := req.URL.Path

	if fixedPath, ok := root.findCaseInsensitivePath(cleanPath(rPath), trailingSlash); ok {
		req.URL.Path = bytesconv.BytesToString(fixedPath)
		redirectRequest(c)
		return true
	}
	return false
}

func redirectRequest(c *Context) {
	req := c.Request
	rPath := req.URL.Path
	rURL := req.URL.String()

	code := http.StatusMovedPermanently // Permanent redirect, request with GET method
	if req.Method != http.MethodGet {
		code = http.StatusTemporaryRedirect
	}
	debugPrint("redirecting request %d: %s --> %s", code, rPath, rURL)
	http.Redirect(c.Writer, req, rURL, code)
	c.writermem.WriteHeaderNow()
}

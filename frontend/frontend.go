package frontend

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	melody "gopkg.in/olahol/melody.v1"

	"github.com/VictorLowther/jsonpatch2"
	"github.com/digitalrebar/logger"
	"github.com/digitalrebar/provision/backend"
	"github.com/digitalrebar/provision/backend/index"
	"github.com/digitalrebar/provision/midlayer"
	"github.com/digitalrebar/provision/models"
	"github.com/digitalrebar/store"
	"github.com/gin-contrib/cors"
	"github.com/gin-contrib/location"
	"github.com/gin-gonic/gin"
	"github.com/gin-gonic/gin/binding"
)

// ErrorResponse is returned whenever an error occurs
// swagger:response
type ErrorResponse struct {
	//in: body
	Body models.Error
}

// NoContentResponse is returned for deletes and auth errors
// swagger:response
type NoContentResponse struct {
	//description: Nothing
}

type Sanitizable interface {
	Sanitize() models.Model
}

type Lockable interface {
	Locks(string) []string
}

type authBlob struct {
	f                           *Frontend
	claim                       *backend.DrpCustomClaims
	claimsList                  []models.Claims
	tenantMembers               map[string]map[string]struct{}
	currentUser, currentGrantor *models.User
	currentMachine              *models.Machine
	currentTenant               string
}

func (a *authBlob) tenantOK(prefix, key string) bool {
	if a.tenantMembers == nil || a.tenantMembers[prefix] == nil {
		return true
	}
	_, res := a.tenantMembers[prefix][key]
	return res
}

func (a *authBlob) tenantSelect(scope string) index.Filter {
	if a.tenantMembers == nil {
		return nil
	}
	test := func(m models.Model) bool {
		if a.tenantOK(m.Prefix(), m.Key()) {
			return true
		}
		switch o := m.(type) {
		case *models.Job:
			return a.tenantOK("machines", o.Machine.String())
		case *backend.Job:
			return a.tenantOK("machines", o.Machine.String())
		case *models.Lease:
			return a.tenantOK("machines", a.f.dt.MacToMachineUUID(o.Token))
		case *backend.Lease:
			return a.tenantOK("machines", a.f.dt.MacToMachineUUID(o.Token))
		case *models.Reservation:
			return a.tenantOK("machines", a.f.dt.MacToMachineUUID(o.Token))
		case *backend.Reservation:
			return a.tenantOK("machines", a.f.dt.MacToMachineUUID(o.Token))
		}
		return false
	}
	return index.Select(test)
}

func (a *authBlob) Find(rt *backend.RequestTracker, prefix, key string) models.Model {
	res := rt.Find(prefix, key)
	if res == nil {
		return res
	}
	if a.tenantOK(prefix, res.Key()) {
		return res
	}
	switch prefix {
	case "jobs":
		j := backend.AsJob(res)
		if a.tenantOK("machines", j.Machine.String()) {
			return res
		}
	case "leases":
		l := backend.AsLease(res)
		if a.tenantOK("machines", a.f.dt.MacToMachineUUID(l.Token)) {
			return res
		}
	case "reservations":
		r := backend.AsReservation(res)
		if a.tenantOK("machines", a.f.dt.MacToMachineUUID(r.Token)) {
			return res
		}
	}
	return nil
}

func (a *authBlob) matchClaim(wanted models.Claims) bool {
	for i := range a.claimsList {
		if a.claimsList[i].Contains(wanted) {
			return true
		}
	}
	return false
}

func (a *authBlob) isLicensed(scope, action string) bool {
	switch action {
	case "list", "get":
		return true
	default:
		switch scope {
		case "roles", "tenants":
			license := a.f.dt.LicenseFor("rbac")
			if license != nil && license.Active {
				return true
			}
			return false
		default:
			return true
		}
	}
}

type Frontend struct {
	Logger     logger.Logger
	FileRoot   string
	MgmtApi    *gin.Engine
	ApiGroup   *gin.RouterGroup
	dt         *backend.DataTracker
	pc         *midlayer.PluginController
	authSource AuthSource
	pubs       *backend.Publishers
	melody     *melody.Melody
	ApiPort    int
	ProvPort   int
	TftpPort   int
	DhcpPort   int
	BinlPort   int
	NoDhcp     bool
	NoTftp     bool
	NoProv     bool
	NoBinl     bool
	SaasDir    string
}

func (f *Frontend) l(c *gin.Context) logger.Logger {
	if c != nil {
		if k, ok := c.Get("logger"); ok {
			return k.(logger.Logger)
		}
	}
	return f.Logger
}

func (f *Frontend) Find(c *gin.Context, rt *backend.RequestTracker, prefix, key string) models.Model {
	var res models.Model
	rt.Do(func(s backend.Stores) {
		res = f.getAuth(c).Find(rt, prefix, key)
	})
	if res == nil {
		err := &models.Error{
			Model:    prefix,
			Key:      key,
			Code:     http.StatusNotFound,
			Type:     c.Request.Method,
			Messages: []string{"Not Found"},
		}
		c.AbortWithStatusJSON(err.Code, err)
	}
	return res
}

func (f *Frontend) rt(c *gin.Context, locks ...string) *backend.RequestTracker {
	if c != nil {
		return f.dt.Request(f.l(c), locks...)
	}
	return f.dt.Request(f.Logger, locks...)
}

type AuthSource interface {
	GetUser(f *Frontend, c *gin.Context, username string) *backend.User
}

type DefaultAuthSource struct {
	dt *backend.DataTracker
}

func (d DefaultAuthSource) GetUser(f *Frontend, c *gin.Context, username string) *backend.User {
	rt := f.rt(c, "users")
	var res *backend.User
	rt.Do(func(d backend.Stores) {
		if u := rt.Find("users", username); u != nil {
			res = u.(*backend.User)
		}
	})
	return res
}

func NewDefaultAuthSource(dt *backend.DataTracker) (das AuthSource) {
	das = DefaultAuthSource{dt: dt}
	return
}

func (fe *Frontend) userAuth() gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.Request.Header.Get("Authorization")
		if len(authHeader) == 0 {
			authHeader = c.Query("token")
			if len(authHeader) == 0 {
				fe.l(c).Warnf("No authentication header or token")
				c.Header("WWW-Authenticate", "dr-provision")
				c.AbortWithStatus(http.StatusUnauthorized)
				return
			} else {
				if strings.Contains(authHeader, ":") {
					authHeader = "Basic " + base64.StdEncoding.EncodeToString([]byte(authHeader))
				} else {
					authHeader = "Bearer " + authHeader
				}
			}
		}
		hdrParts := strings.SplitN(authHeader, " ", 2)
		if len(hdrParts) != 2 || (hdrParts[0] != "Basic" && hdrParts[0] != "Bearer") {
			fe.l(c).Warnf("Bad auth header: %s", authHeader)
			c.Header("WWW-Authenticate", "dr-provision")
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}
		var token *backend.DrpCustomClaims
		if hdrParts[0] == "Basic" {
			hdr, err := base64.StdEncoding.DecodeString(hdrParts[1])
			if err != nil {
				fe.l(c).Warnf("Malformed basic auth string: %s", hdrParts[1])
				c.Header("WWW-Authenticate", "dr-provision")
				c.AbortWithStatus(http.StatusUnauthorized)
				return
			}
			userpass := bytes.SplitN(hdr, []byte(`:`), 2)
			if len(userpass) != 2 {
				fe.l(c).Warnf("Malformed basic auth string: %s", hdrParts[1])
				c.Header("WWW-Authenticate", "dr-provision")
				c.AbortWithStatus(http.StatusUnauthorized)
				return
			}
			user := fe.authSource.GetUser(fe, c, string(userpass[0]))
			if user == nil {
				fe.l(c).Warnf("No such user: %s", string(userpass[0]))
				c.AbortWithStatus(http.StatusForbidden)
				return
			}
			if !user.CheckPassword(string(userpass[1])) {
				c.AbortWithStatus(http.StatusForbidden)
				return
			}
			token = user.GenClaim(string(userpass[0]), 30)
			fe.rt(c).Auditf("Authenticated user %s from %s", userpass[0], c.ClientIP())
		} else if hdrParts[0] == "Bearer" {
			t, err := fe.dt.GetToken(string(hdrParts[1]))
			if err != nil {
				fe.l(c).Warnf("No DRP authentication token")
				c.Header("WWW-Authenticate", "dr-provision")
				c.AbortWithStatus(http.StatusForbidden)
				return
			}
			token = t
		}
		auth := &authBlob{claim: token, f: fe}
		valid := true
		rt := fe.rt(c, "users", "roles", "tenants", "machines")
		rt.Do(func(stores backend.Stores) {
			var userSecret, grantorSecret, machineSecret string
			if u := rt.RawFind("users", token.GrantorClaims.UserId); u != nil {
				auth.currentUser = models.Clone(backend.AsUser(u)).(*models.User)
				userSecret = auth.currentUser.Secret
				auth.currentTenant = backend.AsUser(u).Tenant()
			}
			if token.GrantorClaims.GrantorId == "secret" {
				grantorSecret = rt.Prefs()["systemGrantorSecret"]
			} else if u := rt.Find("users", token.GrantorClaims.GrantorId); u != nil {
				auth.currentGrantor = backend.AsUser(u).User
				grantorSecret = auth.currentGrantor.Secret
			}
			if m := rt.Find("machines", token.GrantorClaims.MachineUuid); m != nil {
				auth.currentMachine = backend.AsMachine(m).Machine
				machineSecret = auth.currentMachine.Secret
			}
			if !token.ValidateSecrets(grantorSecret, userSecret, machineSecret) {
				valid = false
				return
			}
			auth.claimsList = token.ClaimsList(rt)
			if t := rt.RawFind("tenants", auth.currentTenant); t != nil {
				auth.tenantMembers = backend.AsTenant(t).ExpandedMembers()
			}
		})
		if valid {
			c.Set("DRP-AUTH", auth)
			c.Next()
			return
		}
		err := &models.Error{
			Type: "AUTH",
			Code: http.StatusForbidden,
		}
		err.Errorf("Validation failed")
		c.AbortWithStatusJSON(err.Code, err)
	}
}

var EmbeddedAssetsServerFunc func(*gin.Engine, logger.Logger) error

func NewFrontend(
	dt *backend.DataTracker,
	lgr logger.Logger,
	address string,
	apiport, provport, dhcpport, binlport int,
	fileRoot, localUI, UIUrl string,
	authSource AuthSource,
	pubs *backend.Publishers,
	drpid string,
	pc *midlayer.PluginController,
	noDhcp, noTftp, noProv, noBinl bool,
	saasDir string) (me *Frontend) {
	me = &Frontend{
		Logger:     lgr,
		FileRoot:   fileRoot,
		dt:         dt,
		pubs:       pubs,
		pc:         pc,
		ApiPort:    apiport,
		ProvPort:   provport,
		DhcpPort:   dhcpport,
		BinlPort:   binlport,
		NoDhcp:     noDhcp,
		NoTftp:     noTftp,
		NoProv:     noProv,
		NoBinl:     noBinl,
		SaasDir:    saasDir,
		authSource: authSource,
	}
	gin.SetMode(gin.ReleaseMode)

	if me.authSource == nil {
		me.authSource = NewDefaultAuthSource(dt)
	}

	mgmtApi := gin.New()
	mgmtApi.Use(func(c *gin.Context) {
		l := me.Logger.Fork()
		if logLevel := c.GetHeader("X-Log-Request"); logLevel != "" {
			lvl, err := logger.ParseLevel(logLevel)
			if err != nil {
				l.Errorf("Invalid requested log level %s", logLevel)
			} else {
				l = l.Trace(lvl)
			}
		}
		if logToken := c.GetHeader("X-Log-Token"); logToken != "" {
			l.Errorf("Log token: %s", logToken)
		}
		c.Set("logger", l)
		start := time.Now()
		path := c.Request.URL.Path
		raw := c.Request.URL.RawQuery
		c.Next()
		latency := time.Now().Sub(start)
		clientIP := c.ClientIP()
		method := c.Request.Method
		statusCode := c.Writer.Status()
		if raw != "" {
			path = path + "?" + raw
		}
		l.Debugf("API: st: %d lt: %13v ip: %15s m: %s %s",
			statusCode,
			latency,
			clientIP,
			method,
			path,
		)
	})
	mgmtApi.Use(gin.Recovery())

	// CORS Support
	mgmtApi.Use(cors.New(cors.Config{
		AllowAllOrigins:  true,
		AllowCredentials: true,
		AllowMethods:     []string{"GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH", "HEAD"},
		AllowHeaders: []string{
			"Origin",
			"X-Requested-With",
			"Content-Type",
			"Cookie",
			"Authorization",
			"WWW-Authenticate",
			"X-Return-Attributes",
			"X-Log-Level",
			"X-Log-Token",
			"Range",
		},
		ExposeHeaders: []string{
			"Content-Length",
			"WWW-Authenticate",
			"Set-Cookie",
			"Access-Control-Allow-Headers",
			"Access-Control-Allow-Credentials",
			"Access-Control-Allow-Origin",
			"X-Return-Attributes",
			"X-DRP-LIST-COUNT",
			"X-DRP-LIST-TOTAL-COUNT",
		},
	}))

	mgmtApi.Use(location.Default())
	mgmtApi.NoMethod(func(c *gin.Context) {
		err := &models.Error{
			Code: http.StatusMethodNotAllowed,
			Type: c.Request.Method,
			Key:  c.Request.URL.String(),
		}
		err.Errorf("Method not allowed")
		c.JSON(err.Code, err)
	})
	mgmtApi.NoRoute(func(c *gin.Context) {
		err := &models.Error{
			Code: http.StatusNotFound,
			Type: c.Request.Method,
			Key:  c.Request.URL.String(),
		}
		err.Errorf("No route")
		c.JSON(err.Code, err)
	})
	me.MgmtApi = mgmtApi

	apiGroup := mgmtApi.Group("/api/v3")
	apiGroup.Use(me.userAuth())
	me.ApiGroup = apiGroup

	me.InitIndexApi()
	me.InitRoleApi()
	me.InitWebSocket()
	me.InitBootEnvApi()
	me.InitStageApi()
	me.InitIsoApi()
	me.InitFileApi()
	me.InitTemplateApi()
	me.InitMachineApi()
	me.InitProfileApi()
	me.InitLeaseApi()
	me.InitReservationApi()
	me.InitSubnetApi()
	me.InitUserApi(drpid)
	me.InitInterfaceApi()
	me.InitPrefApi()
	me.InitParamApi()
	me.InitInfoApi(drpid)
	me.InitLogApi()
	me.InitPluginApi()
	me.InitPluginProviderApi()
	me.InitTaskApi()
	me.InitJobApi()
	me.InitWorkflowApi()
	me.InitEventApi()
	me.InitContentApi()
	me.InitTenantApi()
	me.InitSystemApi()

	if EmbeddedAssetsServerFunc != nil {
		EmbeddedAssetsServerFunc(mgmtApi, lgr)
	}

	// Optionally add a local dev-ui
	if len(localUI) != 0 {
		lgr.Infof("Running Local UI from %s\n", localUI)
		mgmtApi.Static("/local-ui", localUI)
	}

	// UI points to the cloud
	mgmtApi.GET("/ui", func(c *gin.Context) {
		incomingUrl := location.Get(c)

		url := fmt.Sprintf("%s/#/e/%s", UIUrl, incomingUrl.Host)
		c.Redirect(http.StatusMovedPermanently, url)
	})

	// root path, forward to UI
	mgmtApi.GET("/", func(c *gin.Context) {
		c.Redirect(http.StatusMovedPermanently, "/ui/")
	})

	pubs.Add(me)
	return
}

func (f *Frontend) getAuth(c *gin.Context) *authBlob {
	b, ok := c.Get("DRP-AUTH")
	if !ok {
		f.l(c).Panicf("Missing auth!")
	}
	return b.(*authBlob)
}

func testContentType(c *gin.Context, ct string) bool {
	ct = strings.ToUpper(ct)
	test := strings.ToUpper(c.ContentType())

	return strings.Contains(test, ct)
}

func assureContentType(c *gin.Context, ct string) bool {
	if testContentType(c, ct) {
		return true
	}
	err := &models.Error{Type: c.Request.Method, Code: http.StatusBadRequest}
	err.Errorf("Invalid content type: %s", c.ContentType())
	c.JSON(err.Code, err)
	return false
}

func (f *Frontend) assureAuth(c *gin.Context,
	wantsClaims models.Claims,
	scope, action, specific string) bool {
	auth := f.getAuth(c)
	if auth.matchClaim(wantsClaims) && auth.isLicensed(scope, action) {
		return true
	}
	f.rt(c).Auditf("Failed auth '%s' '%s' '%s' - %s",
		scope, action, specific, c.ClientIP())
	var res *models.Error
	switch action {
	case "get":
		res = &models.Error{
			Model: scope,
			Key:   specific,
			Type:  c.Request.Method,
			Code:  http.StatusNotFound,
		}
		res.Errorf("Not Found")
	default:
		res = &models.Error{
			Type: "AUTH",
			Code: http.StatusForbidden,
		}
		res.Errorf("Cannot access %s", c.Request.URL.String())
		if auth.isLicensed(scope, action) {
			res.Errorf("Requires: %s %s %s", scope, action, specific)
		} else {
			res.Errorf("%s %s is a licensed enterprise feature.  Contact support@rackn.com", scope, action)
		}
	}
	c.AbortWithStatusJSON(res.Code, res)
	return false
}

//
// THIS MUST NOT BE CALLED UNDER LOCKS!
//
func (f *Frontend) assureSimpleAuth(c *gin.Context, scope, action, specific string) bool {
	wantsClaims := models.MakeRole("", scope, action, specific).Compile()
	return f.assureAuth(c, wantsClaims, scope, action, specific)
}

func (f *Frontend) assureAuthUpdate(c *gin.Context,
	scope, action, specific string,
	patch jsonpatch2.Patch) bool {
	claims := []string{}
	for _, line := range patch {
		switch line.Op {
		case "test":
			continue
		case "move":
			claims = append(claims, scope, "update:"+line.From, specific)
			fallthrough
		default:
			claims = append(claims, scope, "update:"+line.Path, specific)
		}
	}
	wantsClaims := models.MakeRole("", claims...).Compile()
	return f.assureAuth(c, wantsClaims, scope, action, specific)
}

func assureDecode(c *gin.Context, val interface{}) bool {
	if !assureContentType(c, "application/json") {
		return false
	}
	if c.Request.ContentLength == 0 {
		val = nil
		return true
	}
	marshalErr := binding.JSON.Bind(c.Request, &val)
	if marshalErr == nil {
		return true
	}
	err := &models.Error{Type: c.Request.Method, Code: http.StatusBadRequest}
	err.AddError(marshalErr)
	c.JSON(err.Code, err)
	return false
}

// This processes the value into a function, if function not specifed, assume Eq.
// Supported Forms:
//
//   Eq(value)
//   Lt(value)
//   Lte(value)
//   Gt(value)
//   Gte(value)
//   Ne(value)
//   Between(valueLower, valueHigher)
//   Except(valueLower, valueHigher)
//
func convertValueToFilter(v string) (index.Filter, error) {
	args := strings.SplitN(v, "(", 2)
	switch args[0] {
	case "Eq":
		subargs := strings.SplitN(args[1], ")", 2)
		return index.Eq(subargs[0]), nil
	case "Lt":
		subargs := strings.SplitN(args[1], ")", 2)
		return index.Lt(subargs[0]), nil
	case "Lte":
		subargs := strings.SplitN(args[1], ")", 2)
		return index.Lte(subargs[0]), nil
	case "Gt":
		subargs := strings.SplitN(args[1], ")", 2)
		return index.Gt(subargs[0]), nil
	case "Gte":
		subargs := strings.SplitN(args[1], ")", 2)
		return index.Gte(subargs[0]), nil
	case "Ne":
		subargs := strings.SplitN(args[1], ")", 2)
		return index.Ne(subargs[0]), nil
	case "Between":
		subargs := strings.SplitN(args[1], ")", 2)
		parts := strings.Split(subargs[0], ",")
		return index.Between(parts[0], parts[1]), nil
	case "Except":
		subargs := strings.SplitN(args[1], ")", 2)
		parts := strings.Split(subargs[0], ",")
		return index.Except(parts[0], parts[1]), nil
	default:
		return index.Eq(v), nil
	}
	return nil, fmt.Errorf("Should never get here")
}

type dynParameter interface {
	ParameterMaker(*backend.RequestTracker, string) (index.Maker, error)
}

func (f *Frontend) processFilters(rt *backend.RequestTracker, d backend.Stores, ref models.Model, params map[string][]string) ([]index.Filter, error) {
	filters := []index.Filter{}
	var err error
	var indexes map[string]index.Maker
	if indexer, ok := ref.(index.Indexer); ok {
		indexes = indexer.Indexes()
	} else {
		indexes = map[string]index.Maker{}
	}

	for k, vs := range params {
		if k == "offset" || k == "limit" || k == "sort" || k == "reverse" {
			continue
		}
		maker, ok := indexes[k]
		pMaker, found := ref.(dynParameter)
		if !ok {
			if !found {
				return nil, fmt.Errorf("Filter not found: %s", k)
			}
			maker, err = pMaker.ParameterMaker(rt, k)
			if err != nil {
				return nil, err
			}
			ok = true
		}
		if ok {
			filters = append(filters, index.Sort(maker))
			subfilters := []index.Filter{}
			for _, v := range vs {
				f, err := convertValueToFilter(v)
				if err != nil {
					return nil, err
				}
				subfilters = append(subfilters, f)
			}
			filters = append(filters, index.Any(subfilters...))
		}
	}

	if vs, ok := params["sort"]; ok {
		for _, piece := range vs {
			if maker, ok := indexes[piece]; ok {
				filters = append(filters, index.Sort(maker))
			} else {
				return nil, fmt.Errorf("Not sortable: %s", piece)
			}
		}
	} else {
		filters = append(filters, index.Native())
	}

	if _, ok := params["reverse"]; ok {
		filters = append(filters, index.Reverse())
	}

	// offset and limit must be last
	if vs, ok := params["offset"]; ok {
		num, err := strconv.Atoi(vs[0])
		if err == nil {
			filters = append(filters, index.Offset(num))
		} else {
			return nil, fmt.Errorf("Offset not valid: %v", err)
		}
	}
	if vs, ok := params["limit"]; ok {
		num, err := strconv.Atoi(vs[0])
		if err == nil {
			filters = append(filters, index.Limit(num))
		} else {
			return nil, fmt.Errorf("Limit not valid: %v", err)
		}
	}

	return filters, nil
}

func jsonError(c *gin.Context, err error, code int, base string) {
	if ne, ok := err.(*models.Error); ok {
		c.JSON(ne.Code, ne)
	} else {
		res := &models.Error{
			Type:  c.Request.Method,
			Code:  code,
			Model: base,
		}
		res.AddError(err)
		c.JSON(res.Code, res)
	}
}

func (f *Frontend) emptyList(c *gin.Context, statsOnly bool) {
	c.Header("X-DRP-LIST-TOTAL-COUNT", "0")
	c.Header("X-DRP-LIST-COUNT", "0")
	if statsOnly {
		c.Status(http.StatusOK)
	} else {
		c.JSON(http.StatusOK, []models.Model{})
	}
}

func (f *Frontend) list(c *gin.Context, ref store.KeySaver, statsOnly bool) {
	backend.Fill(ref)
	arr := []models.Model{}
	var totalCount, count int
	if !f.getAuth(c).matchClaim(models.MakeRole("", ref.Prefix(), "list", "").Compile()) {
		f.emptyList(c, statsOnly)
		return
	}
	res := &models.Error{
		Code:  http.StatusNotAcceptable,
		Type:  c.Request.Method,
		Model: ref.Prefix(),
	}
	var err error

	rt := f.rt(c, ref.(Lockable).Locks("get")...)
	rt.Do(func(d backend.Stores) {
		var filters []index.Filter
		filters, err = f.processFilters(rt, d, ref, c.Request.URL.Query())
		if err != nil {
			res.AddError(err)
			return
		}
		mainIndex := &d(ref.Prefix()).Index
		if tf := f.getAuth(c).tenantSelect(ref.Prefix()); tf != nil {
			mainIndex, _ = tf(mainIndex)
		}
		totalCount = mainIndex.Count()

		idx, err := index.All(filters...)(mainIndex)
		if err != nil {
			res.AddError(err)
			return
		}
		count = idx.Count()

		if statsOnly {
			return
		}

		items := idx.Items()
		for i, item := range items {
			arr = append(arr, models.Clone(item))
			f, ok := arr[i].(models.Filler)
			if ok {
				f.Fill()
			}
			s, ok := arr[i].(Sanitizable)
			if ok {
				arr[i] = s.Sanitize()
			}
		}
	})

	if res.ContainsError() {
		c.JSON(res.Code, res)
		return
	}
	c.Header("X-DRP-LIST-TOTAL-COUNT", fmt.Sprintf("%d", totalCount))
	c.Header("X-DRP-LIST-COUNT", fmt.Sprintf("%d", count))
	if statsOnly {
		c.Status(http.StatusOK)
	} else {
		c.JSON(http.StatusOK, arr)
	}
}

func (f *Frontend) ListStats(c *gin.Context, ref store.KeySaver) {
	f.list(c, ref, true)
}

// XXX: Auth enforce may need to limit return values based up access to get - one day.
func (f *Frontend) List(c *gin.Context, ref store.KeySaver) {
	f.list(c, ref, false)
}

func (f *Frontend) Exists(c *gin.Context, ref store.KeySaver, key string) {
	backend.Fill(ref)
	prefix := ref.Prefix()
	rt := f.rt(c, ref.(Lockable).Locks("get")...)
	if f.Find(c, rt, prefix, key) != nil {
		c.Status(http.StatusOK)
	}
}

func (f *Frontend) Fetch(c *gin.Context, ref store.KeySaver, key string) {
	backend.Fill(ref)
	prefix := ref.Prefix()
	var res models.Model
	rt := f.rt(c, ref.(Lockable).Locks("get")...)
	res = f.Find(c, rt, prefix, key)
	if res == nil {
		return
	}
	aref, _ := res.(backend.AuthSaver)
	if !f.assureSimpleAuth(c, prefix, "get", aref.AuthKey()) {
		return
	}
	s, ok := res.(Sanitizable)
	if ok {
		res = s.Sanitize()
	}
	c.JSON(http.StatusOK, res)
}

func (f *Frontend) create(c *gin.Context, val store.KeySaver) {
	if !f.assureSimpleAuth(c, val.Prefix(), "create", "") {
		return
	}
	var err error
	var res models.Model
	tenant := f.getAuth(c).currentTenant
	locks := val.(Lockable).Locks("create")
	if tenant != "" {
		locks = append(locks, "tenants")
	}
	rt := f.rt(c, locks...)
	rt.Do(func(d backend.Stores) {
		_, err = rt.Create(val)
		if err == nil {
			if tenant != "" {
				t2 := backend.AsTenant(rt.RawFind("tenants", tenant))
				if t2.Members[val.Prefix()] != nil {
					t2.Members[val.Prefix()] = append(t2.Members[val.Prefix()], val.Key())
					rt.Save(t2)
				}
			}
			res = models.Clone(val)
		}
	})
	if err != nil {
		jsonError(c, err, http.StatusBadRequest, "")
	} else {
		s, ok := res.(Sanitizable)
		if ok {
			res = s.Sanitize()
		}
		c.JSON(http.StatusCreated, res)
	}
}

func (f *Frontend) Create(c *gin.Context, val store.KeySaver) {
	backend.Fill(val)
	if !assureDecode(c, val) {
		return
	}
	f.create(c, val)
}

func (f *Frontend) Patch(c *gin.Context, ref store.KeySaver, key string) {
	backend.Fill(ref)
	patch := make(jsonpatch2.Patch, 0)
	if !assureDecode(c, &patch) {
		return
	}
	var err error
	var tref models.Model
	authKey := ""
	rt := f.rt(c, ref.(Lockable).Locks("update")...)
	tref = f.Find(c, rt, ref.Prefix(), key)
	if tref == nil {
		return
	}
	authKey = tref.(backend.AuthSaver).AuthKey()
	if authKey != "" && !f.assureAuthUpdate(c, ref.Prefix(), "patch", authKey, patch) {
		return
	}

	var res models.Model
	rt.Do(func(d backend.Stores) {
		// This will fail with notfound as well.
		a, b := rt.Patch(ref, key, patch)
		res, err = models.Clone(a), b
	})
	if err == nil {
		s, ok := res.(Sanitizable)
		if ok {
			res = s.Sanitize()
		}
		c.JSON(http.StatusOK, res)
		return
	}
	jsonError(c, err, http.StatusBadRequest, "")
}

func (f *Frontend) Update(c *gin.Context, ref store.KeySaver, key string) {
	backend.Fill(ref)
	if !assureDecode(c, ref) {
		return
	}
	if ref.Key() != key {
		err := &models.Error{
			Code:  http.StatusBadRequest,
			Type:  c.Request.Method,
			Model: ref.Prefix(),
			Key:   key,
		}
		err.Errorf("Key change from %s to %s not allowed", key, ref.Key())
		c.JSON(err.Code, err)
		return
	}
	var err error
	var patch jsonpatch2.Patch
	authKey := ""
	rt := f.rt(c, ref.(Lockable).Locks("update")...)
	tref := f.Find(c, rt, ref.Prefix(), ref.Key())
	if tref == nil {
		return
	}
	patch, err = models.GenPatch(tref, ref, false)
	authKey = tref.(backend.AuthSaver).AuthKey()
	if err != nil {
		jsonError(c, err, http.StatusBadRequest, "")
	}
	if !f.assureAuthUpdate(c, ref.Prefix(), "update", authKey, patch) {
		return
	}
	var res models.Model
	rt.Do(func(d backend.Stores) {
		_, b := rt.Update(ref)
		res, err = models.Clone(ref), b
	})
	if err == nil {
		s, ok := ref.(Sanitizable)
		if ok {
			res = s.Sanitize()
		}
		c.JSON(http.StatusOK, res)
		return
	}
	jsonError(c, err, http.StatusBadRequest, "")
}

func (f *Frontend) Remove(c *gin.Context, ref store.KeySaver, key string) {
	backend.Fill(ref)
	var err error
	var res models.Model
	locks := ref.(Lockable).Locks("delete")
	locks = append(locks, "tenants")
	rt := f.rt(c, locks...)
	res = f.Find(c, rt, ref.Prefix(), key)
	if res == nil {
		return
	}
	if !f.assureSimpleAuth(c, ref.Prefix(), "delete", res.(backend.AuthSaver).AuthKey()) {
		return
	}
	rt.Do(func(d backend.Stores) {
		_, err = rt.Remove(res)
		if err != nil {
			return
		}
		for _, tobj := range d("tenants").Items() {
			t := backend.AsTenant(tobj)
			if t.Members[ref.Prefix()] == nil {
				continue
			}
			tenantMembers := t.ExpandedMembers()
			if _, ok := tenantMembers[ref.Prefix()][key]; !ok {
				continue
			}
			newMembers := []string{}
			for _, k := range t.Members[ref.Prefix()] {
				if k != key {
					newMembers = append(newMembers, k)
				}
			}
			t.Members[ref.Prefix()] = newMembers
			rt.Save(t)
		}
	})

	if err != nil {
		jsonError(c, err, http.StatusNotFound, "")
	} else {
		s, ok := res.(Sanitizable)
		if ok {
			res = s.Sanitize()
		}
		c.JSON(http.StatusOK, res)
	}
}

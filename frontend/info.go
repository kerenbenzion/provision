package frontend

import (
	"net"
	"net/http"

	"github.com/digitalrebar/provision"
	"github.com/digitalrebar/provision/backend"
	"github.com/digitalrebar/provision/backend/index"
	"github.com/digitalrebar/provision/models"
	"github.com/gin-gonic/gin"
)

// InfosResponse returned on a successful GET of an info
// swagger:response
type InfoResponse struct {
	// in: body
	Body *models.Info
}

func (f *Frontend) GetInfo(c *gin.Context, drpid string) (*models.Info, *models.Error) {
	i := &models.Info{
		Version:            provision.RS_VERSION,
		Id:                 drpid,
		ApiPort:            f.ApiPort,
		FilePort:           f.ProvPort,
		TftpPort:           f.TftpPort,
		DhcpPort:           f.DhcpPort,
		BinlPort:           f.BinlPort,
		TftpEnabled:        !f.NoTftp,
		DhcpEnabled:        !f.NoDhcp,
		ProvisionerEnabled: !f.NoProv,
		BinlEnabled:        !f.NoBinl,
		License:            f.dt.AllLicenses(),
	}
	i.Fill()

	res := &models.Error{
		Code:  http.StatusInternalServerError,
		Type:  "API_ERROR",
		Model: "info",
	}
	rt := f.rt(c, "machines", "subnets")
	rt.Do(func(d backend.Stores) {
		if idx, err := index.All(index.Native())(&d("machines").Index); err != nil {
			res.AddError(err)
		} else {
			i.Stats = append(i.Stats, models.Stat{"machines.count", idx.Count()})
		}

		if idx, err := index.All(index.Native())(&d("subnets").Index); err != nil {
			res.AddError(err)
		} else {
			i.Stats = append(i.Stats, models.Stat{"subnets.count", idx.Count()})
		}
	})

	if res.HasError() == nil {
		res = nil
	}

	return i, res
}

func (f *Frontend) InitInfoApi(drpid string) {
	// swagger:route GET /info Info getInfo
	//
	// Return current system info.
	//
	//     Produces:
	//       application/json
	//
	//     Responses:
	//       200: InfoResponse
	//       401: NoContentResponse
	//       403: NoContentResponse
	//       500: ErrorResponse
	f.ApiGroup.GET("/info",
		func(c *gin.Context) {
			if !f.assureSimpleAuth(c, "info", "get", "") {
				return
			}
			info, err := f.GetInfo(c, drpid)
			if err != nil {
				c.JSON(err.Code, err)
				return
			}
			if a, _, e := net.SplitHostPort(c.Request.RemoteAddr); e == nil {
				info.Address = backend.LocalFor(f.l(c), net.ParseIP(a))
			}
			c.JSON(http.StatusOK, info)
		})
}

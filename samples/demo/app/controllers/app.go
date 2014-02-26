package controllers

import (
    "github.com/revel/revel"
    "github.com/cbonello/revel-csrf/samples/demo/app/routes"
    "fmt"
)

type App struct {
	*revel.Controller
}

func (c App) Index() revel.Result {
	return c.Render()
}

func (c App) Hello(name string) revel.Result {
	route := c.Request.Request.URL.Path
	exempted := (route == "/HelloExempted")
	return c.Render(name, exempted)
}

func (c App) Hello123Exempted(name string) revel.Result {
	return c.Render(name)
}

func (c App) Logout(name string) revel.Result {
	fmt.Printf("Deleting session keys...\n")
	for k := range c.Session {
		fmt.Printf("Deleting Session[%s]: '%s'\n", k, c.Session[k])
		delete(c.Session, k)
	}
	return c.Redirect(routes.App.Index())
}

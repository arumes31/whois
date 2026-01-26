package utils

import (
	"html/template"
	"io"
	"net"

	"github.com/labstack/echo/v4"
)

type TemplateRegistry struct {
	Templates *template.Template
}

func (t *TemplateRegistry) Render(w io.Writer, name string, data interface{}, c echo.Context) error {
	return t.Templates.ExecuteTemplate(w, name, data)
}

func IsIP(val interface{}) bool {
	if str, ok := val.(string); ok {
		return net.ParseIP(str) != nil
	}
	return false
}

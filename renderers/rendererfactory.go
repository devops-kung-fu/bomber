package renderers

import (
	"fmt"

	"github.com/devops-kung-fu/bomber/models"
	"github.com/devops-kung-fu/bomber/renderers/json"
	"github.com/devops-kung-fu/bomber/renderers/stdout"
)

func NewRenderer(name string) (renderer models.Renderer, err error) {
	switch name {
	case "stdout":
		renderer = stdout.Renderer{}
	case "json":
		renderer = json.Renderer{}
	default:
		err = fmt.Errorf("%s is not a valid output type", name)
	}
	return
}

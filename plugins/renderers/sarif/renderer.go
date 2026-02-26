package sarif

import (
	"io"

	"github.com/GlitchOrb/vulngate/pkg/model"
	coresarif "github.com/GlitchOrb/vulngate/pkg/render/sarif"
)

type Renderer struct {
	core *coresarif.Renderer
}

func New() *Renderer {
	return &Renderer{core: coresarif.New()}
}

func (r *Renderer) Name() string {
	return "sarif"
}

func (r *Renderer) Render(w io.Writer, report model.Report) error {
	return r.core.Render(w, report)
}

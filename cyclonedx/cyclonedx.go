package cyclonedx

import (
	cyclone "github.com/CycloneDX/cyclonedx-go"

	"github.com/devops-kung-fu/bomber/spdx"
)

func ToSPDX(bom *cyclone.BOM) *spdx.BOM {
	spdx := spdx.NewSPDX()
	return spdx
}

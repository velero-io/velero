package schedule

import (
	"github.com/spf13/pflag"

	"github.com/velero-io/velero/pkg/cmd/util/flag"
)

type SkipOptions struct {
	SkipImmediately flag.OptionalBool
}

func NewSkipOptions() *SkipOptions {
	return &SkipOptions{}
}

func (o *SkipOptions) BindFlags(flags *pflag.FlagSet) {
	f := flags.VarPF(&o.SkipImmediately, "skip-immediately", "", "Skip the next scheduled backup immediately")
	f.NoOptDefVal = "" // default to nil so server options can take precedence
}

// Package app holds the gitc configuration and construction.
package app

import "github.com/inovacc/mantle/bootstrap"

// App is the gitc application config, embedding mantle's Base.
type App struct {
	bootstrap.Base `mapstructure:",squash" yaml:",inline"`

	Greeting string `mapstructure:"greeting" yaml:"greeting"`
}

// New returns App seeded with defaults.
func New() *App {
	a := &App{
		Base:     bootstrap.DefaultBase(),
		Greeting: "hello",
	}
	return a
}

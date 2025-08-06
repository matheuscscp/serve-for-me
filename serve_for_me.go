package cloudfunction

import (
	"github.com/GoogleCloudPlatform/functions-framework-go/functions"

	"github.com/matheuscscp/serve-for-me/serveforme"
)

func init() {
	h, err := serveforme.NewServer([]serveforme.Identity{
		// Myself.
		{
			Issuer:   "https://accounts.google.com",
			ClientID: "764086051850-6qr4p6gpi6hn506pt8ejuq83di341hur.apps.googleusercontent.com",
			Subject:  "105001485022452358114",
		},
	})
	if err != nil {
		panic(err)
	}

	functions.HTTP("ServeForMe", h.ServeHTTP)
}

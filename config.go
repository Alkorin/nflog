package nflog

type Config struct {
	// List of NFLog Group to listen. Max 32 values.
	Groups []uint16

	// Max number of bytes of the packet to receive
	// If zero, size is unlimited (default is 0: unlimited)
	CopyRange uint16

	// Return specifies what channels will be populated. If they are set to true,
	// you must read from the respective channels to prevent deadlock.
	Return struct {
		// If enabled, any errors that occurred while consuming are returned on
		// the Errors channel (default is false: disabled).
		Errors bool
	}
}

func NewConfig() *Config {
	return &Config{}
}

func (c Config) Validate() error {
	if len(c.Groups) == 0 {
		return ConfigurationError("No groups defined")
	}

	if len(c.Groups) > 32 {
		return ConfigurationError("Number of groups should be <= 32")
	}

	return nil
}

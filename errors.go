package nflog

// ConfigurationError is the type of error returned from
// Config.Validate() or NFLog.New() when the specified configuration
// is invalid
type ConfigurationError string

func (err ConfigurationError) Error() string {
	return "nflog: invalid configuration: " + string(err)
}

// ReaderError is the type of error returned when an error
// occurs while reading NETLINK socket. This error is sent
// through the Errors() channel.
type ReaderError string

func (err ReaderError) Error() string {
	return "nflog: error while reading socket: " + string(err)
}

// ParserError is the type of error returned when an error
// occurs while parsing NETLINK messages. This error is sent
// through the Errors() channel.
type ParserError string

func (err ParserError) Error() string {
	return "nflog: error while parsing message: " + string(err)
}

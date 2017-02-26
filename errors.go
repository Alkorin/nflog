package nflog

type ConfigurationError string

func (err ConfigurationError) Error() string {
	return "nflog: invalid configuration: " + string(err)
}

type ReaderError string

func (err ReaderError) Error() string {
	return "nflog: error while reading socket: " + string(err)
}

type ParserError string

func (err ParserError) Error() string {
	return "nflog: error while parsing message: " + string(err)
}

package data

type Message struct {
	Message string `json:"message"`
}

type HttpError struct {
	Code    int
	Message Message
}

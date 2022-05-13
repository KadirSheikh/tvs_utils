package utils

type Response struct {
	Message     string      `json:"message"`
	Status_code int         `json:"status_code"`
	Data        interface{} `json:"data"`
}

type EmptyObj struct{}

func BuildResponse(message string, code int, data interface{}) Response {

	res := Response{

		Message:     message,
		Status_code: code,
		Data:        data,
	}
	return res
}

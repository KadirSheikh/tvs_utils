package utils

type Status_code struct {
	Code    int
	Message string
}

func BadRequest() Status_code {
	return Status_code{Code: 500, Message: "Failed to process request.Please try again!"}
}

func OK(d int) Status_code {
	if d == 0 {
		return Status_code{Code: 200, Message: "Login Successful!"}
	} else if d == 1 {

		return Status_code{Code: 200, Message: "OK!"}
	}
	return Status_code{Code: 200, Message: "OK!"}
}

func InvalidCreds() Status_code {
	return Status_code{Code: 401, Message: "Please check again your credential!"}
}

func Conflict(d int) Status_code {
	if d == 0 {
		return Status_code{Code: 409, Message: "Username already in use.Please use different username!"}
	} else if d == 1 {

		return Status_code{Code: 409, Message: "Email already in use.Please use different email!"}
	} else if d == 2 {
		return Status_code{Code: 409, Message: "Vehicle already exists!"}
	}
	return Status_code{Code: 409, Message: "Conflict!"}
}

func Failed() Status_code {
	return Status_code{Code: 400, Message: "Failed.Please try again!"}
}

func Created(d int) Status_code {
	if d == 0 {
		return Status_code{Code: 201, Message: "Registration Successful!"}
	} else if d == 1 {
		return Status_code{Code: 201, Message: "Vehicle added Successful!"}
	}
	return Status_code{Code: 201, Message: "Successfully added!"}
}

func NotFound() Status_code {
	return Status_code{Code: 404, Message: "Id not found!"}
}

func Updated() Status_code {
	return Status_code{Code: 204, Message: "Updated Successfully!"}
}

func Deleted() Status_code {
	return Status_code{Code: 204, Message: "Deleted Successfully!"}
}

func Unauthorized() Status_code {
	return Status_code{Code: 401, Message: "You do not have permission to make this request!"}
}

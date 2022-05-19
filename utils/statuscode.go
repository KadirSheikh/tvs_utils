package utils

type Status_code struct {
	Code    int
	Message string
}

func BadRequest() Status_code {
	return Status_code{Code: 400, Message: "Failed to process request.Please try again!"}
}

func OK(d int) Status_code {
	if d == 0 {
		return Status_code{Code: 200, Message: "Login Successful!"}
	} else if d == 1 {
		return Status_code{Code: 200, Message: "Updated Successfully!"}
	} else if d == 2 {
		return Status_code{Code: 200, Message: "Deleted Successfully!"}
	} else if d == 3 {
		return Status_code{Code: 200, Message: "Password Reset Successfully!"}
	}
	return Status_code{Code: 200, Message: "OK!"}
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

func Created(d int) Status_code {
	if d == 0 {
		return Status_code{Code: 201, Message: "Registration Successful!"}
	} else if d == 1 {
		return Status_code{Code: 201, Message: "Vehicle added Successful!"}
	} else if d == 2 {
		return Status_code{Code: 201, Message: "Address added Successful!"}
	}
	return Status_code{Code: 201, Message: "Successfully added!"}
}

func NotFound(d int) Status_code {
	if d == 0 {
		return Status_code{Code: 404, Message: "Login Id not found!"}
	} else if d == 1 {
		return Status_code{Code: 404, Message: "No user found!"}
	} else if d == 2 {
		return Status_code{Code: 404, Message: "Vehicle registration number found!"}
	} else if d == 3 {
		return Status_code{Code: 404, Message: "No token found!"}
	} else if d == 4 {
		return Status_code{Code: 404, Message: "No Address found!"}
	} else if d == 5 {
		return Status_code{Code: 404, Message: "No Vehicle found!"}
	} else if d == 6 {
		return Status_code{Code: 404, Message: "Role Id not found!"}
	} else if d == 7 {
		return Status_code{Code: 404, Message: "User Id not found!"}
	}
	return Status_code{Code: 404, Message: "Not found!"}
}

func Unauthorized(d int) Status_code {
	if d == 0 {
		return Status_code{Code: 401, Message: "You do not have permission to make this request!"}
	}
	return Status_code{Code: 401, Message: "Please check again your credential!"}
}

func ViolationFound(d int) Status_code {
	if d == 0 {

		return Status_code{Code: 404, Message: "Registration Number not found!"}
	}
	return Status_code{Code: 404, Message: "Violation id not found!"}
}

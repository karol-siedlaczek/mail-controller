from mail_controller.exception.api_exceptions import ApiError


class AuthException(ApiError):
    pass


class AuthTokenMissingException(AuthException):
    def __init__(self, msg: str) -> None:
        super().__init__(401, msg="Authorization is required", detail=msg)


class AuthFailedException(AuthException):
    def __init__(self, msg: str) -> None:
        super().__init__(401, msg="Authorization failed", detail=msg)


class AuthIpNotAllowedException(AuthException):
    def __init__(self, ip_addr: str) -> None:
        super().__init__(403, msg="Access denied", detail=f"Request from IP address '{ip_addr}' is not permitted for this identity")

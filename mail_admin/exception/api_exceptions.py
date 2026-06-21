class ApiError(Exception):
    code: int
    msg: str
    detail: object
    level: str

    def __init__(
        self,
        code: int,
        *,
        msg: str,
        detail: object | None = None,
        level: str = "warning",
    ) -> None:
        self.code = code
        self.msg = msg
        self.detail = detail
        self.level = level
        super().__init__(f"{msg}: {detail}")


class InvalidRequestError(ApiError):
    def __init__(self, msg: str, *, detail: object | None = None) -> None:
        super().__init__(400, msg=msg, detail=detail)


class PermissionDeniedError(ApiError):
    def __init__(self, *, msg: str = "Permission denied", detail: object | None = None) -> None:
        super().__init__(403, msg=msg, detail=detail)


class ResourceNotFoundError(ApiError):
    def __init__(self, *, msg: str = "Resource not found", detail: object | None = None) -> None:
        super().__init__(404, msg=msg, detail=detail)


class ConflictError(ApiError):
    def __init__(self, *, msg: str = "Resource already exists", detail: object | None = None) -> None:
        super().__init__(409, msg=msg, detail=detail)


class UnprocessableError(ApiError):
    def __init__(self, *, msg: str, detail: object | None = None) -> None:
        super().__init__(422, msg=msg, detail=detail)

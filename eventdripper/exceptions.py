
class EventDripperError(Exception):
    pass


class InvalidHeaderError(EventDripperError):
    pass


class SignatureExpiredError(EventDripperError):
    pass


class InvalidSignatureError(EventDripperError):
    pass


class InvalidPayloadFormatError(EventDripperError):
    pass

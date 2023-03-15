# Batch helper error
class BatchHelperError(Exception):
    """
    Base class for other exceptions.

    Attributes:
        message -- explanation of the error
    """

    message = "Something went wrong."

    def __init__(self, message=message):
        self.message = message
        super().__init__(self.message)


# To catch exceptions when using the batch helper
class IntervalFactorTooSmallError(BatchHelperError):
    """
    Raised when the polling interval is too short.

    Attributes:
        interval_factor -- the requested interval factor
        message -- explanation of the error
    """

    def __init__(self, interval_factor):
        self.interval_factor = interval_factor
        self.message = f'The polling interval factor must be at least {MINIMUM_INTERVAL_FACTOR}.'
        super().__init__(self.message)


class NotEnoughActionsError(BatchHelperError):
    """
    Raised when the number of actions is too few.

    Attributes:
        actions_per_batch -- the requested number of actions per batch
        message -- explanation of the error
    """

    def __init__(self, actions_per_batch):
        self.actions_per_batch = actions_per_batch
        self.message = f'The minimum number of actions in a batch is {MIN_ACTIONS}.'
        super().__init__(self.message)


class TooManyActionsError(BatchHelperError):
    """
    Raised when the number of actions is too many.

    Attributes:
        actions_per_batch -- the requested number of actions per batch
        message -- explanation of the error
    """

    def __init__(self, actions_per_batch):
        self.actions_per_batch = actions_per_batch
        self.message = f'The maximum number of actions in a batch is {MAX_ACTIONS_ASYNC}.'
        super().__init__(self.message)


class TooManySynchronousActionsError(BatchHelperError):
    """
    Raised when the number of synchronous actions is too many.

    Attributes:
        actions_per_batch -- the requested number of actions per batch
        message -- explanation of the error
    """

    def __init__(self, actions_per_batch):
        self.actions_per_batch = actions_per_batch
        self.message = f'The maximum number of actions in a synchronous batch is {MAX_ACTIONS_SYNC}.'
        super().__init__(self.message)


class RequiredBatchIdError(BatchHelperError):
    """
    Raised when the user doesn't provide a batch ID.

    Attributes:
        actions_per_batch -- the requested number of actions per batch
        message -- explanation of the error
    """

    def __init__(self):
        self.message = f'If dependent, then you must specify depends_on_batch_id.'
        super().__init__(self.message)


class RequiredBatchOrganizationError(BatchHelperError):
    """
    Raised when the user doesn't provide a batch ID.

    Attributes:
        actions_per_batch -- the requested number of actions per batch
        message -- explanation of the error
    """

    def __init__(self):
        self.message = f'If you set same_organization False, then you must specify the alternateOrganizationId.'
        super().__init__(self.message)


class RequiredBatchFailureError(BatchHelperError):
    """
    Raised when the required batch has failed.

    Attributes:
        depends_on_batch_id -- the ID of the batch dependency
        message -- explanation of the error
    """

    def __init__(self, depends_on_batch_id, batch_errors: list = []):
        self.depends_on_batch_id = depends_on_batch_id
        self.batch_errors = batch_errors
        self.message = f'The required batch with ID {self.depends_on_batch_id} failed. The errors are {batch_errors}.'
        super().__init__(self.message)


class RequiredBatchNotFoundError(BatchHelperError):
    """
    Raised when the required batch is not found.

    Attributes:
        depends_on_batch_id -- the ID of the batch dependency
        organizationId -- the ID of the org where the batch should be
        message -- explanation of the error
    """

    def __init__(self, depends_on_batch_id, organizationId):
        self.depends_on_batch_id = depends_on_batch_id
        self.organizationId = organizationId
        self.message = f'The required batch with ID {self.depends_on_batch_id} in org ID {self.organizationId} was' \
                       f' not found.'
        super().__init__(self.message)


class RequiredBatchNotStartedError(BatchHelperError):
    """
    Raised when the required batch is not found.

    Attributes:
        depends_on_batch_id -- the ID of the batch dependency
        organizationId -- the ID of the org where the batch should be
        message -- explanation of the error
    """

    def __init__(self, depends_on_batch_id, organizationId):
        self.depends_on_batch_id = depends_on_batch_id
        self.organizationId = organizationId
        self.message = f'The required batch with ID {self.depends_on_batch_id} in org ID {self.organizationId} has' \
                       f' not been started (e.g. set confirmed to true). Start any required batches before using this' \
                       f' feature!'
        super().__init__(self.message)


class RequiredBatchStillInProgress(BatchHelperError):
    """
    Raised when the required batch is not found.

    Attributes:
        depends_on_batch_id -- the ID of the batch dependency
        organizationId -- the ID of the org where the batch should be
        message -- explanation of the error
    """

    def __init__(self, depends_on_batch_id, organizationId):
        self.depends_on_batch_id = depends_on_batch_id
        self.organizationId = organizationId
        self.message = f'The required batch with ID {self.depends_on_batch_id} in org ID {self.organizationId} did' \
                       f' not complete within the maximum wait time.'
        super().__init__(self.message)


class BatchCreationFailureError(BatchHelperError):
    """
    Raised when the required batch is not found.

    Attributes:
        message -- explanation of the error
    """

    def __init__(self):
        self.message = f'There was an error submitting an action batch.'
        super().__init__(self.message)


class LinearBatchRequirementsError(BatchHelperError):
    """
    Raised when attempting to combine unconfirmed new batches with linear new batches.

    Attributes:
        message -- explanation of the error
    """

    def __init__(self):
        self.message = f'Linear new batches, which submits new batches in order upon completion of the prior batch,' \
                       f'requires new batches to be confirmed, so that they start immediately upon submission.'


class UnpreparedError(BatchHelperError):
    """
    Raised when attempting to execute a batch helper without preparing it first.

    Attributes:
        message -- explanation of the error
    """

    def __init__(self):
        self.message = f'Executing a batch helper requires preparing it first.'

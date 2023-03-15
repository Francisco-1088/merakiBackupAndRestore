import time
import json
from enum import Enum, auto

import meraki

from .config import *
from .exceptions import *

__version__ = '0.1.0a'


class BatchHelperStatus(Enum):
    """Batch helper statuses."""

    COMPLETE = auto()
    PREPARED = auto()
    WORKING = auto()
    PENDING = auto()
    FAILED = auto()


class BatchHelper:

    def __init__(self,
                 dashboard_session: meraki.DashboardAPI,
                 organizationId: str,
                 new_actions: list,
                 dependent: bool = False,
                 required_batch_id: str = "__default__",
                 alternateOrganizationId: str = "__default__",
                 linear_new_batches: bool = False,
                 confirmed_new_batches: bool = True,
                 synchronous_new_batches: bool = False,
                 actions_per_new_batch: int = MAX_ACTIONS_ASYNC,
                 interval_factor: float = MINIMUM_INTERVAL_FACTOR,
                 maximum_wait: int = MAXIMUM_WAIT):
        """ Creates the batch helper.
        @param dashboard_session: the Meraki Python SDK dashboard session used for executing the batch
        @param organizationId: the Meraki organization ID of the relevant organization where the batch will be run
        @param new_actions: the list of all aggregated new actions that the batch helper will parse
        @param dependent: whether the new actions rely on a different batch to finish first
        @param required_batch_id: when dependent, required_batch_id is the ID of the batch upon which the new batches
        depend
        @param alternateOrganizationId: supplied if the required batch is from a different organization ID
        @param linear_new_batches: whether the new actions need to be executed linearly; requires confirmed new batches
        @param confirmed_new_batches: whether the submitted batches will start upon submission
        @param synchronous_new_batches: whether the submitted batches will be synchronous
        @param actions_per_new_batch: maximum number of actions to group into a single batch
        @param interval_factor: the factor to use for determining wait time
        @param maximum_wait: the maximum wait time in seconds for the entire list of new_actions
        """

        # self assignments
        self.dashboard_session = dashboard_session
        self.organizationId = organizationId
        self.new_actions = new_actions
        self.dependent = dependent
        self.required_batch_id = required_batch_id
        self.alternateOrganizationId = alternateOrganizationId
        self.linear_new_batches = linear_new_batches
        self.confirmed_new_batches = confirmed_new_batches
        self.synchronous_new_batches = synchronous_new_batches
        self.actions_per_new_batch = actions_per_new_batch
        self.interval_factor = interval_factor
        self.maximum_wait = maximum_wait
        self.status = BatchHelperStatus.PENDING

        # defaults prior to preparation
        self.preview = ''
        self.new_batches = list()
        self.new_batches_responses = list()
        self.submitted_new_batches_ids = list()
        self.successful_new_batch_ids = list()
        self.failed_new_batch_ids = list()

        # Validate batch helper input against common mistakes.
        print(f'Validating input...')

        # validate number of actions per batch
        if self.actions_per_new_batch > 100:
            status = BatchHelperStatus.FAILED
            raise TooManyActionsError(self.actions_per_new_batch)

        if self.actions_per_new_batch < 2:
            status = BatchHelperStatus.FAILED
            raise NotEnoughActionsError(self.actions_per_new_batch)

        # validate number of actions per batch in an async batch
        if self.actions_per_new_batch > 20 and self.synchronous_new_batches:
            status = BatchHelperStatus.FAILED
            raise TooManySynchronousActionsError(self.actions_per_new_batch)

        # validate polling interval
        if self.interval_factor < MINIMUM_INTERVAL_FACTOR:
            status = BatchHelperStatus.FAILED
            raise IntervalFactorTooSmallError(interval_factor)

        # validate required batch ID
        if self.dependent and self.required_batch_id == "__default__":
            status = BatchHelperStatus.FAILED
            raise RequiredBatchIdError()

        # enforce linear new batches requirements
        if self.linear_new_batches and not self.confirmed_new_batches:
            status = BatchHelperStatus.FAILED
            raise LinearBatchRequirementsError()

        if self.alternateOrganizationId == '__default__':
            self.required_batch_org_id = self.organizationId
        else:
            self.required_batch_org_id = self.alternateOrganizationId

    def group_actions(self):
        """ Groups actions into lists of appropriate size and returns a list generator. """
        total_actions = len(self.new_actions)
        for i in range(0, total_actions, self.actions_per_new_batch):
            yield self.new_actions[i:i + self.actions_per_new_batch]

    def prepare(self):
        """ Groups actions into batches of the appropriate size. """
        grouped_actions_list = list(self.group_actions())
        created_batches = list()

        # Add each new batch to the new_batches list
        for action_list in grouped_actions_list:
            batch = {
                "organizationId": self.organizationId,
                "actions": action_list,
                "synchronous": self.synchronous_new_batches,
                "confirmed": self.confirmed_new_batches
            }
            created_batches.append(batch)

        self.new_batches = created_batches
        self.status = BatchHelperStatus.PREPARED

    def wait_for_required_batch(self):
        """ When the batches are dependent or linear, waits for the required batch to finish. """

        time_waited = 0
        completed = False
        while time_waited < self.maximum_wait and not completed:
            # While we haven't waited the maximum time and the required batch hasn't completed
            try:
                # Check on the required batch
                required_batch = self.dashboard_session.organizations.getOrganizationActionBatch(
                    self.required_batch_org_id, self.required_batch_id
                )
            except meraki.APIError:
                # If it doesn't exist, raise error
                status = BatchHelperStatus.FAILED
                raise RequiredBatchNotFoundError(self.required_batch_id, self.required_batch_org_id)

            if required_batch['status']['completed']:
                # If it's complete, stop waiting
                self.successful_new_batch_ids.append(required_batch['id'])
                completed = True

            if not required_batch['confirmed']:
                # If it's not confirmed, then it hasn't started, so stop waiting.
                self.status = BatchHelperStatus.FAILED
                raise RequiredBatchNotStartedError(self.required_batch_id, self.required_batch_org_id)

            # if it's started, but it's not complete, check its status on an interval
            if required_batch['confirmed'] and not required_batch['status']['completed']:
                if required_batch['status']['failed']:
                    # if it failed, then stop waiting
                    self.status = BatchHelperStatus.FAILED
                    self.failed_new_batch_ids.append(required_batch['id'])

                    raise RequiredBatchFailureError(self.required_batch_id,
                                                    batch_errors=required_batch['status']['errors'])

                # wait a reasonable interval dependent upon the number of actions in the batch
                length_of_required_batch_actions = len(required_batch['actions'])
                interval = length_of_required_batch_actions * self.interval_factor

                # don't wait longer than the maximum
                if time_waited + interval > MAXIMUM_WAIT:
                    interval = MAXIMUM_WAIT - time_waited - 1

                # update elapsed timer to ensure max wait is not exceeded
                time_waited += interval

                # Print update to console and start waiting
                print(f'Required batch ID {self.required_batch_id} in progress. Waiting {interval} seconds for it to '
                      f'complete.')

                # wait
                time.sleep(interval)

        if time_waited >= self.maximum_wait:
            # error if it's taken too long
            status = BatchHelperStatus.FAILED
            raise RequiredBatchStillInProgress(self.required_batch_id, self.required_batch_org_id)

        if completed:
            # return True if completed
            return True

    def check_batch_queue(self):
        """ Returns the organization's batch queue: pending, active, and whether full. """
        pending_action_batches = self.dashboard_session.organizations.getOrganizationActionBatches(
            organizationId=self.organizationId,
            status='pending')
        active_action_batches = [batch for batch in pending_action_batches if batch['confirmed']]

        # Dashboard API supports up to MAXIMUM_ACTIVE_ACTION_BATCHES.
        batch_queue_is_full = True if len(active_action_batches) >= MAXIMUM_ACTIVE_ACTION_BATCHES else False

        print(f'Checking batch queue...')
        return pending_action_batches, active_action_batches, batch_queue_is_full

    def find_batch_queue_capacity(self):
        """ Finds capacity on the batch queue. """
        pending_action_batches, active_action_batches, batch_queue_is_full = self.check_batch_queue()
        number_of_active_batches = len(active_action_batches)
        print(f'There are {number_of_active_batches} active action batches.')

        if len(active_action_batches):
            # If there are any active action batches, then flatten the list of actions; we want to know how many total
            # actions are pending, so we can calculate a reasonable wait time. Waiting too long is no fun, but
            # checking too frequently is inefficient, and might impact other API applications.
            print(f'Finding batch queue capacity...')

            # Gather all the action lists for the existing action batches
            active_batch_action_lists = [batch['actions'] for batch in active_action_batches]

            # Flatten the list of action lists into a single list of actions
            active_batch_actions = [action for action_list in active_batch_action_lists for action in action_list]

            # Calculate the mean number of actions per batch
            mean_actions_per_batch = len(active_batch_actions) / number_of_active_batches

            # Set an interval based on the interval_factor and the mean actions per batch
            interval = self.interval_factor * mean_actions_per_batch

            while batch_queue_is_full:
                # Wait for space in the queue until there's an open slot.
                print(f'There are already {number_of_active_batches} active action batches. Waiting {interval} '
                      f'seconds before trying again.')
                time.sleep(interval)

                active_action_batches, active_action_batches, batch_queue_is_full = self.check_batch_queue()
        return True

    def confirm_readiness_for_new_batch(self):
        """ Confirm that the org is ready to accept a new batch. """
        if self.dependent:
            # if dependent, check that the required batch has completed
            self.wait_for_required_batch()

        return True

    def submit_action_batches(self):
        """ Submit the next batch and remove it from the list of remaining batches. """
        try:
            new_batch_response = self.dashboard_session.organizations.createOrganizationActionBatch(**self.new_batches.pop(0))
        except meraki.APIError:
            self.status = BatchHelperStatus.FAILED
            raise BatchCreationFailureError()

        self.new_batches_responses.append(new_batch_response)
        self.submitted_new_batches_ids.append(new_batch_response['id'])

        print(f'Creating the next action batch. {len(self.new_batches)} action batches remain.')

        if not self.linear_new_batches:
            # set dependent false, and required batch ID to default
            self.dependent = False
            self.required_batch_id = '__default__'
        else:
            self.dependent = True
            self.required_batch_id = new_batch_response['id']

    def generate_preview(self):
        """ Generates a JSON preview of the new batches. """
        self.prepare()

        preview_json = json.dumps(self.new_batches, indent=2)
        with open('batch_helper_preview.json', 'w+', encoding='utf-8', newline='') as preview_file:
            preview_file.write(preview_json)

    def execute(self):
        """ Submits new batches. """
        while len(self.new_batches):
            self.status = BatchHelperStatus.WORKING
            # Loop as long as there are batches left to process
            print(f'Confirming readiness for batch submission...')

            # Check that the environment is ready for the new batch. Set a single variable false until it passes all the
            # while loop gates
            ready_for_new_batch = False
            while not ready_for_new_batch:
                # Confirm readiness before proceeding. Need to figure out how to pass this required batch ID in such a
                # way that it can change from the initial required batch, to the linear preceding batch, if linear
                ready_for_new_batch = self.confirm_readiness_for_new_batch()

            ready_for_new_batch = False
            while not ready_for_new_batch:
                ready_for_new_batch = self.find_batch_queue_capacity()

            print(f'Submitting new batch.')
            # submit new batch(es)
            self.submit_action_batches()

        self.status = BatchHelperStatus.COMPLETE

        return True


# batch_helper Constants

# Configurable
# --------------------------------------------------
# Maximum number of seconds the helper will wait for any batch to complete before submitting the next
MAXIMUM_WAIT: int = 900

# The minimum number of actions that are required to submit actions to the batch helper.
# If there's a reason to submit action batches with only one action, then please, let us know on GitHub!
MIN_ACTIONS: int = 2

# When waiting for batches to complete, this number times the number of actions in the batch determines how many seconds
# the helper will wait before checking the batch queue. You if your action batches typically take longer to run, you
# can raise this to help conserve your API budget, but there's not much reason to lower it, unless you want to consume
# more API calls to no positive end.
MINIMUM_INTERVAL_FACTOR: float = 0.05

# Less configurable
# --------------------------------------------------
# These values reflect API limits and are 'the law'. Raising them probably doesn't make sense.
# If you do find any reason to raise them, please let us know on GitHub :)
MAX_ACTIONS_SYNC: int = 20
MAX_ACTIONS_ASYNC: int = 100
MAXIMUM_ACTIVE_ACTION_BATCHES: int = 5

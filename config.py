API_KEY= ''
backup_tag = 'merakiBackup'
restore_tag = 'merakiRestore'
backup_directory = './backup'
# Optional, only use one of the following
org_number_filter = [''] # Optional, add any Org IDs comma separated
org_name_filter = 'Fran' # Optional, initial org discovery will filter your organizations for org names containing the string
# Python logging
logging_level="DEBUG" #DEBUG,INFO,ERROR
# Meraki SDK Logs
console_logging=True
max_retries=100
max_requests=10

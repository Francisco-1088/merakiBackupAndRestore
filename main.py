import backupFunctions
import restoreFunctions
import batch_helper
import asyncio
import meraki
import meraki.aio
import json
import time
import os
import sys
import glob
import pandas as pd
from tabulate import tabulate
import config
from datetime import datetime

def print_tabulate(data):
    df = pd.DataFrame(data)
    print(tabulate(df, headers='keys', tablefmt='fancy_grid'))

def read_orgs(dashboard, operation):
    orgs = dashboard.organizations.getOrganizations()
    print("Your API Key has access to the following organizations: ")
    print_tabulate(orgs)
    choice = int(input(f"Which organization do you want to perform a {operation} on? (Enter the table row number): "))
    org = orgs[choice]
    print(f"Working on organization {org['name']} - {org['id']}.")
    return org

def read_nets(dashboard, operation, org_id, tag):
    nets = dashboard.organizations.getOrganizationNetworks(organizationId=org_id, tags=[tag])
    print(f"Performing a {operation} operation on the following networks with the tag {tag}: ")
    print_tabulate(nets)
    proceed = input("Proceed? (Y/N): ")
    return nets, proceed


if __name__ == "__main__":
    dashboard = meraki.DashboardAPI(config.API_KEY, maximum_retries=100, print_console=config.console_logging)
    print('Welcome to the Meraki Backup and Restore tool. Please select an option:')
    print('1 - Backup my Meraki networks')
    print('2 - Restore my Meraki networks to an existing backup')
    option = int(input("Enter the option number: "))
    if option == 1:
        org = read_orgs(dashboard, 'backup')
        nets, proceed = read_nets(dashboard, 'backup', org['id'], tag=config.backup_tag)
        timestr = datetime.now().isoformat()
        backup_path = f"{config.backup_directory}/{org['id']}_{org['name']}_{timestr.replace(':', '-')}"
        if proceed == 'Y':
            if not os.path.exists(config.backup_directory):
                os.makedirs(config.backup_directory)
            if not os.path.exists(backup_path):
                os.makedirs(backup_path)
            api_version = {"api_version": meraki.rest_session.__version__}
            with open(f'{backup_path}/api_version.json', 'w') as fp:
                json.dump(api_version, fp)
                fp.close()
            backup_operations = backupFunctions.merakiBackup(dir=backup_path, org=org, networks=nets, dashboard=dashboard)
            backup_operations_df = pd.DataFrame(backup_operations)
            print_tabulate(backup_operations_df)
            backup_operations_df.to_csv(f'{backup_path}/backup_operations.csv')
    elif option == 2:
        org = read_orgs(dashboard, 'restore')
        nets, proceed = read_nets(dashboard, 'restore', org['id'], tag=config.restore_tag)
        print('Found the following backups in the backup directory: ')
        eligible_backups = []
        for root, dirs, files in os.walk(f'{config.backup_directory}/'):
            if config.backup_directory in root:
                i = 1
                for backup in dirs:
                    if org['id'] in backup:
                        eligible_backups.append(backup)
                        print(f'{i} - {backup}')
                        i = i + 1
        if len(eligible_backups) == 0:
            print('No eligible backups for selected org.')
        elif len(eligible_backups) > 0:
            option = int(input('Enter desired backup number: '))
            print(f'Selected backup is: {eligible_backups[option - 1]}')
            path = eligible_backups[option - 1]
        restore_net_names = [net['name'] for net in nets]
        restore_path = f"{config.backup_directory}/{path}"
        net_names_in_backup = next(os.walk(f"{restore_path}/network"))[1]
        restore_set = set(restore_net_names)
        backup_set = set(net_names_in_backup)
        definitive_set = restore_set & backup_set
        print(f"Out of all networks with the tag {config.restore_tag} in {org['name']}, only {definitive_set} were found in the selected backup.")
        proceed = input("Do you wish to proceed? (Y/N): ")
        if proceed=='Y':
            restore_nets = [net for net in nets if net['name'] in definitive_set]
            print(restore_nets)
            restore_operations = restoreFunctions.merakiRestore(org=org['id'], dir=restore_path,nets=restore_nets,dashboard=dashboard)
            restore_operations_df = pd.DataFrame(restore_operations)
            #print_tabulate(restore_operations_df)
            restore_operations_df.to_csv(f'{restore_path}/restore_operations.csv')
        elif proceed=='N':
            print("Stopping restore!")
            sys.exit()
        else:
            print("Invalid selection!")
            sys.exit()
    else:
        print("Invalid selection!")
        sys.exit()



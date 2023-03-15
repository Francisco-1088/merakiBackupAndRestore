import json
import os
import time
import pandas as pd
import base64
import sys
import meraki
import logging
import logging_class
import config


if config.logging_level=="DEBUG":
    level=logging.DEBUG
elif config.logging_level=="INFO":
    level=logging.INFO
elif config.logging_level=="ERROR":
    level=logging.ERROR

# create logger with 'spam_application'
logger = logging.getLogger("merakiBackupAndRestore")
logger.setLevel(level)

# create console handler with a higher log level
ch = logging.StreamHandler()
ch.setLevel(logging.DEBUG)

ch.setFormatter(logging_class.CustomFormatter())

logger.addHandler(ch)

#dashboard = meraki.DashboardAPI(config.API_KEY)

def merakiRestore(dir, org, nets, dashboard):
    """
    Wrapper function for restore operations. Will iterate across the list of networks and perform applicable
    restore operations, and return a list of dictionaries of operations with their status.
    :param dir: path to backup
    :param networks: list of networks being backed up
    :param dashboard: Meraki API client
    :return: operations: list of operations performed with their status
    """
    operations = []
    path = dir
    if 'organization' in next(os.walk(f"{path}"))[1]:
        if 'policy_objects' in next(os.walk(f"{path}/organization"))[1]:
            if ('policy_objects.json' and 'policy_objects_groups.json') in next(os.walk(f"{path}/organization/policy_objects"))[2]:
                logger.info("Restoring Organization Policy Objects...")
                operations.append(restoreOrganizationPolicyObjects(org=org, dashboard=dashboard, path=path))
        if 'ipsec_vpn' in next(os.walk(f"{path}/organization"))[1]:
            if ('ipsec_vpn.json') in next(os.walk(f"{path}/organization/ipsec_vpn"))[2]:
                logger.info("Restoring Organization IPsec VPN...")
                operations.append(restoreOrganizationMxIpsecVpn(org=org, dashboard=dashboard, path=path))
        if 'vpn_firewall' in next(os.walk(f"{path}/organization"))[1]:
            if ('vpn_firewall.json') in next(os.walk(f"{path}/organization/vpn_firewall"))[2]:
                logger.info("Restoring Organization VPN Firewall...")
                operations.append(restoreOrganizationMxVpnFirewall(org=org, dashboard=dashboard, path=path))

    for net in nets:
        logger.info(f"Restoring settings for network {net['name']}...")
        settings_in_backup = next(os.walk(f"{path}/network/{net['name']}"))[1]
        logger.debug(settings_in_backup)
        # Check if firmware in backup matches firmware in target network
        if 'firmware' in settings_in_backup:
            checkFirmware(net=net, dashboard=dashboard, path=path)
        devices_in_network = dashboard.networks.getNetworkDevices(networkId=net['id'])
        # Restore Network Settings
        if 'webhooks' in settings_in_backup:
            if ('webhooks_payload_templates.json' and 'webhooks_servers.json') in next(os.walk(f"{path}/network/{net['name']}/webhooks"))[2]:
                logger.info("Restoring Webhooks...")
                operations.append(restoreNetworkWebhooks(net=net, dashboard=dashboard, path=path))
        if 'syslog' in settings_in_backup:
            if ('syslog.json') in next(os.walk(f"{path}/network/{net['name']}/syslog"))[2]:
                logger.info("Restoring Syslog...")
                operations.append(restoreNetworkSyslog(net=net, dashboard=dashboard, path=path))
        if 'snmp' in settings_in_backup:
            if ('snmp.json') in next(os.walk(f"{path}/network/{net['name']}/snmp"))[2]:
                logger.info("Restoring SNMP...")
                operations.append(restoreNetworkSnmp(net=net, dashboard=dashboard, path=path))
        if 'alert_settings' in settings_in_backup:
            if ('alerts.json') in next(os.walk(f"{path}/network/{net['name']}/alert_settings"))[2]:
                logger.info("Restoring Alerts...")
                operations.append(restoreNetworkAlerts(net=net, dashboard=dashboard, path=path))
        if 'floorplans' in settings_in_backup:
            if ('floorplans.json') in next(os.walk(f"{path}/network/{net['name']}/floorplans"))[2]:
                logger.info("Restoring Floorplans...")
                operations.append(restoreNetworkFloorplans(net=net, dashboard=dashboard, path=path))
        if 'devices' in settings_in_backup:
            if ('network_devices.json') in next(os.walk(f"{path}/network/{net['name']}/devices"))[2]:
                logger.info("Restoring Network Device settings...")
                operation, devices_to_update = restoreNetworkDevices(net=net, org=org, devices_in_network=devices_in_network, dashboard=dashboard, path=path)
                operations.append(operation)
        if 'appliance' or 'switch' or 'wireless' in net['productTypes'] and 'group_policies' in settings_in_backup:
            logger.info("Restoring Group Policies...")
            operations.append(restoreNetworkGroupPolicies(net=net, dashboard=dashboard, path=path))
        if 'appliance' in net['productTypes'] and 'appliance' in settings_in_backup:
            if 'settings' in next(os.walk(f"{path}/network/{net['name']}/appliance"))[1]:
                # Restore MX Settings
                if 'settings.json' in next(os.walk(f"{path}/network/{net['name']}/appliance/settings"))[2]:
                    logger.info("Restoring MX appliance settings...")
                    settings_operation, settings_data = restoreMxSettings(net=net, dashboard=dashboard, path=path)
                    operations.append(settings_operation)
            if settings_data['deploymentMode']=="routed":
                if 'vlans' in next(os.walk(f"{path}/network/{net['name']}/appliance"))[1]:
                    # Restore VLAN config from vlan_config, vlan_ports and vlan_settings files
                    # Read if VLANs are enabled in the backup
                    if 'vlan_settings.json' in next(os.walk(f"{path}/network/{net['name']}/appliance/vlans"))[2]:
                        # Apply VLAN settings
                        logger.info("Restoring VLAN settings...")
                        vlan_settings_operation, vlan_settings_data = restoreMxVlanSettings(net=net, dashboard=dashboard, path=path)
                        operations.append(vlan_settings_operation)
                        # If VLANs were enabled in the checkpoint, then proceed to configure them individually
                        if vlan_settings_data['vlansEnabled'] == True and ('vlan_config.json' and 'vlan_ports.json') in next(os.walk(f"{path}/network/{net['name']}/appliance/vlans"))[2]:
                            logger.info("Restoring MX per VLAN configuration...")
                            operations.append(restoreMxVlansBatch(org=org, net=net, dashboard=dashboard, path=path))
                if 'appliance_routing' in next(os.walk(f"{path}/network/{net['name']}/appliance"))[1]:
                    # Restore MX Static Routing
                    # Needs to be restored before it is used for Site to Site VPN configs
                    if 'static_routes.json' in next(os.walk(f"{path}/network/{net['name']}/appliance/appliance_routing"))[2]:
                        logger.info('Restoring MX Static Routes...')
                        operations.append(restoreMxStaticRouting(net=net, dashboard=dashboard, path=path))
            elif settings_data['deploymentMode']=='passthrough':
                if 'bgp_settings' in next(os.walk(f"{path}/network/{net['name']}/appliance"))[1]:
                    # Restore MX BGP
                    if 'bgp.json' in next(os.walk(f"{path}/network/{net['name']}/appliance"))[2]:
                        logger.info('Restoring MX BGP settings...')
                        operations.append(restoreMxBgp(net=net, dashboard=dashboard, path=path))
            if 'security' in next(os.walk(f"{path}/network/{net['name']}/appliance"))[1]:
                # Restore MX Security Settings
                if ('amp.json' and 'ips.json') in next(os.walk(f"{path}/network/{net['name']}/appliance/security"))[
                    2]:
                    logger.info("Restoring MX Security...")
                    operations.append(restoreMxSecurity(net=net, dashboard=dashboard, path=path))
                # Restore MX Firewall Settings
                if ('l3_fw.json' and 'l7_fw.json') in next(os.walk(f"{path}/network/{net['name']}/appliance/security"))[
                    2]:
                    logger.info("Restoring MX Firewall...")
                    operations.append(restoreMxFirewall(net=net, dashboard=dashboard, path=path))
                # Restore MX Content Filtering
                if ('content_filtering.json') in \
                        next(os.walk(f"{path}/network/{net['name']}/appliance/security"))[
                            2]:
                    logger.info("Restoring MX Content Filtering...")
                    operations.append(restoreMxContentFiltering(net=net, dashboard=dashboard, path=path))
            if 'shaping' in next(os.walk(f"{path}/network/{net['name']}/appliance"))[1]:
                # Restore Shaping Settings
                if ('global_shaping.json' and 'shaping_rules') in \
                        next(os.walk(f"{path}/network/{net['name']}/appliance/shaping"))[
                                2]:
                    logger.info("Restoring MX Shaping...")
                    operations.append(restoreMxShaping(net=net, dashboard=dashboard, path=path))
            if 'vpn_config' in next(os.walk(f"{path}/network/{net['name']}/appliance"))[1]:
                # Restore VPN Settings
                if ('vpn_config.json') in \
                        next(os.walk(f"{path}/network/{net['name']}/appliance/vpn_config"))[
                                2]:
                    logger.info("Restoring VPN Settings...")
                    operations.append(restoreMxVpnConfig(net=net, dashboard=dashboard, path=path))
            if 'sdwan_settings' in next(os.walk(f"{path}/network/{net['name']}/appliance"))[1]:
                # Restore SDWAN Settings
                logger.info("Restoring SDWAN Settings...")
                operations.append(restoreMxSdWanSettings(net=net, dashboard=dashboard, path=path))
        if 'switch' in net['productTypes']and 'switch' in settings_in_backup:
            if 'switch_settings' in next(os.walk(f"{path}/network/{net['name']}/switch"))[1]:
                if 'port_schedules.json' in next(os.walk(f"{path}/network/{net['name']}/switch/switch_settings"))[2]:
                    logger.info("Restoring Switch Port Schedules...")
                    operations.append(restoreSwitchPortSchedules(net=net, dashboard=dashboard, path=path))
                if 'qos_rules.json' in next(os.walk(f"{path}/network/{net['name']}/switch/switch_settings"))[2]:
                    logger.info("Restoring Switch QoS...")
                    operations.append(restoreSwitchQos(net=net, dashboard=dashboard, path=path))
                if 'access_policies.json' in next(os.walk(f"{path}/network/{net['name']}/switch/switch_settings"))[2]:
                    logger.info("Restoring Access Policies...")
                    operations.append(restoreSwitchAccessPolicies(net=net, dashboard=dashboard, path=path))
                if len(next(os.walk(f"{path}/network/{net['name']}/switch/switch_settings"))[1])>0:
                    number_of_switches = len(next(os.walk(f"{path}/network/{net['name']}/switch/switch_settings"))[1])
                    if number_of_switches > 0:
                        logger.info(f"Restoring switch ports for {number_of_switches} switches...")
                        # Restore Switch Ports
                        operations.append(restoreSwitchPortConfigsBatch(org=org, net=net, dashboard=dashboard,
                                                                        path=path,
                                                                        devices_in_network=devices_in_network))
                if 'dhcp_policies.json' in next(os.walk(f"{path}/network/{net['name']}/switch/switch_settings"))[2]:
                    # Restore Switch DHCP Security
                    logger.info("Restoring Switch DHCP Policies...")
                    operations.append(restoreSwitchDhcpSecurity(net=net, dashboard=dashboard, path=path))
                if 'switch_stp.json' in next(os.walk(f"{path}/network/{net['name']}/switch/switch_settings"))[2]:
                    # Restore Switch STP
                    logger.info("Restoring Switch STP...")
                    operations.append(restoreSwitchStp(net=net, dashboard=dashboard, path=path))
                if 'switch_acl.json' in next(os.walk(f"{path}/network/{net['name']}/switch/switch_settings"))[2]:
                    # Restore Switch ACL
                    logger.info("Restoring Switch ACL...")
                    operations.append(restoreSwitchAcl(net=net, dashboard=dashboard, path=path))
                if 'switch_dscp_cos.json' in next(os.walk(f"{path}/network/{net['name']}/switch/switch_settings"))[2]:
                    # Restore Switch DHCP COS
                    logger.info("Restoring Switch DHCP COS Mappings...")
                    operations.append(restoreSwitchDscpCosMap(net=net, dashboard=dashboard, path=path))
                if 'switch_storm_control.json' in next(os.walk(f"{path}/network/{net['name']}/switch/switch_settings"))[2]:
                    # Restore Switch Storm Control
                    logger.info("Restoring Switch Storm Control...")
                    operations.append(restoreSwitchStormControl(net=net, dashboard=dashboard, path=path))
                if 'switch_mtu.json' in next(os.walk(f"{path}/network/{net['name']}/switch/switch_settings"))[2]:
                    # Restore Switch MTU
                    logger.info("Restoring Switch MTU...")
                    operations.append(restoreSwitchMtu(net=net, dashboard=dashboard, path=path))
                if 'switch_link_aggregations.json' in next(os.walk(f"{path}/network/{net['name']}/switch/switch_settings"))[2]:
                    # Restore Switch Link Aggregation
                    logger.info("Restoring Switch Link Aggregation...")
                    operations.append(restoreSwitchLinkAgg(net=net, dashboard=dashboard, path=path, devices_in_network=devices_in_network))
                if 'switch_settings.json' in next(os.walk(f"{path}/network/{net['name']}/switch/switch_settings"))[2]:
                    # Restore Switch Network Settings
                    logger.info("Restoring Switch Network Settings...")
                    operations.append(restoreSwitchSettings(net=net, dashboard=dashboard, path=path))

            if 'switch_routing' in next(os.walk(f"{path}/network/{net['name']}/switch"))[1]:
                if 'ospf.json' in next(os.walk(f"{path}/network/{net['name']}/switch/switch_routing/"))[2]:
                    # Restore Switch OSPF
                    logger.info(f"Restoring Switch OSPF for switch...")
                    operations.append(restoreSwitchOspf(net=net, dashboard=dashboard, path=path))
                if len(next(os.walk(f"{path}/network/{net['name']}/switch/switch_routing"))[1])>0:
                    # Restore Switch SVIs
                    logger.info(f"Restoring Switch SVIs...")
                    operations.append(restoreSwitchSvis(net=net, dashboard=dashboard, path=path, devices_in_network=devices_in_network))
                    # Restore Switch Static Routes
                    logger.info(f"Restoring Switch Static Routes...")
                    operations.append(restoreSwitchStaticRouting(net=net, dashboard=dashboard, path=path, devices_in_network=devices_in_network))


        if 'wireless' in net['productTypes']:
            if 'ssid_settings' in next(os.walk(f"{path}/network/{net['name']}/wireless"))[1]:
                if 'ssids.json' in next(os.walk(f"{path}/network/{net['name']}/wireless/ssid_settings/"))[2]:
                    # Restore SSID Settings
                    logger.info("Restoring SSID settings...")
                    operations.append(restoreMrSsidConfigs(net=net, dashboard=dashboard, path=path))
                if 'l3_rules.json' and 'l7_rules.json' in next(os.walk(f"{path}/network/{net['name']}/wireless/ssid_settings/"))[2]:
                    # Restore SSID FW settings
                    logger.info("Restoring SSID FW...")
                    operations.append(restoreMrSsidFW(net=net, dashboard=dashboard, path=path))
                if 'shaping_rules.json' in next(os.walk(f"{path}/network/{net['name']}/wireless/ssid_settings/"))[2]:
                    # Restore SSID Shaping settings
                    logger.info("Restoring SSID Shaping...")
                    operations.append(restoreMrSsidShaping(net=net, dashboard=dashboard, path=path))
            if 'radio_settings' in next(os.walk(f"{path}/network/{net['name']}/wireless"))[1]:
                if 'rf_profiles.json' in next(os.walk(f"{path}/network/{net['name']}/wireless/radio_settings/"))[2]:
                    # Restore RF Profile settings
                    logger.info("Restoring RF Profiles...")
                    operations.append(restoreMrRfProfiles(net=net, dashboard=dashboard, path=path, devices_in_network=devices_in_network))
            if 'bluetooth_settings' in next(os.walk(f"{path}/network/{net['name']}/wireless"))[1]:
                if 'network_bluetooth_settings.json' in next(os.walk(f"{path}/network/{net['name']}/wireless/bluetooth_settings/"))[2]:
                    # Restore Bluetooth settings
                    logger.info("Restoring MR Bluetooth...")
                    operations.append(restoreMrBluetooth(net=net, dashboard=dashboard, path=path, devices_in_network=devices_in_network))
            if 'network_wireless_settings' in next(os.walk(f"{path}/network/{net['name']}/wireless"))[1]:
                if 'network_wireless_settings.json' in next(os.walk(f"{path}/network/{net['name']}/wireless/network_wireless_settings/"))[2]:
                    # Restore Wireless Settings
                    logger.info("Restoring Wireless Network Settings...")
                    operations.append(restoreMrWirelessSettings(net=net, dashboard=dashboard, path=path))
    return operations

def restoreMxSettings(net, dashboard, path):
    """
    Restore MX Settings
    :param net: target network
    :param dashboard: Meraki API client
    :param path: Backup location
    :return:
    """
    operation = {"network": net, "operation_type": "appliance", "operation": "restoreMxSettings",
                 "restorePayload": "", "status": ""}
    try:
        with open(f'{path}/network/{net["name"]}/appliance/settings/settings.json') as fp:
            data = json.load(fp)
            fp.close()
        operation['restorePayload']=data
        # Apply VLAN settings
        dashboard.appliance.updateNetworkApplianceSettings(networkId=net['id'], **data)
        operation['status']="Complete"
    except meraki.APIError as e:
        logger.error(e)
        data =""
        operation['status']=e
    return operation, data

def restoreMxVlanSettings(net, dashboard, path):
    """
    Restore MX VLAN Settings
    :param net: target network
    :param dashboard: Meraki API client
    :param path: Backup location
    :return:
    """
    operation = {"network": net, "operation_type": "appliance", "operation": "restoreMxVlanSettings",
                 "restorePayload": "", "status": ""}
    try:
        with open(f'{path}/network/{net["name"]}/appliance/vlans/vlan_settings.json') as fp:
            data = json.load(fp)
            fp.close()
        operation['restorePayload']=data
        # Apply VLAN settings
        dashboard.appliance.updateNetworkApplianceVlansSettings(networkId=net['id'], **data)
        operation['status']="Complete"
    except meraki.APIError as e:
        logger.error(e)
        data =""
        operation['status']=e
    return operation, data

def checkFirmware(net, dashboard, path):
    """
    Function to check if the backup firmware versions match the current firmware versions. Discrepancies in firmware versions
    can cause incompatibilities and make the script fail. Take this into account when restoring and try to back up often.
    :param net: target network
    :param dashboard: Meraki API client
    :param path: Backup location
    :return:
    """
    with open(f'{path}/network/{net["name"]}/firmware/firmware.json') as fp:
        backup_firmware = json.load(fp)
        fp.close()
    current_firmware = dashboard.networks.getNetworkFirmwareUpgrades(net['id'])
    prods_in_backup = {product:backup_firmware['products'][product]['currentVersion']['firmware'] for product in backup_firmware['products'].keys()}
    logger.debug(prods_in_backup)
    prods_in_current = {product:current_firmware['products'][product]['currentVersion']['firmware'] for product in current_firmware['products'].keys()}
    logger.debug(prods_in_current)
    for key_b in prods_in_backup.keys():
        for key_c in prods_in_current.keys():
            if key_b == key_c:
                if prods_in_backup[key_b]!=prods_in_current[key_c]:
                    print(f"Firmware version for {key_b} in backup is {prods_in_backup[key_b]} and {prods_in_current[key_c]} in your existing network. Firmware differences can lead to feature incompatibilities and the restore operation failing.")
                    proceed = input("Do you wish to proceed? (Y/N): ")
                    if proceed=='Y':
                        continue
                    else:
                        print("Aborted by user.")
                        sys.exit()

def restoreNetworkGroupPolicies(net, dashboard, path):
    """
    Function to restore a network's group policies.
    :param net: target network
    :param dashboard: Meraki API client
    :param path: Backup location
    :return:
    """
    operation = {"network": net, "operation_type": "network", "operation": "restoreNetworkGroupPolicies", "restorePayload": "","status": ""}
    try:
        with open(f'{path}/network/{net["name"]}/group_policies/group_policies.json') as fp:
            group_policies = json.load(fp)
            fp.close()
        operation['restorePayload']=group_policies
        existing_gps = dashboard.networks.getNetworkGroupPolicies(networkId=net['id'])
        for policy in group_policies:
            # CHECK IF POLICIES EXIST ALREADY BEFORE CREATING
            # IF THEY EXIST, JUST UPDATE
            update_flag = False
            for gp in existing_gps:
                if policy['name'] == gp['name']:
                    update_flag = True
                    break
            if update_flag == True:
                group_policy_id = policy['groupPolicyId']
                upd = {k: policy[k] for k in policy.keys() - {'groupPolicyId'}}
                dashboard.networks.updateNetworkGroupPolicy(networkId=net['id'], groupPolicyId=group_policy_id, **upd)
            else:
                name = policy['name']
                upd = {k: policy[k] for k in policy.keys() - {'name', 'groupPolicyId'}}
                dashboard.networks.createNetworkGroupPolicy(networkId=net['id'], name=name, **upd)
        operation['status'] = "Complete"
    except meraki.APIError as e:
        logger.error(e)
        operation['status'] = e
    return operation

def restoreSwitchPortSchedules(net, dashboard, path):
    """
    Function to restore a network's switch port group policies.
    :param net: target network
    :param dashboard: Meraki API client
    :param path: Backup location
    :return:
    """
    operation = {"network": net, "operation_type": "switch", "operation": "restoreSwitchPortSchedules", "restorePayload": "","status": ""}
    try:
        with open(f'{path}/network/{net["name"]}/switch/switch_settings/port_schedules.json') as fp:
            data = json.load(fp)
            fp.close()
        operation['restorePayload']=data
        existing_port_schedules = dashboard.switch.getNetworkSwitchPortSchedules(networkId=net['id'])
        # CHECK IF PORT SCHEDULE EXISTS
        # IF IT DOES, JUST UPDATE
        for schedule in data:
            update_flag = False
            for sched in existing_port_schedules:
                if schedule['name'] == sched['name']:
                    update_flag = True
                    port_schedule_id = sched['id']
                    break
            if update_flag == True:
                upd = {k: schedule[k] for k in schedule.keys() - {'id', 'networkId'}}
                dashboard.switch.updateNetworkSwitchPortSchedule(networkId=net['id'], portScheduleId=port_schedule_id, **upd)
            else:
                name = schedule['name']
                upd = {k: schedule[k] for k in schedule.keys() - {'id', 'networkId', 'name'}}
                dashboard.switch.createNetworkSwitchPortSchedule(networkId=net['id'], name=name, **upd)
        operation['status'] = "Complete"
    except meraki.APIError as e:
        logger.error(e)
        operation['status'] = e
    return operation

def restoreSwitchQos(net, dashboard, path):
    """
    Function to restore a network's switch qos policies.
    :param net: target network
    :param dashboard: Meraki API client
    :param path: Backup location
    :return:
    """
    operation = {"network": net, "operation_type": "switch", "operation": "restoreSwitchQos", "restorePayload": "","status": ""}
    try:
        with open(f'{path}/network/{net["name"]}/switch/switch_settings/qos_rules.json') as fp:
            data = json.load(fp)
            fp.close()
        operation['restorePayload']=data
        existing_qos_rules = dashboard.switch.getNetworkSwitchQosRules(networkId=net['id'])
        # CHECK IF QOS RULE EXISTS
        # IF IT DOES, DELETE THEN CREATE
        for rule in existing_qos_rules:
            dashboard.switch.deleteNetworkSwitchQosRule(networkId=net['id'], qosRuleId=rule['id'])
        for rule in data:
            vlan = rule['vlan']
            upd = {k: rule[k] for k in rule.keys() - {'id', 'vlan'}}
            if upd['srcPort']==None:
                del upd['srcPort']
            if upd['dstPort']==None:
                del upd['dstPort']
            dashboard.switch.createNetworkSwitchQosRule(networkId=net['id'], vlan=vlan, **upd)
        operation['status'] = "Complete"
    except meraki.APIError as e:
        logger.error(e)
        operation['status'] = e
    return operation

def restoreSwitchOspf(net, dashboard, path):
    """
    Function to restore a network's switch OSPF settings.
    :param net: target network
    :param dashboard: Meraki API client
    :param path: Backup location
    :return:
    """
    operation = {"network": net, "operation_type": "switch", "operation": "restoreSwitchOspf", "restorePayload": "","status": ""}
    try:
        with open(f'{path}/network/{net["name"]}/switch/switch_routing/ospf.json') as fp:
            data = json.load(fp)
            fp.close()
        operation['restorePayload']=data
        logger.debug(data)
        if data['v3']['enabled']==False:
            del data['v3']
        dashboard.switch.updateNetworkSwitchRoutingOspf(networkId=net['id'], **data)
        operation['status'] = "Complete"
    except meraki.APIError as e:
        logger.error(e)
        operation['status'] = e
    return operation

def restoreSwitchAccessPolicies(net, dashboard, path):
    """
    Function to restore a network's switch access policies.
    :param net: target network
    :param dashboard: Meraki API client
    :param path: Backup location
    :return:
    """
    operation = {"network": net, "operation_type": "switch", "operation": "restoreSwitchAccessPolicies", "restorePayload": "","status": ""}
    try:
        with open(f'{path}/network/{net["name"]}/switch/switch_settings/access_policies.json') as fp:
            data = json.load(fp)
            fp.close()
        operation['restorePayload']=data
        existing_access_policies = dashboard.switch.getNetworkSwitchAccessPolicies(networkId=net['id'])
        # CHECK IF ACCESS POLICY EXISTS
        # IF IT DOES, JUST UPDATE
        for policy in data:
            update_flag = False
            policy_keys = policy.keys()
            for ap in existing_access_policies:
                if policy['name'] == ap['name']:
                    update_flag = True
                    break
            if update_flag == True:
                access_policy_number = policy['accessPolicyNumber']
                name = policy['name']
                radius_auth_servers = []
                if 'radiusServers' in policy_keys:
                    radius_auth_servers = policy['radiusServers']
                    for auth_server in radius_auth_servers:
                        auth_server['secret'] = input(f"Please input your desired RADIUS authentication secret for Access Policy {name} and server {auth_server['host']}: ")
                if 'radiusAccountingServers' in policy_keys:
                    radius_acct_servers = policy['radiusAccountingServers']
                    for acct_server in radius_acct_servers:
                        acct_server['secret'] = input(f"Please input your desired RADIUS accounting secret for Access Policy {name} and server {acct_server['host']}: ")
                radius_testing = policy['radiusTestingEnabled']
                if radius_testing==None:
                    radius_testing=False
                radius_coa_support = policy['radiusCoaSupportEnabled']
                if radius_coa_support==None:
                    radius_coa_support=False
                radius_acct_enabled = policy['radiusAccountingEnabled']
                if radius_acct_enabled==None:
                    radius_acct_enabled=False
                host_mode = policy['hostMode']
                url_redirect_walled_garden_enabled = policy['urlRedirectWalledGardenEnabled']
                if url_redirect_walled_garden_enabled==None:
                    url_redirect_walled_garden_enabled=False
                upd = {k: policy[k] for k in policy.keys() - {
                    'accessPolicyNumber',
                    'name',
                    'radiusServers',
                    'radiusTestingEnabled',
                    'radiusCoaSupportEnabled',
                    'radiusAccountingEnabled',
                    'hostMode',
                    'urlRedirectWalledGardenEnabled'
                }}
                dashboard.switch.updateNetworkSwitchAccessPolicy(
                    networkId=net['id'],
                    accessPolicyNumber=access_policy_number,
                    name=name,
                    radiusServers=radius_auth_servers,
                    radiusTestingEnabled=radius_testing,
                    radiusCoaSupportEnabled=radius_coa_support,
                    radiusAccountingEnabled=radius_acct_enabled,
                    hostMode=host_mode,
                    urlRedirectWalledGardenEnabled=url_redirect_walled_garden_enabled,
                    **upd
                )
            else:
                access_policy_number=policy['accessPolicyNumber']
                name = policy['name']
                radius_auth_servers = []
                if 'radiusServers' in policy_keys:
                    radius_auth_servers = policy['radiusServers']
                    for auth_server in radius_auth_servers:
                        auth_server['secret'] = input(f"Please input your desired RADIUS authentication secret for Access Policy {name} and server {auth_server['host']}: ")
                if 'radiusAccountingServers' in policy_keys:
                    radius_acct_servers = policy['radiusAccountingServers']
                    for acct_server in radius_acct_servers:
                        acct_server['secret'] = input(f"Please input your desired RADIUS accounting secret for Access Policy {name} and server {acct_server['host']}: ")
                radius_testing = policy['radiusTestingEnabled']
                if radius_testing == None:
                    radius_testing = False
                radius_coa_support = policy['radiusCoaSupportEnabled']
                if radius_coa_support == None:
                    radius_coa_support = False
                radius_acct_enabled = policy['radiusAccountingEnabled']
                if radius_acct_enabled == None:
                    radius_acct_enabled = False
                host_mode = policy['hostMode']
                url_redirect_walled_garden_enabled = policy['urlRedirectWalledGardenEnabled']
                if url_redirect_walled_garden_enabled==None:
                    url_redirect_walled_garden_enabled=False
                upd = {k: policy[k] for k in policy.keys() - {
                    'accessPolicyNumber',
                    'name',
                    'radiusServers',
                    'radiusTestingEnabled',
                    'radiusCoaSupportEnabled',
                    'radiusAccountingEnabled',
                    'hostMode',
                    'urlRedirectWalledGardenEnabled'
                }}
                dashboard.switch.createNetworkSwitchAccessPolicy(
                    networkId=net['id'],
                    name=name,
                    radiusServers=radius_auth_servers,
                    radiusTestingEnabled=radius_testing,
                    radiusCoaSupportEnabled=radius_coa_support,
                    radiusAccountingEnabled=radius_acct_enabled,
                    hostMode=host_mode,
                    urlRedirectWalledGardenEnabled=url_redirect_walled_garden_enabled,
                    **upd
                )
        operation['status'] = "Complete"
    except meraki.APIError as e:
        logger.error(e)
        operation['status'] = e
    return operation

def restoreMxVlansBatch(org, net, dashboard, path):
    """
    Function to restore a network's MX VLANs.
    :param net: target network
    :param dashboard: Meraki API client
    :param path: Backup location
    :return:
    """
    operation = {"network": net, "operation_type": "appliance", "operation": "restoreMxVlansBatch", "restorePayload": "","status": ""}
    try:
        # Open VLAN settings
        with open(f'{path}/network/{net["name"]}/appliance/vlans/vlan_config.json') as fp:
            data = json.load(fp)
            fp.close()
        existing_vlans = dashboard.appliance.getNetworkApplianceVlans(networkId=net['id'])
        actions = []
        for i in range(len(data)):
            # Since VLAN 1 always exists in a new config, this must be updated
            # Trying to create it gives an error
            if data[i]['id'] == 1:
                action = {
                    "resource": f'/networks/{net["id"]}/appliance/vlans/{data[i]["id"]}',
                    "operation": 'update',
                    "body": {k: data[i][k] for k in data[i].keys() - {'id', 'networkId'}}
                }
                actions.append(action)
            # For all other VLANs create them
            # CHECK IF VLANS ALREADY EXIST
            # IF THEY DO, JUST UPDATE
            else:
                update_flag = False
                for j in range(len(existing_vlans)):
                    if data[i]['id']==existing_vlans[j]['id']:
                        update_flag = True
                        break
                if update_flag==True:
                    action = {
                        "resource": f'/networks/{net["id"]}/appliance/vlans/{data[i]["id"]}',
                        "operation": 'update',
                        "body": {k: data[i][k] for k in data[i].keys() - {'id', 'networkId'}}
                    }
                    actions.append(action)
                else:
                    action = {
                        "resource": f'/networks/{net["id"]}/appliance/vlans',
                        "operation": 'create',
                        "body": {k: data[i][k] for k in data[i].keys() - {'networkId'}}
                    }
                    actions.append(action)
        with open(f'{path}/network/{net["name"]}/appliance/vlans/vlan_ports.json') as fp:
            data = json.load(fp)
            fp.close()
        devices = dashboard.networks.getNetworkDevices(networkId=net['id'])
        for device in devices:
            if device['model'] in ['MX64', 'MX64W', 'MX67', 'MX67W', 'MX67C', 'MX100']:
                starting_port = 2
                logger.debug(starting_port)
            elif 'MX' in device['model']:
                starting_port = 3
        model_ports = dashboard.appliance.getNetworkAppliancePorts(networkId=net['id'])
        # If trying to apply a backup to an MX with fewer ports stop at the last port
        if len(data) < len(model_ports):
            logger.info("MX has more ports than backup")
            for i in range(len(data)):
                action = {
                    "resource": f'/networks/{net["id"]}/appliance/ports/{i+starting_port}',
                    "operation": 'update',
                    "body": {k: data[i][k] for k in data[i].keys() - {'number'}}
                }
                actions.append(action)
        else:
            for i in range(len(model_ports)):
                action = {
                    "resource": f'/networks/{net["id"]}/appliance/ports/{i+starting_port}',
                    "operation": 'update',
                    "body": {k: data[i][k] for k in data[i].keys() - {'number'}}
                }
                actions.append(action)
        operation['restorePayload']=actions
        # Synchronous batches may only have 20 actions, so need to split actions list in groups of 20
        # Since we're grouping VLAN creation and port assignment, and port assignment depends on VLANs existing, port
        # assignment must happen after VLAN creation, hence synchronously
        if len(actions)<=20:
            dashboard.organizations.createOrganizationActionBatch(
                organizationId=org,
                actions=actions,
                confirmed=True,
                synchronous=True
            )
        else:
            for i in range(0, len(actions), 20):
                subactions = actions[i:i+20]
                batch = dashboard.organizations.createOrganizationActionBatch(
                    organizationId=org,
                    actions=subactions,
                    confirmed=True,
                    synchronous=True
                )
                time.sleep(1)
                status = dashboard.organizations.getOrganizationActionBatch(organizationId=org,
                                                                            actionBatchId=batch['id'])['status']['completed']
                while status != True:
                    time.sleep(1)
                    status = dashboard.organizations.getOrganizationActionBatch(organizationId=org,
                                                                                actionBatchId=batch['id'])['status']['completed']
        operation['status'] = "Complete"
    except meraki.APIError as e:
        logger.error(e)
        operation['status'] = e
    return operation

def restoreMxSecurity(net, dashboard, path):
    """
    Function to restore a network's MX AMP and IPS settings
    :param net: target network
    :param dashboard: Meraki API client
    :param path: Backup location
    :return:
    """
    operation = {"network": net, "operation_type": "appliance", "operation": "restoreMxSecurity", "restorePayload": "","status": ""}
    try:
        with open(f'{path}/network/{net["name"]}/appliance/security/amp.json') as fp:
            amp_data = json.load(fp)
            fp.close()
        with open(f'{path}/network/{net["name"]}/appliance/security/ips.json') as fp:
            ips_data = json.load(fp)
            fp.close()
        operation['restorePayload']=[amp_data, ips_data]
        dashboard.appliance.updateNetworkApplianceSecurityIntrusion(networkId=net['id'], **ips_data)
        dashboard.appliance.updateNetworkApplianceSecurityMalware(networkId=net['id'], **amp_data)
        operation['status'] = "Complete"
    except meraki.APIError as e:
        logger.error(e)
        operation['status'] = e
    return operation

def restoreMxFirewall(net, dashboard, path):
    """
    Function to restore a network's MX L3 and L7 firewall settings
    :param net: target network
    :param dashboard: Meraki API client
    :param path: Backup location
    :return:
    """
    operation = {"network": net, "operation_type": "appliance", "operation": "restoreMxFirewall", "restorePayload": "","status": ""}
    try:
        with open(f'{path}/network/{net["name"]}/appliance/security/l3_fw.json') as fp:
            l3_data = json.load(fp)
            fp.close()
        with open(f'{path}/network/{net["name"]}/appliance/security/l7_fw.json') as fp:
            l7_data = json.load(fp)
            fp.close()
        operation['restorePayload']=[l3_data, l7_data]
        dashboard.appliance.updateNetworkApplianceFirewallL3FirewallRules(networkId=net['id'], **l3_data)
        dashboard.appliance.updateNetworkApplianceFirewallL7FirewallRules(networkId=net['id'], **l7_data)
        operation['status'] = "Complete"
    except meraki.APIError as e:
        logger.error(e)
        operation['status'] = e
    return operation

def restoreMxContentFiltering(net, dashboard, path):
    """
    Function to restore a network's MX Content Filtering settings
    :param net: target network
    :param dashboard: Meraki API client
    :param path: Backup location
    :return:
    """
    operation = {"network": net, "operation_type": "appliance", "operation": "restoreMxContentFiltering", "restorePayload": "","status": ""}
    try:
        # Read each config file and apply the config
        with open(f'{path}/network/{net["name"]}/appliance/security/content_filtering.json') as fp:
            data = json.load(fp)
            fp.close()
        operation['restorePayload']=data
        dashboard.appliance.updateNetworkApplianceContentFiltering(networkId=net['id'], **data)
        operation['status'] = "Complete"
    except meraki.APIError as e:
        logger.error(e)
        operation['status'] = e
    return operation

def restoreMxShaping(net, dashboard, path):
    """
    Function to restore a network's MX Shaping settings
    :param net: target network
    :param dashboard: Meraki API client
    :param path: Backup location
    :return:
    """
    operation = {"network": net, "operation_type": "appliance", "operation": "restoreMxShaping", "restorePayload": "","status": ""}
    try:
        with open(f'{path}/network/{net["name"]}/appliance/shaping/global_shaping.json') as fp:
            global_data = json.load(fp)
            fp.close()
        with open(f'{path}/network/{net["name"]}/appliance/shaping/shaping_rules.json') as fp:
            rules_data = json.load(fp)
            fp.close()
        operation['restorePayload']=[global_data, rules_data]
        dashboard.appliance.updateNetworkApplianceTrafficShaping(networkId=net['id'], **global_data)
        dashboard.appliance.updateNetworkApplianceTrafficShapingRules(networkId=net['id'], **rules_data)
        operation['status'] = "Complete"
    except meraki.APIError as e:
        logger.error(e)
        operation['status'] = e
    return operation

def restoreMxVpnConfig(net, dashboard, path):
    """
    Function to restore a network's MX VPN settings
    :param net: target network
    :param dashboard: Meraki API client
    :param path: Backup location
    :return:
    """
    operation = {"network": net, "operation_type": "appliance", "operation": "restoreMxVpnConfig", "restorePayload": "","status": ""}
    try:
        with open(f'{path}/network/{net["name"]}/appliance/vpn_config/vpn_config.json') as fp:
            data = json.load(fp)
            fp.close()
        operation['restorePayload']=data
        mode = data['mode']
        upd = {k: data[k] for k in data.keys() - {'mode'}}
        dashboard.appliance.updateNetworkApplianceVpnSiteToSiteVpn(networkId=net['id'], mode=mode, **upd)
        operation['status'] = "Complete"
    except meraki.APIError as e:
        logger.error(e)
        operation['status'] = e
    return operation

def restoreSwitchPortConfigsBatch(org, net, dashboard, path, devices_in_network):
    """
    Function to restore a network's Switch Port settings
    :param net: target network
    :param dashboard: Meraki API client
    :param path: Backup location
    :return:
    """
    operation = {"network": net, "operation_type": "switch", "operation": "restoreSwitchPortConfigsBatch", "restorePayload": "","status": ""}
    try:
        directory = f'{path}/network/{net["name"]}/switch/switch_settings'
        port_schedules = dashboard.switch.getNetworkSwitchPortSchedules(networkId=net['id'])
        access_policies = dashboard.switch.getNetworkSwitchAccessPolicies(networkId=net['id'])
        # For each switch subfolder, read and update port configs
        actions = []
        for subdirs, dirs, files in os.walk(directory):
            for dir in dirs:
                if dir not in [device['serial'] for device in devices_in_network]:
                    logger.info(f"Your backup contains switch port configs for {dir}, but this device is not currently in the network.")
                    logger.info(f"Switch port settings for {dir} will not be restored.")
                else:
                    with open(f'{path}/network/{net["name"]}/switch/switch_settings/{dir}/switch_ports.json') as fp:
                        data = json.load(fp)
                        fp.close()
                    for port in data:
                        upd = port
                        for schedule in port_schedules:
                            if schedule['name']==upd['portScheduleId']:
                                upd['portScheduleId']=schedule['id']
                        if port['type'] == 'access':
                            if port['accessPolicyType'] != 'Open':
                                for policy in access_policies:
                                    if policy['name'] == port['accessPolicyNumber']:
                                        upd['accessPolicyNumber']=int(policy['accessPolicyNumber'])
                        action = {
                            "resource": f'/devices/{dir}/switch/ports/{upd["portId"]}',
                            "operation": 'update',
                            "body": {k: upd[k] for k in upd.keys() - {'portId'}}
                        }
                        actions.append(action)
        operation['restorePayload']=actions
        for i in range(0, len(actions), 100):
            subactions = actions[i:i + 100]
            dashboard.organizations.createOrganizationActionBatch(
                organizationId=org,
                actions=subactions,
                confirmed=True,
                synchronous=False
            )
            time.sleep(1)
        operation['status'] = "Complete"
    except meraki.APIError as e:
        logger.error(e)
        operation['status'] = e
    return operation

def restoreNetworkAlerts(net, dashboard, path):
    """
    Function to restore a network's alerts.
    :param net: target network
    :param dashboard: Meraki API client
    :param path: Backup location
    :return:
    """
    operation = {"network": net, "operation_type": "network", "operation": "restoreNetworkAlerts", "restorePayload": "","status": ""}
    try:
        with open(f'{path}/network/{net["name"]}/alert_settings/alerts.json') as fp:
            data = json.load(fp)
            fp.close()
        dashboard.networks.updateNetworkAlertsSettings(networkId=net['id'], defaultDestinations=data['defaultDestinations'], alerts=data['alerts'])
        operation['status'] = "Complete"
    except meraki.APIError as e:
        logger.error(e)
        operation['status'] = e
    return operation

def restoreMrSsidConfigs(net, dashboard, path):
    """
    Function to restore a network's SSIDs
    :param net: target network
    :param dashboard: Meraki API client
    :param path: Backup location
    :return:
    """
    operation = {"network": net, "operation_type": "wireless", "operation": "restoreMrSsidConfigs", "restorePayload": "","status": ""}
    try:
        with open(f'{path}/network/{net["name"]}/wireless/ssid_settings/ssids.json') as fp:
            data = json.load(fp)
            fp.close()
        operation['restorePayload'] = data
        for ssid in data:
            if 'Unconfigured SSID' not in ssid['name']:
                upd = ssid
                ssid_number = ssid['number']
                del upd['number']
                ssid_keys = upd.keys()
                if 'authMode' in ssid_keys:
                    if ssid['authMode']=='psk':
                        ssid['psk']=input(f"Please input your desired PSK for SSID {ssid['name']}: ")
                    if ssid['authMode']=='8021x-radius':
                        if ssid['wpaEncryptionMode']=='WPA3 192-bit Security':
                            ssid['wpaEncryptionMode']='WPA3 only'
                        if 'radiusServers' in ssid_keys:
                            for auth_server in ssid['radiusServers']:
                                auth_server['secret'] = input(f"Please input your desired RADIUS authentication secret for SSID {ssid['name']} and server {auth_server['host']}: ")
                        if 'radiusAccountingServers' in ssid_keys:
                            for acct_server in ssid['radiusAccountingServers']:
                                acct_server['secret'] = input(f"Please input your desired RADIUS accounting secret for SSID {ssid['name']} and server {acct_server['host']}: ")
                    if upd['authMode']!='psk' and upd['authMode']!='open':
                        del upd['encryptionMode']
                        delete_keys=[]
                        for key in upd.keys():
                            if upd[key]==None:
                                delete_keys.append(key)
                        for key in delete_keys:
                            del upd[key]
                dashboard.wireless.updateNetworkWirelessSsid(networkId=net['id'],number=ssid_number,**upd)
        operation['status'] = "Complete"
    except meraki.APIError as e:
        logger.error(e)
        operation['status'] = e
    return operation

def restoreMrRfProfiles(net, dashboard, path, devices_in_network):
    """
    Function to restore a network's RF Profiles
    :param net: target network
    :param dashboard: Meraki API client
    :param path: Backup location
    :return:
    """
    operation = {"network": net, "operation_type": "wireless", "operation": "restoreMrRfProfiles", "restorePayload": "","status": ""}
    try:
        with open(f'{path}/network/{net["name"]}/wireless/radio_settings/rf_profiles.json') as fp:
            data = json.load(fp)
            fp.close()
        operation['restorePayload']=data
        existing_profiles = dashboard.wireless.getNetworkWirelessRfProfiles(networkId=net['id'])
        for rf_profile in data:
            update_flag = False
            for profile in existing_profiles:
                if rf_profile['name']==profile['name']:
                    update_flag = True
                    profile_id = profile['id']
                    profile_name = profile['name']
                    break
            if update_flag == True:
                upd = rf_profile
                band_selection_type = rf_profile['bandSelectionType']
                if upd['fiveGhzSettings']['minPower'] < 8:
                    upd['fiveGhzSettings']['minPower'] = 8
                    logger.warning('Minimum power configurable for 5GHz via API is 8')
                if upd['fiveGhzSettings']['maxPower'] > 30:
                    upd['fiveGhzSettings']['maxPower'] = 30
                    logger.warning('Maximum power configurable for 5GHz is 30')
                if upd['twoFourGhzSettings']['minPower'] < 5:
                    upd['twoFourGhzSettings']['minPower'] = 5
                    logger.warning('Minimum power configurable for 2.4GHz via API is 5')
                if upd['twoFourGhzSettings']['maxPower'] > 30:
                    upd['twoFourGhzSettings']['maxPower'] = 30
                    logger.warning('Maximum power configurable for 2.4GHz is 30')
                del upd['id']
                del upd['networkId']
                del upd['name']
                del upd['bandSelectionType']
                # API endpoint does not support channels 169, 173 and 177
                upd['fiveGhzSettings']['validAutoChannels']=[channel for channel in upd['fiveGhzSettings']['validAutoChannels'] if channel <= 165]
                # CHECK IF RF PROFILE ALREADY EXISTS
                # IF IT DOES, JUST UPDATE
                dashboard.wireless.updateNetworkWirelessRfProfile(networkId=net['id'], rfProfileId=profile_id,
                                                                  bandSelectionType=band_selection_type, **upd)
            else:
                upd = rf_profile
                name = rf_profile['name']
                band_selection_type = rf_profile['bandSelectionType']
                if upd['fiveGhzSettings']['minPower']<8:
                    upd['fiveGhzSettings']['minPower']=8
                    logger.warning('Minimum power configurable for 5GHz via API is 8')
                if upd['fiveGhzSettings']['maxPower']>30:
                    upd['fiveGhzSettings']['maxPower']=30
                    logger.warning('Maximum power configurable for 5GHz is 30')
                if upd['twoFourGhzSettings']['minPower']<5:
                    upd['twoFourGhzSettings']['minPower']=5
                    logger.warning('Minimum power configurable for 2.4GHz via API is 5')
                if upd['twoFourGhzSettings']['maxPower']>30:
                    upd['twoFourGhzSettings']['maxPower']=30
                    logger.warning('Maximum power configurable for 2.4GHz is 30')
                del upd['id']
                del upd['networkId']
                del upd['name']
                del upd['bandSelectionType']
                # CHECK IF RF PROFILE ALREADY EXISTS
                # IF IT DOES, JUST UPDATE
                # API endpoint does not support channels 169, 173 and 177
                upd['fiveGhzSettings']['validAutoChannels']=[channel for channel in upd['fiveGhzSettings']['validAutoChannels'] if channel <= 165]
                dashboard.wireless.createNetworkWirelessRfProfile(networkId=net['id'], name=name, bandSelectionType=band_selection_type, **upd)
        rf_profiles = dashboard.wireless.getNetworkWirelessRfProfiles(networkId=net['id'])
        with open(f'{path}/network/{net["name"]}/wireless/radio_settings/radio_settings.json') as fp:
            data = json.load(fp)
            fp.close()
        for setting in data:
            if setting['serial'] in [device['serial'] for device in devices_in_network]:
                if 'profileName' in setting.keys():
                    upd = setting
                    serial = setting['serial']
                    for profile in rf_profiles:
                        if profile['name']==upd['profileName']:
                            upd['rfProfileId'] = profile['id']
                    del upd['serial']
                    dashboard.wireless.updateDeviceWirelessRadioSettings(serial=serial, **upd)
                else:
                    logger.info(f"Your backup contains radio settings for device {setting['serial']} but this device was not found in your network.")
                    logger.info("Settings for this device will not be restored.")
        operation['status'] = "Complete"
    except meraki.APIError as e:
        logger.error(e)
        operation['status'] = e
    return operation

def restoreMrSsidFW(net, dashboard, path):
    """
    Function to restore a network's SSID FW
    :param net: target network
    :param dashboard: Meraki API client
    :param path: Backup location
    :return:
    """
    operation = {"network": net, "operation_type": "wireless", "operation": "restoreMrSsidFW", "restorePayload": "","status": ""}
    try:
        with open(f'{path}/network/{net["name"]}/wireless/ssid_settings/l7_rules.json') as fp:
            data = json.load(fp)
            fp.close()
        operation['restorePayload']=[data]
        for ssid in data:
            upd = ssid
            ssid_number = ssid['number']
            del upd['number']
            dashboard.wireless.updateNetworkWirelessSsidFirewallL7FirewallRules(networkId=net['id'], number=ssid_number, **upd)
        with open(f'{path}/network/{net["name"]}/wireless/ssid_settings/l3_rules.json') as fp:
            data = json.load(fp)
            fp.close()
        operation['restorePayload'].append(data)
        for ssid in data:
            ssid_rules = [rule for rule in ssid['rules'] if (rule['destCidr']!='Local LAN' and rule['comment']!='Default rule')]
            upd = ssid
            upd['rules']=ssid_rules
            ssid_number = ssid['number']
            del upd['number']
            dashboard.wireless.updateNetworkWirelessSsidFirewallL3FirewallRules(networkId=net['id'], number=ssid_number, **upd)
        operation['status'] = "Complete"
    except meraki.APIError as e:
        logger.error(e)
        operation['status'] = e
    return operation

def restoreMrSsidShaping(net, dashboard, path):
    """
    Function to restore a network's SSID shaping
    :param net: target network
    :param dashboard: Meraki API client
    :param path: Backup location
    :return:
    """
    operation = {"network": net, "operation_type": "wireless", "operation": "restoreMrSsidFW", "restorePayload": "","status": ""}
    try:
        with open(f'{path}/network/{net["name"]}/wireless/ssid_settings/shaping_rules.json') as fp:
            data = json.load(fp)
            fp.close()
        operation['restorePayload']=data
        for ssid in data:
            upd = ssid
            ssid_number = ssid['number']
            del upd['number']
            dashboard.wireless.updateNetworkWirelessSsidTrafficShapingRules(networkId=net['id'], number=ssid_number, **upd)
        operation['status'] = "Complete"
    except meraki.APIError as e:
        logger.error(e)
        operation['status'] = e
    return operation

def restoreSwitchSvis(net, dashboard, path, devices_in_network):
    """
    Function to restore a network's Switch SVIs
    :param net: target network
    :param dashboard: Meraki API client
    :param path: Backup location
    :return:
    """
    operation = {"network": net, "operation_type": "switch", "operation": "restoreSwitchSvis", "restorePayload": "","status": ""}
    try:
        directory = f'{path}/network/{net["name"]}/switch/switch_routing'
        # For each switch subfolder, read and update svi configs
        for subdirs, dirs, files in os.walk(directory):
            for dir in dirs:
                if dir not in [device['serial'] for device in devices_in_network]:
                    logger.info(f"Your backup contains SVI configs for {dir}, but this device is not currently in the network.")
                    logger.info(f"SVI settings for {dir} will not be restored.")
                else:
                    if ('svi_dhcp.json' and 'svis.json') in next(os.walk(f"{path}/network/{net['name']}/switch/switch_routing/{dir}"))[2]:
                        #Load SVI configs into svis variable
                        with open(f'{path}/network/{net["name"]}/switch/switch_routing/{dir}/svis.json') as fp:
                            svis = json.load(fp)
                            fp.close()
                        existing_svis = dashboard.switch.getDeviceSwitchRoutingInterfaces(serial=dir)
                        #Load SVI DHCP configs into svi_dhcps variable
                        with open(f'{path}/network/{net["name"]}/switch/switch_routing/{dir}/svi_dhcp.json') as fp:
                            svi_dhcps = json.load(fp)
                            fp.close()
                        #Iterate through SVIs in svi list
                        for svi in svis:
                            update_flag = False
                            for existing_svi in existing_svis:
                                if svi['name'] == existing_svi['name']:
                                    update_flag = True
                                    interface_id = existing_svi['interfaceId']
                                    break
                            if update_flag == True:
                                svi_name = svi['name']
                                interface_ip = svi['interfaceIp']
                                vlan_id = svi['vlanId']
                                upd = {k: svi[k] for k in svi.keys() - {'name', 'interfaceIp', 'vlanId', 'interfaceId', 'defaultGateway'}}
                                # create SVI
                                # CHECK IF SVI EXISTS
                                # IF IT DOES, JUST UPDATE
                                new_id = dashboard.switch.updateDeviceSwitchRoutingInterface(serial=dir, interfaceId=interface_id,
                                                                                             name=svi_name,
                                                                                             interfaceIp=interface_ip,
                                                                                             vlanId=vlan_id, **upd)
                                # Update DHCP settings of SVI
                                for i in range(len(svi_dhcps)):
                                    if svi_dhcps[i]['interfaceId'] == interface_id:
                                        upd_dhcp = svi_dhcps[i]
                                        del upd_dhcp['interfaceId']
                                        dashboard.switch.updateDeviceSwitchRoutingInterfaceDhcp(serial=dir,
                                                                                                interfaceId=new_id['interfaceId'],
                                                                                                **upd_dhcp)
                                        pop = i
                                # Remove used SVI DHCP entry to avoid in next iteration
                                svi_dhcps.pop(pop)
                            else:
                                svi_name = svi['name']
                                interface_ip = svi['interfaceIp']
                                vlan_id = svi['vlanId']
                                interface_id = svi['interfaceId']
                                upd = {k: svi[k] for k in svi.keys() - {'name','interfaceIp','vlanId','interfaceId'}}
                                #create SVI
                                # CHECK IF SVI EXISTS
                                # IF IT DOES, JUST UPDATE
                                print(upd)
                                new_id = dashboard.switch.createDeviceSwitchRoutingInterface(serial=dir, name=svi_name, interfaceIp=interface_ip, vlanId=vlan_id, **upd)
                                #Update DHCP settings of SVI
                                for i in range(len(svi_dhcps)):
                                    if svi_dhcps[i]['interfaceId']==interface_id:
                                        upd_dhcp = svi_dhcps[i]
                                        del upd_dhcp['interfaceId']
                                        dashboard.switch.updateDeviceSwitchRoutingInterfaceDhcp(serial=dir, interfaceId=new_id['interfaceId'],
                                                                                                **upd_dhcp)
                                        pop=i
                                #Remove used SVI DHCP entry to avoid in next iteration
                                svi_dhcps.pop(pop)
        operation['status'] = "Complete"
    except meraki.APIError as e:
        logger.error(e)
        operation['status'] = e
    return operation

def restoreMxStaticRouting(net, dashboard, path):
    """
    Function to restore a network's MX Static Routes
    :param net: target network
    :param dashboard: Meraki API client
    :param path: Backup location
    :return:
    """
    operation = {"network": net, "operation_type": "appliance", "operation": "restoreMxStaticRouting", "restorePayload": "","status": ""}
    try:
        with open(f'{path}/network/{net["name"]}/appliance/appliance_routing/static_routes.json') as fp:
            data = json.load(fp)
            fp.close()
        operation['restorePayload']=data
        existing_routes = dashboard.appliance.getNetworkApplianceStaticRoutes(networkId=net['id'])
        # CHECK IF ROUTE EXISTS
        # IF IT DOES, JUST UPDATE
        for route in data:
            update_flag = False
            for existing_route in existing_routes:
                if route['name']==existing_route['name']:
                    update_flag = True
                    route_id = existing_route['id']
                    break
            if update_flag == True:
                dashboard.appliance.updateNetworkApplianceStaticRoute(networkId=net['id'], staticRouteId=route_id, name=route['name'], subnet=route['subnet'], gatewayIp=route['gatewayIp'])
            else:
                dashboard.appliance.createNetworkApplianceStaticRoute(networkId=net['id'], name=route['name'], subnet=route['subnet'], gatewayIp=route['gatewayIp'])
        operation['status'] = "Complete"
    except meraki.APIError as e:
        logger.error(e)
        operation['status'] = e
    return operation


def restoreSwitchDhcpSecurity(net, dashboard, path):
    """
    Function to restore a network's Switch DHCP Security
    :param net: target network
    :param dashboard: Meraki API client
    :param path: Backup location
    :return:
    """
    operation = {"network": net, "operation_type": "switch", "operation": "restoreMxVpnConfig", "restorePayload": "","status": ""}
    try:
        with open(f'{path}/network/{net["name"]}/switch/switch_settings/dhcp_policies.json') as fp:
            data = json.load(fp)
            fp.close()
        operation['restorePayload']=data
        dashboard.switch.updateNetworkSwitchDhcpServerPolicy(networkId=net['id'], **data)
        operation['status'] = "Complete"
    except meraki.APIError as e:
        logger.error(e)
        operation['status'] = e
    return operation

def restoreMxSdWanSettings(net, dashboard, path):
    """
    Function to restore a network's MX VPN settings
    :param net: target network
    :param dashboard: Meraki API client
    :param path: Backup location
    :return:
    """
    operation = {"network": net, "operation_type": "appliance", "operation": "restoreMxSdWanSettings", "restorePayload": "","status": ""}
    try:
        with open(f'{path}/network/{net["name"]}/appliance/sdwan_settings/perf_classes.json') as fp:
            perf_classes = json.load(fp)
            fp.close()
        existing_perf_classes = dashboard.appliance.getNetworkApplianceTrafficShapingCustomPerformanceClasses(networkId=net['id'])
        with open(f'{path}/network/{net["name"]}/appliance/sdwan_settings/uplink_bandwidth.json') as fp:
            uplink_bw = json.load(fp)
            fp.close()
        with open(f'{path}/network/{net["name"]}/appliance/sdwan_settings/uplink_selection.json') as fp:
            uplink_selection = json.load(fp)
            fp.close()
        operation['restorePayload']=[perf_classes, uplink_bw, uplink_selection]
        dashboard.appliance.updateNetworkApplianceTrafficShapingUplinkBandwidth(networkId=net['id'], **uplink_bw)
        for perf in perf_classes:
            update_flag = False
            for perf_class in existing_perf_classes:
                if perf['name']==perf_class['name']:
                    update_flag = True
                    perf_class_id = perf_class['customPerformanceClassId']
                    break
            if update_flag==True:
                upd = perf
                name = perf['name']
                old_id = upd['customPerformanceClassId']
                del upd['name']
                del upd['customPerformanceClassId']
                # CHECK IF PERFORMANCE CLASS EXISTS
                # IF IT DOES, JUST UPDATE
                new_id = dashboard.appliance.updateNetworkApplianceTrafficShapingCustomPerformanceClass(networkId=net['id'],
                                                                                                        customPerformanceClassId=perf_class_id,
                                                                                                        name=name,
                                                                                                        **upd)
                perf['newId'] = perf_class_id
                perf['oldId'] = old_id
            else:
                upd = perf
                name = perf['name']
                old_id = upd['customPerformanceClassId']
                del upd['name']
                del upd['customPerformanceClassId']
                # CHECK IF PERFORMANCE CLASS EXISTS
                # IF IT DOES, JUST UPDATE
                new_id = dashboard.appliance.createNetworkApplianceTrafficShapingCustomPerformanceClass(networkId=net['id'], name=name,
                                                                                               **upd)
                perf['newId']=new_id['customPerformanceClassId']
                perf['oldId']=old_id
        for i in range(len(uplink_selection["vpnTrafficUplinkPreferences"])):
            if uplink_selection["vpnTrafficUplinkPreferences"][i]['preferredUplink']!='bestForVoIP' and uplink_selection["vpnTrafficUplinkPreferences"][i]!='defaultUplink':
                for perf in perf_classes:
                    if perf['oldId']==uplink_selection["vpnTrafficUplinkPreferences"][i]['performanceClass']['customPerformanceClassId']:
                        uplink_selection["vpnTrafficUplinkPreferences"][i]['performanceClass']['customPerformanceClassId']=perf['newId']
        dashboard.appliance.updateNetworkApplianceTrafficShapingUplinkSelection(networkId=net['id'], **uplink_selection)
        operation['status'] = "Complete"
    except meraki.APIError as e:
        logger.error(e)
        operation['status'] = e
    return operation

def restoreNetworkWebhooks(net, dashboard, path):
    """
    Restore Network Webhooks
    :param net: target network
    :param dashboard: Meraki API client
    :param path: Backup location
    :return:
    """
    operation = {"network": net, "operation_type": "network", "operation": "restoreNetworkWebhooks",
                 "restorePayload": "", "status": ""}
    try:
        with open(f'{path}/network/{net["name"]}/webhooks/webhooks_servers.json') as fp:
            webhook_data = json.load(fp)
            fp.close()
        with open(f'{path}/network/{net["name"]}/webhooks/webhooks_payload_templates.json') as fp:
            webhook_template_data = json.load(fp)
            fp.close()
        operation['restorePayload'] = [webhook_data, webhook_template_data]
        existing_webhook_payloads = dashboard.networks.getNetworkWebhooksPayloadTemplates(networkId=net['id'])
        backup_wt_set = set(wt['name'] for wt in webhook_template_data)
        net_wt_set = set(wt['name'] for wt in existing_webhook_payloads)
        to_create = backup_wt_set.difference(net_wt_set)
        to_update = backup_wt_set.difference(to_create)

        # Construct list of Webhook Templates to be created and updated based on the result of the previous set operation
        create_wt = [wt for wt in webhook_template_data if (wt['name'] in to_create and wt['type']!='included')]
        update_wt = [wt for wt in webhook_template_data if (wt['name'] in to_update and wt['type']!='included')]

        for wt in create_wt:
            name = wt['name']
            upd = {k: wt[k] for k in wt.keys() - {'id', 'networkId', 'name'}}
            dashboard.networks.createNetworkWebhooksPayloadTemplate(networkId=net['id'], name=name, **upd)

        for wt in update_wt:
            wt_id = wt['id']
            upd = {k: wt[k] for k in wt.keys() - {'id', 'networkId'}}
            dashboard.networks.updateNetworkWebhooksPayloadTemplate(networkId=net['id'],
                                                                    payloadTemplateId=wt_id, **upd)

        new_webhook_payloads = dashboard.networks.getNetworkWebhooksPayloadTemplates(networkId=net['id'])

        existing_webhook_servers = dashboard.networks.getNetworkWebhooksHttpServers(networkId=net['id'])
        backup_ws_set = set(ws['name'] for ws in webhook_data)
        net_ws_set = set(ws['name'] for ws in existing_webhook_servers)
        to_create = backup_ws_set.difference(net_ws_set)
        to_update = backup_ws_set.difference(to_create)

        # Construct list of Webhook Servers to be created and updated based on the result of the previous set operation
        create_ws = [ws for ws in webhook_data if (ws['name'] in to_create)]
        for ws in create_ws:
            for wt in new_webhook_payloads:
                if ws['payloadTemplate']['name']==wt['name']:
                    ws['payloadTemplate']['payloadTemplateId']=wt['id']
            name = ws['name']
            url = ws['url']
            upd = {k: ws[k] for k in ws.keys() - {'id', 'networkId', 'name', 'url'}}
            dashboard.networks.createNetworkWebhooksHttpServer(networkId=net['id'], name=name, url=url, **upd)
        update_ws = [ws for ws in webhook_data if (ws['name'] in to_update)]
        for ws in update_ws:
            for wt in new_webhook_payloads:
                if ws['payloadTemplate']['name']==wt['name']:
                    ws['payloadTemplate']['payloadTemplateId']=wt['payloadTemplateId']
            ws_id = ws['id']
            upd = {k: ws[k] for k in ws.keys() - {'id', 'networkId'}}
            dashboard.networks.updateNetworkWebhooksHttpServer(networkId=net['id'], httpServerId=ws_id,
                                                               **upd)
        operation['status'] = "Complete"
    except meraki.APIError as e:
        logger.error(e)
        operation['status'] = e
    return operation

def restoreNetworkSyslog(net, dashboard, path):
    """
    Restore Network Syslog
    :param net: target network
    :param dashboard: Meraki API client
    :param path: Backup location
    :return:
    """
    operation = {"network": net, "operation_type": "network", "operation": "restoreNetworkSyslog",
                 "restorePayload": "", "status": ""}
    try:
        with open(f'{path}/network/{net["name"]}/syslog/syslog.json') as fp:
            syslog_data = json.load(fp)
            fp.close()
        dashboard.networks.updateNetworkSyslogServers(networkId=net['id'], servers=syslog_data['servers'])
        operation['status'] = "Complete"
    except meraki.APIError as e:
        logger.error(e)
        operation['status'] = e
    return operation
def restoreNetworkSnmp(net, dashboard, path):
    """
    Restore Network SNMP
    :param net: target network
    :param dashboard: Meraki API client
    :param path: Backup location
    :return:
    """
    operation = {"network": net, "operation_type": "network", "operation": "restoreNetworkSnmp",
                 "restorePayload": "", "status": ""}
    try:
        with open(f'{path}/network/{net["name"]}/snmp/snmp.json') as fp:
            snmp_data = json.load(fp)
            fp.close()
        dashboard.networks.updateNetworkSnmp(networkId=net['id'], **snmp_data)
        operation['status'] = "Complete"
    except meraki.APIError as e:
        logger.error(e)
        operation['status'] = e
    return operation

def restoreNetworkFloorplans(net, dashboard, path):
    """
    Restore Network Floorplans
    :param net: target network
    :param dashboard: Meraki API client
    :param path: Backup location
    :return:
    """
    operation = {"network": net, "operation_type": "network", "operation": "restoreNetworkDevices",
                 "restorePayload": "", "status": ""}
    try:
        with open(f'{path}/network/{net["name"]}/floorplans/floorplans.json') as fp:
            floorplans_in_backup = json.load(fp)
            fp.close()
        current_floorplans = dashboard.networks.getNetworkFloorPlans(networkId=net['id'])

        backup_fp_set = set(fp['name'] for fp in floorplans_in_backup)
        net_fp_set = set(fp['name'] for fp in current_floorplans)
        to_create = backup_fp_set.difference(net_fp_set)
        to_update = backup_fp_set.difference(to_create)

        # Construct list of Policy Objects to be created and updated based on the result of the previous set operation
        create_fp = [fp for fp in floorplans_in_backup if (fp['name'] in to_create)]
        update_fp = [fp for fp in floorplans_in_backup if (fp['name'] in to_update)]

        for fp in create_fp:
            with open(f'{path}/network/{net["name"]}/floorplans/{fp["name"]}.png', 'rb') as fp_file:
                encoded_string = base64.b64encode(fp_file.read()).decode('utf-8')
            name = fp['name']
            upd = {k: fp[k] for k in fp.keys() - {'floorPlanId', 'name', 'devices', 'imageUrl', 'imageMd5', 'imageExtension', 'imageExpiresAt'}}
            dashboard.networks.createNetworkFloorPlan(networkId=net['id'], name=name, imageContents=encoded_string, **upd)

        for fp in update_fp:
            with open(f'{path}/network/{net["name"]}/floorplans/{fp["name"]}.png', 'rb') as fp_file:
                encoded_string = base64.b64encode(fp_file.read()).decode('utf-8')
            fp_id = fp['floorPlanId']
            upd = {k: fp[k] for k in fp.keys() - {'floorPlanId', 'devices', 'imageUrl', 'imageMd5', 'imageExtension', 'imageUrlExpiresAt'}}
            upd['imageContents']=encoded_string
            dashboard.networks.updateNetworkFloorPlan(networkId=net['id'], floorPlanId=fp_id, **upd)

        operation['status'] = "Complete"
    except meraki.APIError as e:
        logger.error(e)
        operation['status'] = e
    return operation

def restoreNetworkDevices(net, org, devices_in_network, dashboard, path):
    """
    Restore Network Device settings
    :param net: target network
    :param dashboard: Meraki API client
    :param path: Backup location
    :return:
    """
    operation = {"network": net, "operation_type": "network", "operation": "restoreNetworkDevices",
                 "restorePayload": "", "status": ""}
    try:
        with open(f'{path}/network/{net["name"]}/devices/network_devices.json') as fp:
            devices_in_backup = json.load(fp)
            fp.close()
        backup_set = set([device['serial'] for device in devices_in_backup])
        current_set = set([device['serial'] for device in devices_in_network])
        devices_not_in_network = backup_set - current_set
        if devices_not_in_network != set():
            print(f"Network {net['name']} is missing the following devices that were part of your last backup:")
            missing_devices = [device for device in devices_in_backup if device['serial'] in devices_not_in_network]
            for device in missing_devices:
                print(device)
            print("Settings assigned to the missing devices will not be restored, and will be omitted in future tasks of the restore job.")
            proceed = input("Do you wish to continue? (Y/N)")
            if proceed != 'Y':
                print("Aborted by user.")
                sys.exit()
        intersection_set = backup_set.intersection(current_set)
        devices_to_update = [device for device in devices_in_backup if device['serial'] in intersection_set]
        actions = []
        for device in devices_to_update:
            action = {
                "resource": f'/devices/{device["serial"]}',
                "operation": 'update',
                "body": {k: device[k] for k in device.keys() - {'serial', 'elevationUncertainty', 'switchProfileId'}}
            }
            actions.append(action)
        operation['restorePayload']=actions
        if len(actions)<=100:
            dashboard.organizations.createOrganizationActionBatch(
                organizationId=org,
                actions=actions,
                confirmed=True,
                synchronous=False
            )
        else:
            for i in range(0, len(actions), 100):
                subactions = actions[i:i+100]
                batch = dashboard.organizations.createOrganizationActionBatch(
                    organizationId=org,
                    actions=subactions,
                    confirmed=True,
                    synchronous=False
                )
                time.sleep(1)
                status = dashboard.organizations.getOrganizationActionBatch(organizationId=org,
                                                                            actionBatchId=batch['id'])['status']['completed']
                while status != True:
                    time.sleep(1)
                    status = dashboard.organizations.getOrganizationActionBatch(organizationId=org,
                                                                                actionBatchId=batch['id'])['status']['completed']
        operation['status'] = "Complete"
    except meraki.APIError as e:
        logger.error(e)
        operation['status'] = e
    return operation, devices_to_update

def restoreSwitchStp(net, dashboard, path):
    """
    Restore STP Settings
    :param net: target network
    :param dashboard: Meraki API client
    :param path: Backup location
    :return:
    """
    operation = {"network": net, "operation_type": "switch", "operation": "restoreSwitchStp",
                 "restorePayload": "", "status": ""}
    try:
        with open(f'{path}/network/{net["name"]}/switch/switch_settings/switch_stp.json') as fp:
            backup_stp = json.load(fp)
            fp.close()
        switches_in_backup = []
        current_switches = []
        current_stp = dashboard.switch.getNetworkSwitchStp(networkId=net['id'])
        for priority in backup_stp['stpBridgePriority']:
            if 'switches' in priority.keys():
                for switch in priority['switches']:
                    switches_in_backup.append(switch)
            if 'stacks' in priority.keys():
                for stack in priority['stacks']:
                    switches_in_backup.append(stack)
        for priority in current_stp['stpBridgePriority']:
            if 'switches' in priority.keys():
                for switch in priority['switches']:
                    current_switches.append(switch)
            if 'stacks' in priority.keys():
                for stack in priority['stacks']:
                    current_switches.append(stack)

        if switches_in_backup != current_switches:
            logger.info("Switches in backup don't match switches in network. Skipping STP restore.")
            operation['status']="Switches in backup don't match switches in network. Skipping STP restore."
        else:
            dashboard.switch.updateNetworkSwitchStp(networkId=net['id'], **backup_stp)
            operation['status'] = "Complete"
    except meraki.APIError as e:
        logger.error(e)
        operation['status'] = e
    return operation

def restoreSwitchAcl(net, dashboard, path):
    """
    Restore Switch ACL
    :param net: target network
    :param dashboard: Meraki API client
    :param path: Backup location
    :return:
    """
    operation = {"network": net, "operation_type": "switch", "operation": "restoreSwitchAcl",
                 "restorePayload": "", "status": ""}
    try:
        with open(f'{path}/network/{net["name"]}/switch/switch_settings/switch_acl.json') as fp:
            data = json.load(fp)
            fp.close()
        rules = [rule for rule in data['rules'] if rule['comment']!='Default rule']
        operation['restorePayload']=data
        dashboard.switch.updateNetworkSwitchAccessControlLists(networkId=net['id'], rules=rules)
        operation['status'] = "Complete"
    except meraki.APIError as e:
        logger.error(e)
        operation['status'] = e
    return operation

def restoreOrganizationMxVpnFirewall(org, dashboard, path):
    """
    Restore Organization VPN Firewall
    :param org: target organization
    :param dashboard: Meraki API client
    :param path: Backup location
    :return:
    """
    operation = {"network": "Organization", "operation_type": "organization", "operation": "restoreOrganizationVpnFirewall",
                 "restorePayload": "", "status": ""}
    try:
        with open(
                f'{path}/organization/vpn_firewall/vpn_firewall.json') as fp:
            data = json.load(fp)
            fp.close()
        operation['restorePayload'] = data
        dashboard.appliance.updateOrganizationApplianceVpnVpnFirewallRules(organizationId=org, **data)
        operation['status'] = "Complete"
    except meraki.APIError as e:
        logger.error(e)
        operation['status'] = e
    return operation

def restoreOrganizationMxIpsecVpn(org, dashboard, path):
    """
    Restore Organization IPsec VPN
    :param org: target organization
    :param dashboard: Meraki API client
    :param path: Backup location
    :return:
    """
    operation = {"network": "Organization", "operation_type": "organization",
                 "operation": "restoreOrganizationIpsecVpn",
                 "restorePayload": "", "status": ""}
    try:
        with open(
                f'{path}/organization/ipsec_vpn/ipsec_vpn.json') as fp:
            data = json.load(fp)
            fp.close()
        operation['restorePayload'] = data
        # Note, only
        dashboard.appliance.updateOrganizationApplianceVpnThirdPartyVPNPeers(organizationId=org, peers=data['peers'])
        operation['status'] = "Complete"
    except meraki.APIError as e:
        logger.error(e)
        operation['status'] = e
    return operation


def restoreSwitchSettings(net, dashboard, path):
    """
    Restore Switch Network Settings
    :param net: target network
    :param dashboard: Meraki API client
    :param path: Backup location
    :return:
    """
    operation = {"network": net, "operation_type": "wireless", "operation": "restoreSwitchSettings",
                 "restorePayload": "", "status": ""}
    try:
        with open(
                f'{path}/network/{net["name"]}/switch/switch_settings/switch_settings.json') as fp:
            data = json.load(fp)
            fp.close()
        operation['restorePayload'] = data
        dashboard.switch.updateNetworkSwitchSettings(networkId=net['id'], **data)
        operation['status'] = "Complete"
    except meraki.APIError as e:
        logger.error(e)
        operation['status'] = e
    return operation

def restoreSwitchMtu(net, dashboard, path):
    """
    Restore Switch MTU
    :param net: target network
    :param dashboard: Meraki API client
    :param path: Backup location
    :return:
    """
    operation = {"network": net, "operation_type": "wireless", "operation": "restoreSwitchMtu",
                 "restorePayload": "", "status": ""}
    try:
        with open(
                f'{path}/network/{net["name"]}/switch/switch_settings/switch_mtu.json') as fp:
            data = json.load(fp)
            fp.close()
        operation['restorePayload'] = data
        dashboard.switch.updateNetworkSwitchMtu(networkId=net['id'], **data)
        operation['status'] = "Complete"
    except meraki.APIError as e:
        logger.error(e)
        operation['status'] = e
    return operation

def restoreMrWirelessSettings(net, dashboard, path):
    """
    Restore MR Network Wireless Settings
    :param net: target network
    :param dashboard: Meraki API client
    :param path: Backup location
    :return:
    """
    operation = {"network": net, "operation_type": "wireless", "operation": "restoreMrWirelessSettings",
                 "restorePayload": "", "status": ""}
    try:
        with open(f'{path}/network/{net["name"]}/wireless/network_wireless_settings/network_wireless_settings.json') as fp:
            data = json.load(fp)
            fp.close()
        operation['restorePayload'] = data
        dashboard.wireless.updateNetworkWirelessSettings(networkId=net['id'], **data)
        operation['status'] = "Complete"
    except meraki.APIError as e:
        logger.error(e)
        operation['status'] = e
    return operation

def restoreMxBgp(net, dashboard, path):
    """
    Restore MX BGP
    :param net: target network
    :param dashboard: Meraki API client
    :param path: Backup location
    :return:
    """
    operation = {"network": net, "operation_type": "appliance", "operation": "restoreMxBgp",
                 "restorePayload": "", "status": ""}
    try:
        with open(f'{path}/network/{net["name"]}/appliance/appliance_routing/bgp.json') as fp:
            data = json.load(fp)
            fp.close()
        enabled=data['enabled']
        upd = {k:data[k] for k in data.keys() - {"enabled"}}
        operation['restorePayload'] = data
        dashboard.appliance.updateNetworkApplianceVpnBgp(networkId=net['id'], enabled=enabled, **upd)
        operation['status'] = "Complete"
    except meraki.APIError as e:
        logger.error(e)
        operation['status'] = e
    return operation


def restoreSwitchLinkAgg(net, dashboard, path, devices_in_network):
    """
    Restore Switch Link Agg Groups
    This function will:
    1. Check if the backup switches match the current switches in the network
    2. If this check is successful, it will delete all current link aggregations, and create new ones based on the
    backup
    :param net: target network
    :param dashboard: Meraki API client
    :param path: Backup location
    :return:
    """
    operation = {"network": net, "operation_type": "switch", "operation": "restoreSwitchLinkAgg",
                 "restorePayload": "", "status": ""}
    try:
        with open(f'{path}/network/{net["name"]}/switch/switch_settings/switch_link_aggregations.json') as fp:
            backup_link_aggs = json.load(fp)
            fp.close()
        operation['restorePayload'] = backup_link_aggs
        current_link_aggs = dashboard.switch.getNetworkSwitchLinkAggregations(networkId=net['id'])
        switches_in_backup_preproc = []
        for la in backup_link_aggs:
            for port in la['switchPorts']:
                switches_in_backup_preproc.append(port['serial'])
        switches_in_backup = set(switches_in_backup_preproc)
        current_switches_preproc = []
        for la in current_link_aggs:
            for port in la['switchPorts']:
                current_switches_preproc.append(port['serial'])
        current_switches = set(switches_in_backup_preproc)
        non_intersection = switches_in_backup.difference(current_switches)
        if non_intersection != set():
            logger.error("Switches in backup do not match switches currently in network. Link aggregations will not be restored.")
            logger.debug(f"Switches in backup: {switches_in_backup}")
            logger.debug(f"Current switches: {current_switches}")
        else:
            proceed = input("Current link aggregations will be deleted, and recreated according to backup. Do you wish to continue? (Y/N): ")
            if proceed == 'Y':
                for la in current_link_aggs:
                    dashboard.switch.deleteNetworkSwitchLinkAggregation(networkId=net['id'], linkAggregationId=la['id'])
                for la in backup_link_aggs:
                    upd = {k:la[k] for k in la.keys() - {'id'}}
                    dashboard.switch.createNetworkSwitchLinkAggregation(networkId=net['id'], **upd)
            else:
                logger.error("Link aggregation restore aborted by user.")
        operation['status'] = "Complete"
    except meraki.APIError as e:
        logger.error(e)
        operation['status'] = e
    return operation


def restoreOrganizationPolicyObjects(org, dashboard, path):
    """
    Restore Organization Policy Objects
    :param net: target network
    :param dashboard: Meraki API client
    :param path: Backup location
    :return:
    """
    operation = {"network": "Organization", "operation_type": "organization", "operation": "restoreOrganizationPolicyObjects",
                 "restorePayload": "", "status": ""}
    try:
        with open(f'{path}/organization/policy_objects/policy_objects.json') as fp:
            policy_object_data = json.load(fp)
            fp.close()
        with open(f'{path}/organization/policy_objects/policy_objects_groups.json') as fp:
            policy_objects_groups_data = json.load(fp)
            fp.close()
        operation['restorePayload'] = [policy_object_data, policy_objects_groups_data]

        existing_policy_objects = dashboard.organizations.getOrganizationPolicyObjects(organizationId=org, total_pages=-1)
        backup_po_set = set(po['name'] for po in policy_object_data)
        net_po_set = set(po['name'] for po in existing_policy_objects)
        to_create = backup_po_set.difference(net_po_set)
        to_update = backup_po_set.difference(to_create)

        # Construct list of Policy Objects to be created and updated based on the result of the previous set operation
        create_po = [po for po in policy_object_data if (po['name'] in to_create)]
        update_po = [po for po in policy_object_data if (po['name'] in to_update)]

        for po in create_po:
            name = po['name']
            category=po['category']
            type=po['type']
            upd = {k: po[k] for k in po.keys() - {'id', 'name', 'category', 'type', 'groupIds', 'networkIds'}}
            dashboard.organizations.createOrganizationPolicyObject(organizationId=org, name=name, category=category, type=type,**upd)

        for po in update_po:
            po_id = po['id']
            upd = {k: po[k] for k in po.keys() - {'id', 'groupIds', 'networkIds'}}
            dashboard.organizations.updateOrganizationPolicyObject(organizationId=org, policyObjectId=po_id, **upd)


        new_pos = dashboard.organizations.getOrganizationPolicyObjects(organizationId=org, total_pages=-1)

        existing_policy_objects_groups = dashboard.organizations.getOrganizationPolicyObjectsGroups(organizationId=org, total_pages=-1)
        backup_pog_set = set(pog['name'] for pog in policy_objects_groups_data)
        net_pog_set = set(pog['name'] for pog in existing_policy_objects_groups)
        to_create = backup_pog_set.difference(net_pog_set)
        to_update = backup_pog_set.difference(to_create)

        # Construct list of Policy Object Groups to be created and updated based on the result of the previous set operation
        create_pog = [pog for pog in policy_objects_groups_data if (pog['name'] in to_create)]
        update_pog = [pog for pog in policy_objects_groups_data if (pog['name'] in to_update)]

        for pog in create_pog:
            new_object_ids=[]
            for o_id in pog['objectIds']:
                for obj in policy_object_data:
                    if obj['id']==o_id:
                        for new_object in new_pos:
                            if new_object['name']==obj['name']:
                                new_object_ids.append(new_object['id'])
            pog['objectIds']=new_object_ids
            name = pog['name']
            upd = {k: pog[k] for k in pog.keys() - {'id', 'name', 'networkIds'}}
            dashboard.organizations.createOrganizationPolicyObjectsGroup(organizationId=org, name=name, **upd)

        for pog in update_pog:
            new_object_ids=[]
            for o_id in pog['objectIds']:
                for obj in policy_object_data:
                    if obj['id']==o_id:
                        for new_object in new_pos:
                            if new_object['name']==obj['name']:
                                new_object_ids.append(new_object['id'])
            pog_id = pog['id']
            upd = {k: pog[k] for k in pog.keys() - {'id', 'networkIds'}}
            dashboard.organizations.updateOrganizationPolicyObjectsGroup(organizationId=org, policyObjectGroupId=pog_id, **upd)
        operation['status'] = "Complete"
    except meraki.APIError as e:
        logger.error(e)
        operation['status'] = e
    return operation

def restoreMrBluetooth(net, dashboard, path, devices_in_network):
    """
    Restore MR Bluetooth settings
    :param net: target network
    :param dashboard: Meraki API client
    :param path: Backup location
    :return:
    """
    operation = {"network": net, "operation_type": "wireless", "operation": "restoreMrBluetooth",
                 "restorePayload": "", "status": ""}
    try:
        with open(f'{path}/network/{net["name"]}/wireless/bluetooth_settings/network_bluetooth_settings.json') as fp:
            data = json.load(fp)
            fp.close()
        operation['restorePayload'] = data
        dashboard.wireless.updateNetworkWirelessBluetoothSettings(networkId=net['id'], **data)
        operation['status'] = "Complete"
    except meraki.APIError as e:
        logger.error(e)
        operation['status'] = e
    return operation


def restoreSwitchStaticRouting(net, dashboard, path, devices_in_network):
    """
    Function to restore a network's Switch Static Routing
    :param net: target network
    :param dashboard: Meraki API client
    :param path: Backup location
    :return:
    """
    operation = {"network": net, "operation_type": "switch", "operation": "restoreSwitchStaticRouting", "restorePayload": "",
                 "status": ""}
    try:
        directory = f'{path}/network/{net["name"]}/switch/switch_routing'
        # For each switch subfolder, read and update Static Route configs
        for subdirs, dirs, files in os.walk(directory):
            for dir in dirs:
                if dir not in [device['serial'] for device in devices_in_network]:
                    logger.info(
                        f"Your backup contains static routes for {dir}, but this device is not currently in the network.")
                    logger.info(f"Static route settings for {dir} will not be restored.")
                else:
                    if 'static_routes.json' in \
                            next(os.walk(f"{path}/network/{net['name']}/switch/switch_routing/{dir}"))[2]:
                        # Load SVI configs into svis variable
                        with open(f'{path}/network/{net["name"]}/switch/switch_routing/{dir}/static_routes.json') as fp:
                            routes = json.load(fp)
                            fp.close()
                        existing_routes = dashboard.switch.getDeviceSwitchRoutingStaticRoutes(serial=dir)
                        # Iterate through routes in route list
                        for route in routes:
                            update_flag = False
                            for existing_route in existing_routes:
                                if route['name'] == existing_route['name']:
                                    update_flag = True
                                    route_id = existing_route['staticRouteId']
                                    break
                            if update_flag == True:
                                route_name = route['name']
                                upd = {k: route[k] for k in route.keys() - {'staticRouteId'}}
                                new_id = dashboard.switch.updateDeviceSwitchRoutingStaticRoute(serial=dir,
                                                                                      staticRouteId=route_id, **upd)

                            else:
                                route_name = route['name']
                                subnet=route['subnet']
                                next_hop_ip=route['nextHopIp']
                                upd = {k: route[k] for k in route.keys() - {'name', 'subnet', 'nextHopIp'}}
                                new_id = dashboard.switch.createDeviceSwitchRoutingStaticRoute(serial=dir, subnet=subnet, nextHopIp=next_hop_ip,**upd)
        operation['status'] = "Complete"
    except meraki.APIError as e:
        logger.error(e)
        operation['status'] = e
    return operation


def restoreSwitchStormControl(net, dashboard, path):
    """
    Restore Switch Storm Control
    :param net: target network
    :param dashboard: Meraki API client
    :param path: Backup location
    :return:
    """
    operation = {"network": net, "operation_type": "switch", "operation": "restoreSwitchStormControl",
                 "restorePayload": "", "status": ""}
    try:
        with open(f'{path}/network/{net["name"]}/switch/switch_settings/switch_storm_control.json') as fp:
            data = json.load(fp)
            fp.close()
        operation['restorePayload'] = data
        dashboard.switch.updateNetworkSwitchStormControl(networkId=net['id'], **data)
        operation['status'] = "Complete"
    except meraki.APIError as e:
        logger.error(e)
        operation['status'] = e
    return operation

def restoreSwitchDscpCosMap(net, dashboard, path):
    """
    Restore Switch DSCP to COS Map
    :param net: target network
    :param dashboard: Meraki API client
    :param path: Backup location
    :return:
    """
    operation = {"network": net, "operation_type": "switch", "operation": "restoreSwitchDscpCosMap",
                 "restorePayload": "", "status": ""}
    try:
        with open(f'{path}/network/{net["name"]}/switch/switch_settings/switch_dscp_cos.json') as fp:
            data = json.load(fp)
            fp.close()
        operation['restorePayload'] = data
        dashboard.switch.updateNetworkSwitchDscpToCosMappings(networkId=net['id'], mappings=data['mappings'])
        operation['status'] = "Complete"
    except meraki.APIError as e:
        logger.error(e)
        operation['status'] = e
    return operation



### Retired functions

def restoreVlans(net, dashboard, path):
    """Function for restoring VLAN configs"""

    # Open VLAN settings
    with open(f'{path}/network/{net["name"]}/appliance/vlans/vlan_config.json') as fp:
        data = json.load(fp)
        fp.close()
    for i in range(len(data)):
        # Since VLAN 1 always exists in a new config, this must be updated
        # Trying to create it gives an error
        try:
            if data[i]['groupPolicyId']:
                logger.info('VLAN has a Group Policy')
                if data[i]['id'] == 1:
                    dashboard.appliance.updateNetworkApplianceVlan(
                        applianceIp=data[i]['applianceIp'],
                        vlanId=data[i]['id'],
                        name=data[i]['name'],
                        networkId=net['id'],
                        subnet=data[i]['subnet'],
                        groupPolicyId=data[i]['groupPolicyId']
                    )
                # For all other VLANs create them
                # CHECK IF VLAN ALREADY EXISTS
                # IF THEY DO, JUST UPDATE
                else:
                    dashboard.appliance.createNetworkApplianceVlan(
                        applianceIp=data[i]['applianceIp'],
                        id=data[i]['id'],
                        name=data[i]['name'],
                        networkId=net['id'],
                        subnet=data[i]['subnet'],
                        groupPolicyId=data[i]['groupPolicyId']
                    )
        except KeyError as e:
            logger.error(e)
            logger.info('VLAN does not have a Group Policy')
            if data[i]['id'] == 1:
                dashboard.appliance.updateNetworkApplianceVlan(
                    applianceIp=data[i]['applianceIp'],
                    vlanId=data[i]['id'],
                    name=data[i]['name'],
                    networkId=net['id'],
                    subnet=data[i]['subnet']
                )
            # For all other VLANs create them
            # CHECK IF VLAN ALREADY EXISTS
            # IF IT DOES, JUST UPDATE
            else:
                dashboard.appliance.createNetworkApplianceVlan(
                    applianceIp=data[i]['applianceIp'],
                    id=data[i]['id'],
                    name=data[i]['name'],
                    networkId=net['id'],
                    subnet=data[i]['subnet']
                )
    # Default VLAN creation behavior does not modify DHCP settings on it, so need to now do an
    # Update DHCP settings operation
    for item in data:
        if item['dhcpHandling'] != 'Do not respond to DHCP requests' \
                and item['dhcpHandling'] != 'Relay DHCP to another server':
            vlan_id = item['id']
            upd = {k: item[k] for k in item.keys() - {'id', 'networkId'}}
            dashboard.appliance.updateNetworkApplianceVlan(
                networkId=net['id'],
                vlanId=vlan_id,
                **upd
            )
    # Update Port configurations on the MX to allow the specific VLANs
    with open(f'{path}/network/{net["name"]}/appliance/vlans/vlan_ports.json') as fp:
        data = json.load(fp)
        fp.close()
    devices = dashboard.networks.getNetworkDevices(networkId=net['id'])
    for device in devices:
        if device['model'] in ['MX64', 'MX64W', 'MX67', 'MX67W', 'MX67C', 'MX100']:
            starting_port = 2
            logger.debug(starting_port)
        elif 'MX' in device['model']:
            starting_port = 3
    model_ports = dashboard.appliance.getNetworkAppliancePorts(networkId=net['id'])
    # If trying to apply a backup to an MX with fewer ports stop at the last port
    if len(data) < len(model_ports):
        logger.info("MX has more ports than backup")
        for i in range(len(data)):
            upd = {k: data[i][k] for k in data[i].keys() - {'number'}}
            dashboard.appliance.updateNetworkAppliancePort(
                networkId=net['id'],
                portId=i + starting_port,
                **upd
            )
    else:
        for i in range(len(model_ports)):
            upd = {k: data[i][k] for k in data[i].keys() - {'number'}}
            dashboard.appliance.updateNetworkAppliancePort(
                networkId=net['id'],
                portId=i + starting_port,
                **upd
            )

def restoreSwitchPortConfigs(net, dashboard, path):
    """Function for restoring Switch Port configs"""
    directory = f'{path}/network/{net["name"]}/switch/switch_settings'
    port_schedules = dashboard.switch.getNetworkSwitchPortSchedules(networkId=net['id'])
    access_policies = dashboard.switch.getNetworkSwitchAccessPolicies(networkId=net['id'])
    # For each switch subfolder, read and update port configs
    for subdirs, dirs, files in os.walk(directory):
        for dir in dirs:
            with open(f'{path}/network/{net["name"]}/switch/switch_settings/{dir}/switch_ports.json') as fp:
                data = json.load(fp)
                fp.close()
            for port in data:
                upd = port
                port_id = upd['portId']
                del upd['portId']
                for schedule in port_schedules:
                    if schedule['name']==upd['portScheduleId']:
                        upd['portScheduleId']=schedule['id']
                if port['type'] == 'access':
                    if port['accessPolicyType'] != 'Open':
                        for policy in access_policies:
                            if policy['name'] == port['accessPolicyNumber']:
                                upd['accessPolicyNumber']=int(policy['accessPolicyNumber'])
                dashboard.switch.updateDeviceSwitchPort(serial=dir, portId=port_id, **upd)
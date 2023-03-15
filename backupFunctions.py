import os
import json
import meraki
import requests
import shutil

def merakiBackup(dir, org, networks, dashboard, logger):
    """
    Wrapper function for backup operations. Will iterate across the list of networks and perform applicable
    backup operations, and return a list of dictionaries of operations with their status.
    :param dir: path to backup
    :param networks: list of networks being backed up
    :param dashboard: Meraki API client
    :return: operations: list of operations performed with their status
    """
    operations = []
    # Backup Org Settings
    logger.info("Backing up organization settings...")
    operations.append(backupOrganizationPolicyObjects(org=org, dir=dir, dashboard=dashboard, logger=logger))
    operations.append(backupOrganizationMxIpsecVpn(org=org, dir=dir, dashboard=dashboard, logger=logger))
    operations.append(backupOrganizationMxVpnFirewall(org=org, dir=dir, dashboard=dashboard, logger=logger))
    for net in networks:
        # Backup MX Settings
        logger.info(f"Backing up settings for network {net['name']}...")
        if 'appliance' in net['productTypes']:
            logger.info("Backing up MX appliance settings...")
            settings, mx_settings_operation = backupMxSettings(net=net, dir=dir, dashboard=dashboard, logger=logger)
            operations.append(mx_settings_operation)
            logger.info("Backing up MX Warm Spare settings...")
            operations.append(backupMxWarmSpare(net=net, dir=dir, dashboard=dashboard, logger=logger))
            if settings != []:
                if settings['deploymentMode']=='routed':
                    logger.info("Backing up MX VLAN settings...")
                    operations.append(backupMxVlans(net=net, dir=dir, dashboard=dashboard, logger=logger))
            logger.info("Backing up MX Firewall settings...")
            operations.append(backupMxFirewall(net=net, dir=dir, dashboard=dashboard, logger=logger))
            logger.info("Backing up MX Security settings...")
            operations.append(backupMxSecurity(net=net, dir=dir, dashboard=dashboard, logger=logger))
            logger.info("Backing up MX Content Filtering settings...")
            operations.append(backupMxContentFiltering(net=net, dir=dir, dashboard=dashboard, logger=logger))
            logger.info("Backing up MX Shaping settings...")
            operations.append(backupMxShaping(net=net, dir=dir, dashboard=dashboard, logger=logger))
            logger.info("Backing up MX AutoVPN settings...")
            vpn_config, vpn_operation = backupMxVpnConfig(net=net, dir=dir, dashboard=dashboard, logger=logger)
            operations.append(vpn_operation)
            if settings != []:
                if settings['deploymentMode']=='routed':
                    logger.info("Backing up MX Static Routes settings...")
                    operations.append(backupMxStaticRouting(net=net, dir=dir, dashboard=dashboard, logger=logger))
            operations.append(backupMxSdWanSettings(net=net, dir=dir, dashboard=dashboard, logger=logger))
            if settings != [] and vpn_config != []:
                if settings['deploymentMode']=='passthrough' and vpn_config["mode"]=='hub':
                    logger.info("Backing up MX BGP settings...")
                    operations.append(backupMxBgp(net=net, dir=dir, dashboard=dashboard, logger=logger))
        # Backup MR Settings
        if 'wireless' in net['productTypes']:
            logger.info("Backing up MR Wireless Network settings...")
            operations.append(backupMrWirelessSettings(net=net, dir=dir, dashboard=dashboard, logger=logger))
            logger.info("Backing up MR SSID configs settings...")
            operations.append(backupMrSsidConfigs(net=net, dir=dir, dashboard=dashboard, logger=logger))
            logger.info("Backing up MR RF Profiles settings...")
            operations.append(backupMrRfProfiles(net=net, dir=dir, dashboard=dashboard, logger=logger))
            logger.info("Backing up MR SSID Firewall settings...")
            operations.append(backupMrSsidFW(net=net, dir=dir, dashboard=dashboard, logger=logger))
            logger.info("Backing up MR SSID Shaping settings...")
            operations.append(backupMrSsidShaping(net=net, dir=dir, dashboard=dashboard, logger=logger))
            logger.info("Backing up MR Bluetooth settings...")
            operations.append(backupMrBluetooth(net=net, dir=dir, dashboard=dashboard, logger=logger))
        # Backup MS settings
        if 'switch' in net['productTypes']:
            logger.info("Backing up MS Switch settings...")
            operations.append(backupSwitchSettings(net=net, dir=dir, dashboard=dashboard, logger=logger))
            logger.info("Backing up MS DSCP to COS Mappings settings...")
            operations.append(backupSwitchDscpCosMap(net=net, dir=dir, dashboard=dashboard, logger=logger))
            logger.info("Backing up MS MTU settings...")
            operations.append(backupSwitchMtu(net=net, dir=dir, dashboard=dashboard, logger=logger))
            logger.info("Backing up MS QoS settings...")
            operations.append(backupSwitchQos(net=net, dir=dir, dashboard=dashboard, logger=logger))
            logger.info("Backing up MS STP settings...")
            operations.append(backupSwitchStp(net=net, dir=dir, dashboard=dashboard, logger=logger))
            logger.info("Backing up MS ACL settings...")
            operations.append(backupSwitchAcl(net=net, dir=dir, dashboard=dashboard, logger=logger))
            logger.info("Backing up MS Stack Settings settings...")
            operations.append(backupSwitchStacks(net=net, dir=dir, dashboard=dashboard, logger=logger))
            logger.info("Backing up MS Port Schedules  settings...")
            operations.append(backupSwitchPortSchedules(net=net, dir=dir, dashboard=dashboard, logger=logger))
            logger.info("Backing up MS Access Policies  settings...")
            operations.append(backupSwitchAccessPolicies(net=net, dir=dir, dashboard=dashboard, logger=logger))
            logger.info("Backing up MS Link Aggregation  settings...")
            operations.append(backupSwitchLinkAggregations(net=net, dir=dir, dashboard=dashboard, logger=logger))
            logger.info("Backing up MS Switch Port Configs settings...")
            operations.append(backupSwitchPortConfigs(net=net, dir=dir, dashboard=dashboard, logger=logger))
            logger.info("Backing up MS Switch SVIs settings...")
            operations.append(backupSwitchSvis(net=net, dir=dir, dashboard=dashboard, logger=logger))
            logger.info("Backing up MS Static Routes settings...")
            operations.append(backupSwitchStaticRouting(net=net, dir=dir, dashboard=dashboard, logger=logger))
            logger.info("Backing up MS OSPF settings...")
            operations.append(backupSwitchOspf(net=net, dir=dir, dashboard=dashboard, logger=logger))
            logger.info("Backing up MS Multicast Routing settings...")
            operations.append(backupSwitchRoutingMulticast(net=net, dir=dir, dashboard=dashboard, logger=logger))
            logger.info("Backing up MS Switch DHCP Security settings...")
            operations.append(backupSwitchDhcpSecurity(net=net, dir=dir, dashboard=dashboard, logger=logger))
            logger.info("Backing up MS Switch DAI settings...")
            operations.append(backupSwitchDai(net=net, dir=dir, dashboard=dashboard, logger=logger))
            logger.info("Backing up MS Storm Control settings...")
            operations.append(backupSwitchStormControl(net=net, dir=dir, dashboard=dashboard, logger=logger))

        # Backup Network Settings
        if 'switch' or 'appliance' or 'wireless' in net['productTypes']:
            logger.info("Backing up Network Group Policy settings...")
            operations.append(backupNetworkGroupPolicies(net=net, dir=dir, dashboard=dashboard, logger=logger))
        logger.info("Backing up Network Alert settings...")
        operations.append(backupNetworkAlerts(net=net, dir=dir, dashboard=dashboard, logger=logger))
        logger.info("Backing up Network Device settings...")
        operations.append(backupNetworkDevices(net=net, dir=dir, dashboard=dashboard, logger=logger))
        logger.info("Backing up Network Floorplan settings...")
        operations.append(backupNetworkFloorPlans(net=net, dir=dir, dashboard=dashboard, logger=logger))
        logger.info("Backing up Network Webhooks settings...")
        operations.append(backupNetworkWebhooks(net=net, dir=dir, dashboard=dashboard, logger=logger))
        logger.info("Backing up Network Syslog settings...")
        operations.append(backupNetworkSyslog(net=net, dir=dir, dashboard=dashboard, logger=logger))
        logger.info("Backing up Network SNMP settings...")
        operations.append(backupNetworkSnmp(net=net, dir=dir, dashboard=dashboard, logger=logger))
        logger.info("Backing up Network Firmware Version settings...")
        operations.append(backupNetworkFirmwareVersions(net=net, dir=dir, dashboard=dashboard, logger=logger))
    return operations

def backupNetworkDevices(net, dir, dashboard, logger):
    """
    Back up network device settings like names, tags, locations, IP addresses
    :param net: Network to get devices list from
    :param dir: Path to backup
    :param dashboard: Meraki API Client
    :return: operation: operation performed and its status
    """
    operation = {"network": net, "operation_type": "network","operation": "backupNetworkDevices", "status": ""}
    try:
        network_devices = dashboard.networks.getNetworkDevices(networkId=net['id'])
        # Check folder structure exists, and if not create it
        if not os.path.exists(dir):
            os.makedirs(dir)
        if not os.path.exists(f'{dir}/network'):
            os.makedirs(f'{dir}/network')
        if not os.path.exists(f'{dir}/network/{net["name"]}'):
            os.makedirs(f'{dir}/network/{net["name"]}')
        if not os.path.exists(f'{dir}/network/{net["name"]}/devices'):
            os.makedirs(f'{dir}/network/{net["name"]}/devices')
        # Write Device settings to devices.json
        with open(f'{dir}/network/{net["name"]}/devices/network_devices.json', 'w') as fp:
            json.dump(network_devices, fp)
            fp.close()
        operation["status"]="Complete"
    except meraki.APIError as e:
        logger.error(e)
        operation["status"]=e
    return operation

def backupNetworkFloorPlans(net, dir, dashboard, logger):
    """
    Back up network floorplans
    :param net: Network to get Floorplans for
    :param dir: Path to backup
    :param dashboard: Meraki API Client
    :return: operation: operation performed and its status
    """
    operation = {"network": net, "operation_type": "network", "operation": "backupNetworkFloorPlans", "status": ""}
    try:
        floorplans = dashboard.networks.getNetworkFloorPlans(networkId=net['id'])
        if not os.path.exists(dir):
            os.makedirs(dir)
        if not os.path.exists(f'{dir}/network'):
            os.makedirs(f'{dir}/network')
        if not os.path.exists(f'{dir}/network/{net["name"]}'):
            os.makedirs(f'{dir}/network/{net["name"]}')
        if not os.path.exists(f'{dir}/network/{net["name"]}/floorplans'):
            os.makedirs(f'{dir}/network/{net["name"]}/floorplans')
        # Write floorplans to floorplans.json
        with open(f'{dir}/network/{net["name"]}/floorplans/floorplans.json', 'w') as fp:
            json.dump(floorplans, fp)
            fp.close()
        for floorplan in floorplans:
            url = floorplan['imageUrl']
            res = requests.get(url.split('?')[0], stream=True)
            if res.status_code == 200:
                with open(f'{dir}/network/{net["name"]}/floorplans/{floorplan["name"]}.png', 'wb') as f:
                    shutil.copyfileobj(res.raw, f)
                logger.info(f'Image sucessfully Downloaded: {dir}/network/{net["name"]}/floorplans/{floorplan["name"]}.png')
            else:
                logger.error(f'Image for floorplan {floorplan["name"]} couldn\'t be retrieved')
        operation['status']="Complete"
    except meraki.APIError as e:
        logger.error(e)
        operation["status"]=e
    return operation

def backupMxVlans(net, dir, dashboard, logger):
    """
    Backup MX VLAN Configs
    :param net: Network to get MX VLANs for
    :param dir: Path to backup
    :param dashboard: Meraki API Client
    :return: operation: operation performed and its status
    """
    operation = {"network": net, "operation_type": "appliance","operation": "backupMxVlans", "status": ""}
    try:
        vlan_settings = dashboard.appliance.getNetworkApplianceVlansSettings(networkId=net['id'])
        # Check folder structure exists, and if not create it
        if not os.path.exists(dir):
            os.makedirs(dir)
        if not os.path.exists(f'{dir}/network'):
            os.makedirs(f'{dir}/network')
        if not os.path.exists(f'{dir}/network/{net["name"]}'):
            os.makedirs(f'{dir}/network/{net["name"]}')
        if not os.path.exists(f'{dir}/network/{net["name"]}/appliance'):
            os.makedirs(f'{dir}/network/{net["name"]}/appliance')
        if not os.path.exists(f'{dir}/network/{net["name"]}/appliance/vlans'):
            os.makedirs(f'{dir}/network/{net["name"]}/appliance/vlans')
        # Write VLAN settings to vlan_settings.json file
        with open(f'{dir}/network/{net["name"]}/appliance/vlans/vlan_settings.json', 'w') as fp:
            json.dump(vlan_settings, fp)
            fp.close()
        # Write VLAN port and global config into the vlan_config and vlan_ports files
        if vlan_settings['vlansEnabled'] == True:
            vlan_config = dashboard.appliance.getNetworkApplianceVlans(networkId=net['id'])
            vlan_ports = dashboard.appliance.getNetworkAppliancePorts(networkId=net['id'])
            with open(f'{dir}/network/{net["name"]}/appliance/vlans/vlan_config.json', 'w') as fp:
                json.dump(vlan_config, fp)
                fp.close()
            with open(f'{dir}/network/{net["name"]}/appliance/vlans/vlan_ports.json', 'w') as fp:
                json.dump(vlan_ports, fp)
                fp.close()
        operation['status']="Complete"
    except meraki.APIError as e:
        logger.error(e)
        operation['status']=e
    return operation


def backupMxFirewall(net, dir, dashboard, logger):
    """
    Back up MX Firewall settings
    :param net: Network to get MX Firewall for
    :param dir: Path to backup
    :param dashboard: Meraki API Client
    :return: operation: operation performed and its status
    """
    operation = {"network": net, "operation_type": "appliance","operation": "backupMxFirewall", "status": ""}
    try:
        # Check folder structure exists for security and shaping rules, if not, create it
        if not os.path.exists(dir):
            os.makedirs(dir)
        if not os.path.exists(f'{dir}/network'):
            os.makedirs(f'{dir}/network')
        if not os.path.exists(f'{dir}/network/{net["name"]}'):
            os.makedirs(f'{dir}/network/{net["name"]}')
        if not os.path.exists(f'{dir}/network/{net["name"]}/appliance'):
            os.makedirs(f'{dir}/network/{net["name"]}/appliance')
        if not os.path.exists(f'{dir}/network/{net["name"]}/appliance/security'):
            os.makedirs(f'{dir}/network/{net["name"]}/appliance/security')

        # Obtain current L3 firewall rules
        l3_fw = dashboard.appliance.getNetworkApplianceFirewallL3FirewallRules(networkId=net['id'])
        # Write L7 firewall rules to file l7_fw.json
        with open(f'{dir}/network/{net["name"]}/appliance/security/l3_fw.json', 'w') as fp:
            json.dump(l3_fw, fp)
            fp.close()
        # Obtain current L7 firewall rules
        l7_fw = dashboard.appliance.getNetworkApplianceFirewallL7FirewallRules(networkId=net['id'])
        # Write L7 firewall rules to file l7_fw.json
        with open(f'{dir}/network/{net["name"]}/appliance/security/l7_fw.json', 'w') as fp:
            json.dump(l7_fw, fp)
            fp.close()
        operation['status']="Complete"
    except meraki.APIError as e:
        logger.error(e)
        operation['status']=e
    return operation


def backupMxSecurity(net, dir, dashboard, logger):
    """
    Back up MX AMP and Intrusion settings
    :param net: Network to get MX AMP and Intrusion settings for
    :param dir: Path to backup
    :param dashboard: Meraki API Client
    :return: operation: operation performed and its status
    """
    operation = {"network": net, "operation_type": "appliance", "operation": "backupMxSecurity", "status": ""}
    try:
        # Check folder structure exists for security and shaping rules, if not, create it
        if not os.path.exists(dir):
            os.makedirs(dir)
        if not os.path.exists(f'{dir}/network'):
            os.makedirs(f'{dir}/network')
        if not os.path.exists(f'{dir}/network/{net["name"]}'):
            os.makedirs(f'{dir}/network/{net["name"]}')
        if not os.path.exists(f'{dir}/network/{net["name"]}/appliance'):
            os.makedirs(f'{dir}/network/{net["name"]}/appliance')
        if not os.path.exists(f'{dir}/network/{net["name"]}/appliance/security'):
            os.makedirs(f'{dir}/network/{net["name"]}/appliance/security')
        amp = dashboard.appliance.getNetworkApplianceSecurityMalware(networkId=net['id'])
        # Write AMP rules to amp.json file
        with open(f'{dir}/network/{net["name"]}/appliance/security/amp.json', 'w') as fp:
            json.dump(amp, fp)
            fp.close()
        # Obtain current IPS rules
        ips = dashboard.appliance.getNetworkApplianceSecurityIntrusion(networkId=net['id'])
        # Write IPS rules to ips.json file
        with open(f'{dir}/network/{net["name"]}/appliance/security/ips.json', 'w') as fp:
            json.dump(ips, fp)
            fp.close()
        operation['status'] = "Complete"
    except meraki.APIError as e:
        logger.error(e)
        operation['status'] = e
    return operation

def backupMxContentFiltering(net, dir, dashboard, logger):
    """
    Back up MX Content Filtering settings
    :param net: Network to get MX Content Filtering for
    :param dir: Path to backup
    :param dashboard: Meraki API Client
    :return: operation: operation performed and its status
    """
    operation = {"network": net, "operation_type": "appliance", "operation": "backupMxContentFiltering", "status": ""}
    try:
        # Check folder structure exists for security and shaping rules, if not, create it
        if not os.path.exists(dir):
            os.makedirs(dir)
        if not os.path.exists(f'{dir}/network'):
            os.makedirs(f'{dir}/network')
        if not os.path.exists(f'{dir}/network/{net["name"]}'):
            os.makedirs(f'{dir}/network/{net["name"]}')
        if not os.path.exists(f'{dir}/network/{net["name"]}/appliance'):
            os.makedirs(f'{dir}/network/{net["name"]}/appliance')
        if not os.path.exists(f'{dir}/network/{net["name"]}/appliance/security'):
            os.makedirs(f'{dir}/network/{net["name"]}/appliance/security')
        # Obtain current content filtering rules
        content_filtering = dashboard.appliance.getNetworkApplianceContentFiltering(networkId=net['id'])
        # Reshape blockedUrlCategories in format required by endpoint
        blockedUrlCategories = []
        for category in content_filtering['blockedUrlCategories']:
            blockedUrlCategories.append(category['id'])
        # Add to list
        content_filtering['blockedUrlCategories'] = blockedUrlCategories
        # Write list to content_filtering.json file
        with open(f'{dir}/network/{net["name"]}/appliance/security/content_filtering.json', 'w') as fp:
            json.dump(content_filtering, fp)
            fp.close()
        operation['status'] = "Complete"
    except meraki.APIError as e:
        logger.error(e)
        operation['status'] = e
    return operation

def backupMxShaping(net, dir, dashboard, logger):
    """
    Back up MX Shaping settings
    :param net: Network to get MX Shaping for
    :param dir: Path to backup
    :param dashboard: Meraki API Client
    :return: operation: operation performed and its status
    """
    operation = {"network": net, "operation_type": "appliance", "operation": "backupMxShaping", "status": ""}
    try:
        # Check folder structure exists for security and shaping rules, if not, create it
        if not os.path.exists(dir):
            os.makedirs(dir)
        if not os.path.exists(f'{dir}/network'):
            os.makedirs(f'{dir}/network')
        if not os.path.exists(f'{dir}/network/{net["name"]}'):
            os.makedirs(f'{dir}/network/{net["name"]}')
        if not os.path.exists(f'{dir}/network/{net["name"]}/appliance'):
            os.makedirs(f'{dir}/network/{net["name"]}/appliance')
        if not os.path.exists(f'{dir}/network/{net["name"]}/appliance/shaping'):
            os.makedirs(f'{dir}/network/{net["name"]}/appliance/shaping')

                # Obtain current global shaping rules
        global_shaping = dashboard.appliance.getNetworkApplianceTrafficShaping(networkId=net['id'])
        # Write global shaping rules to file global_shaping.json
        with open(f'{dir}/network/{net["name"]}/appliance/shaping/global_shaping.json', 'w') as fp:
            json.dump(global_shaping, fp)
            fp.close()
        # Obtain current local shaping rules
        shaping_rules = dashboard.appliance.getNetworkApplianceTrafficShapingRules(networkId=net['id'])
        # Write global shaping rules to file shaping_rules.json
        with open(f'{dir}/network/{net["name"]}/appliance/shaping/shaping_rules.json', 'w') as fp:
            json.dump(shaping_rules, fp)
            fp.close()
        operation['status'] = "Complete"
    except meraki.APIError as e:
        logger.error(e)
        operation['status'] = e
    return operation

def backupMxVpnConfig(net, dir, dashboard, logger):
    """
    Back up MX VPN settings
    :param net: Network to get VPN Configs for
    :param dir: Path to backup
    :param dashboard: Meraki API Client
    :return: operation: operation performed and its status
    """
    vpn_config = []
    operation = {"network": net, "operation_type": "appliance", "operation": "backupMxVpn", "status": ""}
    try:
        # Check folder structure exists for VPN config, if not, create it
        if not os.path.exists(dir):
            os.makedirs(dir)
        if not os.path.exists(f'{dir}/network'):
            os.makedirs(f'{dir}/network')
        if not os.path.exists(f'{dir}/network/{net["name"]}'):
            os.makedirs(f'{dir}/network/{net["name"]}')
        if not os.path.exists(f'{dir}/network/{net["name"]}/appliance'):
            os.makedirs(f'{dir}/network/{net["name"]}/appliance')
        if not os.path.exists(f'{dir}/network/{net["name"]}/appliance/vpn_config'):
            os.makedirs(f'{dir}/network/{net["name"]}/appliance/vpn_config')
        # Obtain current VPN Config
        vpn_config = dashboard.appliance.getNetworkApplianceVpnSiteToSiteVpn(networkId=net['id'])
        with open(f'{dir}/network/{net["name"]}/appliance/vpn_config/vpn_config.json', 'w') as fp:
            json.dump(vpn_config, fp)
            fp.close()
        operation['status'] = "Complete"
    except meraki.APIError as e:
        logger.error(e)
        operation['status'] = e
    return vpn_config, operation

def backupMxWarmSpare(net, dir, dashboard, logger):
    """
    Back up MX Warm Spare settings
    :param net: Network to get Warm Spare for
    :param dir: Path to backup
    :param dashboard: Meraki API Client
    :return: operation: operation performed and its status
    """
    operation = {"network": net, "operation_type": "appliance", "operation": "backupMxWarmSpare", "status": ""}
    try:
        # Check folder structure exists for Warm Spare, if not, create it
        if not os.path.exists(dir):
            os.makedirs(dir)
        if not os.path.exists(f'{dir}/network'):
            os.makedirs(f'{dir}/network')
        if not os.path.exists(f'{dir}/network/{net["name"]}'):
            os.makedirs(f'{dir}/network/{net["name"]}')
        if not os.path.exists(f'{dir}/network/{net["name"]}/appliance'):
            os.makedirs(f'{dir}/network/{net["name"]}/appliance')
        if not os.path.exists(f'{dir}/network/{net["name"]}/appliance/warm_spare'):
            os.makedirs(f'{dir}/network/{net["name"]}/appliance/warm_spare')
        warm_spare = dashboard.appliance.getNetworkApplianceWarmSpare(networkId=net['id'])
        with open(f'{dir}/network/{net["name"]}/appliance/warm_spare/warm_spare.json', 'w') as fp:
            json.dump(warm_spare, fp)
            fp.close()
        operation['status'] = "Complete"
    except meraki.APIError as e:
        logger.error(e)
        operation['status'] = e
    return operation

def backupSwitchQos(net, dir, dashboard, logger):
    """
    Back up MS QoS settings
    :param net: Network to get Switch QOS for
    :param dir: Path to backup
    :param dashboard: Meraki API Client
    :return: operation: operation performed and its status
    """
    operation = {"network": net, "operation_type": "switch", "operation": "backupSwitchQos", "status": ""}
    try:
        # Check folder structure exists for switch settings, if not, create it
        if not os.path.exists(dir):
            os.makedirs(dir)
        if not os.path.exists(f'{dir}/network'):
            os.makedirs(f'{dir}/network')
        if not os.path.exists(f'{dir}/network/{net["name"]}'):
            os.makedirs(f'{dir}/network/{net["name"]}')
        if not os.path.exists(f'{dir}/network/{net["name"]}/switch'):
            os.makedirs(f'{dir}/network/{net["name"]}/switch')
        if not os.path.exists(f'{dir}/network/{net["name"]}/switch/switch_settings'):
            os.makedirs(f'{dir}/network/{net["name"]}/switch/switch_settings')
        # Obtain current QoS rules
        qos_rules = dashboard.switch.getNetworkSwitchQosRules(networkId=net['id'])
        with open(f'{dir}/network/{net["name"]}/switch/switch_settings/qos_rules.json', 'w') as fp:
            json.dump(qos_rules, fp)
            fp.close()
        operation['status'] = "Complete"
    except meraki.APIError as e:
        logger.error(e)
        operation['status'] = e
    return operation


def backupSwitchPortSchedules(net, dir, dashboard, logger):
    """
    Back up MS Port Schedule settings
    :param net: Network to get Switch Port Schedules for
    :param dir: Path to backup
    :param dashboard: Meraki API Client
    :return: operation: operation performed and its status
    """
    operation = {"network": net, "operation_type": "switch", "operation": "backupSwitchPortSchedules", "status": ""}
    try:
        # Check folder structure exists for switch settings, if not, create it
        if not os.path.exists(dir):
            os.makedirs(dir)
        if not os.path.exists(f'{dir}/network'):
            os.makedirs(f'{dir}/network')
        if not os.path.exists(f'{dir}/network/{net["name"]}'):
            os.makedirs(f'{dir}/network/{net["name"]}')
        if not os.path.exists(f'{dir}/network/{net["name"]}/switch'):
            os.makedirs(f'{dir}/network/{net["name"]}/switch')
        if not os.path.exists(f'{dir}/network/{net["name"]}/switch/switch_settings'):
            os.makedirs(f'{dir}/network/{net["name"]}/switch/switch_settings')
        # Obtain current port schedules
        port_schedules = dashboard.switch.getNetworkSwitchPortSchedules(networkId=net['id'])
        with open(f'{dir}/network/{net["name"]}/switch/switch_settings/port_schedules.json', 'w') as fp:
            json.dump(port_schedules, fp)
            fp.close()
        operation['status'] = "Complete"
    except meraki.APIError as e:
        logger.error(e)
        operation['status'] = e
    return operation

def backupSwitchPortConfigs(net, dir, dashboard, logger):
    """
    Back up MS Port Configs
    :param net: Network to get Switch Ports for
    :param dir: Path to backup
    :param dashboard: Meraki API Client
    :return: operation: operation performed and its status
    """
    operation = {"network": net, "operation_type": "switch", "operation": "backupSwitchPortConfigs", "status": ""}
    try:
        # Check folder structure exists for switch settings, if not, create it
        if not os.path.exists(dir):
            os.makedirs(dir)
        if not os.path.exists(f'{dir}/network'):
            os.makedirs(f'{dir}/network')
        if not os.path.exists(f'{dir}/network/{net["name"]}'):
            os.makedirs(f'{dir}/network/{net["name"]}')
        if not os.path.exists(f'{dir}/network/{net["name"]}/switch'):
            os.makedirs(f'{dir}/network/{net["name"]}/switch')
        if not os.path.exists(f'{dir}/network/{net["name"]}/switch/switch_settings'):
            os.makedirs(f'{dir}/network/{net["name"]}/switch/switch_settings')
        # Obtain current Port configs
        devices = dashboard.networks.getNetworkDevices(networkId=net['id'])
        port_schedules = dashboard.switch.getNetworkSwitchPortSchedules(networkId=net['id'])
        access_policies = dashboard.switch.getNetworkSwitchAccessPolicies(networkId=net['id'])
        for device in devices:
            if 'MS' in device['model']:
                switch_ports = dashboard.switch.getDeviceSwitchPorts(serial=device['serial'])
                for port in switch_ports:
                    if port['type']=='access':
                        if port['accessPolicyType']!='Open':
                            for policy in access_policies:
                                if policy['accessPolicyNumber']==port['accessPolicyNumber']:
                                    port['accessPolicyNumber']=policy['name']
                    if port['portScheduleId'] != None:
                        for schedule in port_schedules:
                            if schedule['id']==port['portScheduleId']:
                                port['portScheduleId']=schedule['name']
                if not os.path.exists(f'{dir}/network/{net["name"]}/switch/switch_settings/{device["serial"]}'):
                    os.makedirs(f'{dir}/network/{net["name"]}/switch/switch_settings/{device["serial"]}')
                with open(f'{dir}/network/{net["name"]}/switch/switch_settings/{device["serial"]}/switch_ports.json',
                          'w') as fp:
                    json.dump(switch_ports, fp)
                    fp.close()
        operation['status'] = "Complete"
    except meraki.APIError as e:
        logger.error(e)
        operation['status'] = e
    return operation

def backupNetworkAlerts(net, dir, dashboard, logger):
    """
    Back up Network Alerts
    :param net: Network to get Alerts for
    :param dir: Path to backup
    :param dashboard: Meraki API Client
    :return: operation: operation performed and its status
    """
    operation = {"network": net, "operation_type": "network", "operation": "backupNetworkAlerts", "status": ""}
    try:
        # Check folder structure exists for switch settings, if not, create it
        if not os.path.exists(dir):
            os.makedirs(dir)
        if not os.path.exists(f'{dir}/network'):
            os.makedirs(f'{dir}/network')
        if not os.path.exists(f'{dir}/network/{net["name"]}'):
            os.makedirs(f'{dir}/network/{net["name"]}')
        if not os.path.exists(f'{dir}/network/{net["name"]}/alert_settings'):
            os.makedirs(f'{dir}/network/{net["name"]}/alert_settings')
        # Obtain current alert settings
        alerts = dashboard.networks.getNetworkAlertsSettings(networkId=net['id'])
        with open(f'{dir}/network/{net["name"]}/alert_settings/alerts.json', 'w') as fp:
            json.dump(alerts, fp)
            fp.close()
        operation['status'] = "Complete"
    except meraki.APIError as e:
        logger.error(e)
        operation['status'] = e
    return operation

def backupMrSsidConfigs(net, dir, dashboard, logger):
    """
    Back up MR SSID Configs
    :param net: Network to get SSID configs for
    :param dir: Path to backup
    :param dashboard: Meraki API Client
    :return: operation: operation performed and its status
    """
    operation = {"network": net, "operation_type": "wireless", "operation": "backupMrSsidConfigs", "status": ""}
    try:
        # Check folder structure exists for switch settings, if not, create it
        if not os.path.exists(dir):
            os.makedirs(dir)
        if not os.path.exists(f'{dir}/network'):
            os.makedirs(f'{dir}/network')
        if not os.path.exists(f'{dir}/network/{net["name"]}'):
            os.makedirs(f'{dir}/network/{net["name"]}')
        if not os.path.exists(f'{dir}/network/{net["name"]}/wireless'):
            os.makedirs(f'{dir}/network/{net["name"]}/wireless')
        if not os.path.exists(f'{dir}/network/{net["name"]}/wireless/ssid_settings'):
            os.makedirs(f'{dir}/network/{net["name"]}/wireless/ssid_settings')
        # Obtain current SSID settings
        ssids = dashboard.wireless.getNetworkWirelessSsids(networkId=net['id'])
        with open(f'{dir}/network/{net["name"]}/wireless/ssid_settings/ssids.json', 'w') as fp:
            json.dump(ssids, fp)
            fp.close()
        operation['status'] = "Complete"
    except meraki.APIError as e:
        logger.error(e)
        operation['status'] = e
    return operation

def backupMrRfProfiles(net, dir, dashboard, logger):
    """
    Back up MR SSID Configs
    :param net: Network to get RF Profiles for
    :param dir: Path to backup
    :param dashboard: Meraki API Client
    :return: operation: operation performed and its status
    """
    operation = {"network": net, "operation_type": "wireless", "operation": "backupMrRfProfiles", "status": ""}
    try:
        # Check folder structure exists for switch settings, if not, create it
        if not os.path.exists(dir):
            os.makedirs(dir)
        if not os.path.exists(f'{dir}/network'):
            os.makedirs(f'{dir}/network')
        if not os.path.exists(f'{dir}/network/{net["name"]}'):
            os.makedirs(f'{dir}/network/{net["name"]}')
        if not os.path.exists(f'{dir}/network/{net["name"]}/wireless'):
            os.makedirs(f'{dir}/network/{net["name"]}/wireless')
        if not os.path.exists(f'{dir}/network/{net["name"]}/wireless/radio_settings'):
            os.makedirs(f'{dir}/network/{net["name"]}/wireless/radio_settings')
        rf_profiles = dashboard.wireless.getNetworkWirelessRfProfiles(networkId=net['id'])
        with open(f'{dir}/network/{net["name"]}/wireless/radio_settings/rf_profiles.json', 'w') as fp:
            json.dump(rf_profiles, fp)
            fp.close()
        #Get devices in network
        devices = dashboard.networks.getNetworkDevices(networkId=net['id'])
        #Construct radio settings file for APs
        radio_settings = []
        #For every device that is an MR, get their radio settings
        for device in devices:
            if 'MR' in device['model'] or device['model'] in ['CW9166I', 'CW9164I', 'CW9162I']:
                radio_setting = dashboard.wireless.getDeviceWirelessRadioSettings(serial=device['serial'])
                for profile in rf_profiles:
                    if profile['id'] == radio_setting['rfProfileId']:
                        radio_setting['profileName'] = profile['name']
                radio_settings.append(radio_setting)
        with open(f'{dir}/network/{net["name"]}/wireless/radio_settings/radio_settings.json', 'w') as fp:
            json.dump(radio_settings, fp)
            fp.close()
        operation['status'] = "Complete"
    except meraki.APIError as e:
        logger.error(e)
        operation['status'] = e
    return operation


def backupMrSsidFW(net, dir, dashboard, logger):
    """
    Back up MR SSID FW
    :param net: Network to get SSID FW for
    :param dir: Path to backup
    :param dashboard: Meraki API Client
    :return: operation: operation performed and its status
    """
    operation = {"network": net, "operation_type": "wireless", "operation": "backupMrSsidFW", "status": ""}
    try:
        if not os.path.exists(dir):
            os.makedirs(dir)
        if not os.path.exists(f'{dir}/network'):
            os.makedirs(f'{dir}/network')
        if not os.path.exists(f'{dir}/network/{net["name"]}'):
            os.makedirs(f'{dir}/network/{net["name"]}')
        if not os.path.exists(f'{dir}/network/{net["name"]}/wireless'):
            os.makedirs(f'{dir}/network/{net["name"]}/wireless')
        if not os.path.exists(f'{dir}/network/{net["name"]}/wireless/ssid_settings'):
            os.makedirs(f'{dir}/network/{net["name"]}/wireless/ssid_settings')
        #Construct lists for L3 and L7 rules for each SSID
        l7_rules = []
        l3_rules = []
        for i in range(15):
            l7 = dashboard.wireless.getNetworkWirelessSsidFirewallL7FirewallRules(networkId=net['id'], number=i)
            l7['number'] = i
            l3 = dashboard.wireless.getNetworkWirelessSsidFirewallL3FirewallRules(networkId=net['id'], number=i)
            l3['number'] = i
            l7_rules.append(l7)
            l3_rules.append(l3)
        with open(f'{dir}/network/{net["name"]}/wireless/ssid_settings/l7_rules.json', 'w') as fp:
            json.dump(l7_rules, fp)
            fp.close()
        with open(f'{dir}/network/{net["name"]}/wireless/ssid_settings/l3_rules.json', 'w') as fp:
            json.dump(l3_rules, fp)
            fp.close()
        operation['status'] = "Complete"
    except meraki.APIError as e:
        logger.error(e)
        operation['status'] = e
    return operation


def backupMrSsidShaping(net, dir, dashboard, logger):
    """
    Back up MR SSID Shaping
    :param net: Network to get SSID Shaping for
    :param dir: Path to backup
    :param dashboard: Meraki API Client
    :return: operation: operation performed and its status
    """
    operation = {"network": net, "operation_type": "wireless", "operation": "backupMrSsidShaping", "status": ""}
    try:
        if not os.path.exists(dir):
            os.makedirs(dir)
        if not os.path.exists(f'{dir}/network'):
            os.makedirs(f'{dir}/network')
        if not os.path.exists(f'{dir}/network/{net["name"]}'):
            os.makedirs(f'{dir}/network/{net["name"]}')
        if not os.path.exists(f'{dir}/network/{net["name"]}/wireless'):
            os.makedirs(f'{dir}/network/{net["name"]}/wireless')
        if not os.path.exists(f'{dir}/network/{net["name"]}/wireless/ssid_settings'):
            os.makedirs(f'{dir}/network/{net["name"]}/wireless/ssid_settings')
        #Construct a list for shaping rules per SSID
        shaping_rules = []
        for i in range(15):
            shaping = dashboard.wireless.getNetworkWirelessSsidTrafficShapingRules(networkId=net['id'], number=i)
            shaping['number'] = i
            shaping_rules.append(shaping)
        with open(f'{dir}/network/{net["name"]}/wireless/ssid_settings/shaping_rules.json', 'w') as fp:
            json.dump(shaping_rules, fp)
            fp.close()
        operation['status'] = "Complete"
    except meraki.APIError as e:
        logger.error(e)
        operation['status'] = e
    return operation


def backupSwitchSvis(net, dir, dashboard, logger):
    """
    Back up MS SVIs
    :param net: Network to get Switch SVIs for
    :param dir: Path to backup
    :param dashboard: Meraki API Client
    :return: operation: operation performed and its status
    """
    operation = {"network": net, "operation_type": "switch", "operation": "backupSwitchSvis", "status": ""}
    try:
        if not os.path.exists(dir):
            os.makedirs(dir)
        if not os.path.exists(f'{dir}/network'):
            os.makedirs(f'{dir}/network')
        if not os.path.exists(f'{dir}/network/{net["name"]}'):
            os.makedirs(f'{dir}/network/{net["name"]}')
        if not os.path.exists(f'{dir}/network/{net["name"]}/switch'):
            os.makedirs(f'{dir}/network/{net["name"]}/switch')
        if not os.path.exists(f'{dir}/network/{net["name"]}/switch/switch_routing'):
            os.makedirs(f'{dir}/network/{net["name"]}/switch/switch_routing')
        #Get all devices in network
        devices = dashboard.networks.getNetworkDevices(networkId=net['id'])
        #If device is an MS that supports SVIs, get SVIs for it
        for device in devices:
            if 'MS' in device['model'] and ('120' or '125') not in device['model']:
                svis = dashboard.switch.getDeviceSwitchRoutingInterfaces(serial=device['serial'])
                if not os.path.exists(f'{dir}/network/{net["name"]}/switch/switch_routing/{device["serial"]}'):
                    os.makedirs(f'{dir}/network/{net["name"]}/switch/switch_routing/{device["serial"]}')
                with open(f'{dir}/network/{net["name"]}/switch/switch_routing/{device["serial"]}/svis.json', 'w') as fp:
                    json.dump(svis, fp)
                    fp.close()
                svi_dhcp = []
                for svi in svis:
                    dhcp = dashboard.switch.getDeviceSwitchRoutingInterfaceDhcp(serial=device['serial'],
                                                                                interfaceId=svi['interfaceId'])
                    dhcp['interfaceId'] = svi['interfaceId']
                    svi_dhcp.append(dhcp)
                with open(f'{dir}/network/{net["name"]}/switch/switch_routing/{device["serial"]}/svi_dhcp.json', 'w') as fp:
                    json.dump(svi_dhcp, fp)
                    fp.close()
        operation['status'] = "Complete"
    except meraki.APIError as e:
        logger.error(e)
        operation['status'] = e
    return operation


def backupMxStaticRouting(net, dir, dashboard, logger):
    """
    Back up MX Static Routing
    :param net: Network to get MX Static routes for
    :param dir: Path to backup
    :param dashboard: Meraki API Client
    :return: operation: operation performed and its status
    """
    operation = {"network": net, "operation_type": "switch", "operation": "backupMxStaticRouting", "status": ""}
    try:
        if not os.path.exists(dir):
            os.makedirs(dir)
        if not os.path.exists(f'{dir}/network'):
            os.makedirs(f'{dir}/network')
        if not os.path.exists(f'{dir}/network/{net["name"]}'):
            os.makedirs(f'{dir}/network/{net["name"]}')
        if not os.path.exists(f'{dir}/network/{net["name"]}/appliance'):
            os.makedirs(f'{dir}/network/{net["name"]}/appliance')
        if not os.path.exists(f'{dir}/network/{net["name"]}/appliance/appliance_routing'):
            os.makedirs(f'{dir}/network/{net["name"]}/appliance/appliance_routing')
        #Get all Appliance static routes
        static_routes = dashboard.appliance.getNetworkApplianceStaticRoutes(networkId=net['id'])
        with open(f'{dir}/network/{net["name"]}/appliance/appliance_routing/static_routes.json', 'w') as fp:
            json.dump(static_routes, fp)
            fp.close()
        operation['status'] = "Complete"
    except meraki.APIError as e:
        logger.error(e)
        operation['status'] = e
    return operation


def backupSwitchOspf(net, dir, dashboard, logger):
    """
    Back up Switch OSPF Settings
    :param net: Network to get Switch OSPF for
    :param dir: Path to backup
    :param dashboard: Meraki API Client
    :return: operation: operation performed and its status
    """
    operation = {"network": net, "operation_type": "switch", "operation": "backupSwitchOspf", "status": ""}
    try:
        if not os.path.exists(dir):
            os.makedirs(dir)
        if not os.path.exists(f'{dir}/network'):
            os.makedirs(f'{dir}/network')
        if not os.path.exists(f'{dir}/network/{net["name"]}'):
            os.makedirs(f'{dir}/network/{net["name"]}')
        if not os.path.exists(f'{dir}/network/{net["name"]}/switch'):
            os.makedirs(f'{dir}/network/{net["name"]}/switch')
        if not os.path.exists(f'{dir}/network/{net["name"]}/switch/switch_routing'):
            os.makedirs(f'{dir}/network/{net["name"]}/switch/switch_routing')
        #Get all OSPF settings
        ospf = dashboard.switch.getNetworkSwitchRoutingOspf(networkId=net['id'])
        with open(f'{dir}/network/{net["name"]}/switch/switch_routing/ospf.json', 'w') as fp:
            json.dump(ospf, fp)
            fp.close()
        operation['status'] = "Complete"
    except meraki.APIError as e:
        logger.error(e)
        operation['status'] = e
    return operation


def backupSwitchAccessPolicies(net, dir, dashboard, logger):
    """
    Back up Switch Access Policies
    :param net: Network to get Access Policies for
    :param dir: Path to backup
    :param dashboard: Meraki API Client
    :return: operation: operation performed and its status
    """
    operation = {"network": net, "operation_type": "switch", "operation": "backupSwitchAccessPolicies", "status": ""}
    try:
        if not os.path.exists(dir):
            os.makedirs(dir)
        if not os.path.exists(f'{dir}/network'):
            os.makedirs(f'{dir}/network')
        if not os.path.exists(f'{dir}/network/{net["name"]}'):
            os.makedirs(f'{dir}/network/{net["name"]}')
        if not os.path.exists(f'{dir}/network/{net["name"]}/switch'):
            os.makedirs(f'{dir}/network/{net["name"]}/switch')
        if not os.path.exists(f'{dir}/network/{net["name"]}/switch/switch_settings'):
            os.makedirs(f'{dir}/network/{net["name"]}/switch/switch_settings')
        #Get all switch access policies
        access_policies = dashboard.switch.getNetworkSwitchAccessPolicies(networkId=net['id'])
        with open(f'{dir}/network/{net["name"]}/switch/switch_settings/access_policies.json', 'w') as fp:
            json.dump(access_policies, fp)
            fp.close()
        operation['status'] = "Complete"
    except meraki.APIError as e:
        logger.error(e)
        operation['status'] = e
    return operation

def backupSwitchStp(net, dir, dashboard, logger):
    """
    Back up Switch STP Settings
    :param net: Network to get STP for
    :param dir: Path to backup
    :param dashboard: Meraki API Client
    :return: operation: operation performed and its status
    """
    operation = {"network": net, "operation_type": "switch", "operation": "backupSwitchStp", "status": ""}
    try:
        if not os.path.exists(dir):
            os.makedirs(dir)
        if not os.path.exists(f'{dir}/network'):
            os.makedirs(f'{dir}/network')
        if not os.path.exists(f'{dir}/network/{net["name"]}'):
            os.makedirs(f'{dir}/network/{net["name"]}')
        if not os.path.exists(f'{dir}/network/{net["name"]}/switch'):
            os.makedirs(f'{dir}/network/{net["name"]}/switch')
        if not os.path.exists(f'{dir}/network/{net["name"]}/switch/switch_settings'):
            os.makedirs(f'{dir}/network/{net["name"]}/switch/switch_settings')
        #Get all switch STP settings
        switch_stp = dashboard.switch.getNetworkSwitchStp(net['id'])
        with open(f'{dir}/network/{net["name"]}/switch/switch_settings/switch_stp.json', 'w') as fp:
            json.dump(switch_stp, fp)
            fp.close()
        operation['status'] = "Complete"
    except meraki.APIError as e:
        logger.error(e)
        operation['status'] = e
    return operation

def backupSwitchAcl(net, dir, dashboard, logger):
    """
    Back up Switch ACL Settings
    :param net: Network to get Switch ACL for
    :param dir: Path to backup
    :param dashboard: Meraki API Client
    :return: operation: operation performed and its status
    """
    operation = {"network": net, "operation_type": "switch", "operation": "backupSwitchAcl", "status": ""}
    try:
        if not os.path.exists(dir):
            os.makedirs(dir)
        if not os.path.exists(f'{dir}/network'):
            os.makedirs(f'{dir}/network')
        if not os.path.exists(f'{dir}/network/{net["name"]}'):
            os.makedirs(f'{dir}/network/{net["name"]}')
        if not os.path.exists(f'{dir}/network/{net["name"]}/switch'):
            os.makedirs(f'{dir}/network/{net["name"]}/switch')
        if not os.path.exists(f'{dir}/network/{net["name"]}/switch/switch_settings'):
            os.makedirs(f'{dir}/network/{net["name"]}/switch/switch_settings')
        #Get all switch ACL settings
        switch_acl = dashboard.switch.getNetworkSwitchAccessControlLists(networkId=net['id'])
        with open(f'{dir}/network/{net["name"]}/switch/switch_settings/switch_acl.json', 'w') as fp:
            json.dump(switch_acl, fp)
            fp.close()
        operation['status'] = "Complete"
    except meraki.APIError as e:
        logger.error(e)
        operation['status'] = e
    return operation

def backupSwitchDhcpSecurity(net, dir, dashboard, logger):
    """
    Back up Switch DHCP Security
    :param net: Network to get Switch DHCP Security for
    :param dir: Path to backup
    :param dashboard: Meraki API Client
    :return: operation: operation performed and its status
    """
    operation = {"network": net, "operation_type": "switch", "operation": "backupSwitchDhcpSecurity", "status": ""}
    try:
        if not os.path.exists(dir):
            os.makedirs(dir)
        if not os.path.exists(f'{dir}/network'):
            os.makedirs(f'{dir}/network')
        if not os.path.exists(f'{dir}/network/{net["name"]}'):
            os.makedirs(f'{dir}/network/{net["name"]}')
        if not os.path.exists(f'{dir}/network/{net["name"]}/switch'):
            os.makedirs(f'{dir}/network/{net["name"]}/switch')
        if not os.path.exists(f'{dir}/network/{net["name"]}/switch/switch_settings'):
            os.makedirs(f'{dir}/network/{net["name"]}/switch/switch_settings')
        #Get all switch DHCP polioies
        dhcp_policies = dashboard.switch.getNetworkSwitchDhcpServerPolicy(networkId=net['id'])
        with open(f'{dir}/network/{net["name"]}/switch/switch_settings/dhcp_policies.json', 'w') as fp:
            json.dump(dhcp_policies, fp)
            fp.close()
        operation['status'] = "Complete"
    except meraki.APIError as e:
        logger.error(e)
        operation['status'] = e
    return operation

def backupMxSdWanSettings(net, dir, dashboard, logger):
    """
    Back up MX SDWAN Settings
    :param net: Network to get SDWAN settings for
    :param dir: Path to backup
    :param dashboard: Meraki API Client
    :return: operation: operation performed and its status
    """
    operation = {"network": net, "operation_type": "appliance", "operation": "backupMxSdWanSettings", "status": ""}
    try:
        if not os.path.exists(dir):
            os.makedirs(dir)
        if not os.path.exists(f'{dir}/network'):
            os.makedirs(f'{dir}/network')
        if not os.path.exists(f'{dir}/network/{net["name"]}'):
            os.makedirs(f'{dir}/network/{net["name"]}')
        if not os.path.exists(f'{dir}/network/{net["name"]}/appliance'):
            os.makedirs(f'{dir}/network/{net["name"]}/appliance')
        if not os.path.exists(f'{dir}/network/{net["name"]}/appliance/sdwan_settings'):
            os.makedirs(f'{dir}/network/{net["name"]}/appliance/sdwan_settings')
        #Get Uplink selection settings
        uplink_selection = dashboard.appliance.getNetworkApplianceTrafficShapingUplinkSelection(networkId=net['id'])
        with open(f'{dir}/network/{net["name"]}/appliance/sdwan_settings/uplink_selection.json', 'w') as fp:
            json.dump(uplink_selection, fp)
            fp.close()
        #Get Custom Performance Classes
        perf_classes = dashboard.appliance.getNetworkApplianceTrafficShapingCustomPerformanceClasses(networkId=net['id'])
        with open(f'{dir}/network/{net["name"]}/appliance/sdwan_settings/perf_classes.json', 'w') as fp:
            json.dump(perf_classes, fp)
            fp.close()
        #Get Uplink Bandwidth
        uplink_bandwidth = dashboard.appliance.getNetworkApplianceTrafficShapingUplinkBandwidth(networkId=net['id'])
        with open(f'{dir}/network/{net["name"]}/appliance/sdwan_settings/uplink_bandwidth.json', 'w') as fp:
            json.dump(uplink_bandwidth, fp)
            fp.close()
        operation['status'] = "Complete"
    except meraki.APIError as e:
        logger.error(e)
        operation['status'] = e
    return operation

def backupNetworkGroupPolicies(net, dir, dashboard, logger):
    """
    Back up Network Group Policies
    :param net: Network to get group policies for
    :param dir: Path to backup
    :param dashboard: Meraki API Client
    :return: operation: operation performed and its status
    """
    operation = {"network": net, "operation_type": "network", "operation": "backupNetworkGroupPolicies", "status": ""}
    try:
        if not os.path.exists(dir):
            os.makedirs(dir)
        if not os.path.exists(f'{dir}/network'):
            os.makedirs(f'{dir}/network')
        if not os.path.exists(f'{dir}/network/{net["name"]}'):
            os.makedirs(f'{dir}/network/{net["name"]}')
        if not os.path.exists(f'{dir}/network/{net["name"]}/group_policies'):
            os.makedirs(f'{dir}/network/{net["name"]}/group_policies')
        #Get all network group policies
        group_policies = dashboard.networks.getNetworkGroupPolicies(networkId=net['id'])
        with open(f'{dir}/network/{net["name"]}/group_policies/group_policies.json', 'w') as fp:
            json.dump(group_policies, fp)
            fp.close()
        operation['status'] = "Complete"
    except meraki.APIError as e:
        logger.error(e)
        operation['status'] = e
    return operation

def backupNetworkWebhooks(net, dir, dashboard, logger):
    """
    Back up Network Webhooks
    :param net: Network to get Webhooks for
    :param dir: Path to backup
    :param dashboard: Meraki API Client
    :return: operation: operation performed and its status
    """
    operation = {"network": net, "operation_type": "network", "operation": "backupNetworkWebhooks", "status": ""}
    try:
        if not os.path.exists(dir):
            os.makedirs(dir)
        if not os.path.exists(f'{dir}/network'):
            os.makedirs(f'{dir}/network')
        if not os.path.exists(f'{dir}/network/{net["name"]}'):
            os.makedirs(f'{dir}/network/{net["name"]}')
        if not os.path.exists(f'{dir}/network/{net["name"]}/webhooks'):
            os.makedirs(f'{dir}/network/{net["name"]}/webhooks')
        webhooks_servers = dashboard.networks.getNetworkWebhooksHttpServers(net['id'])
        webhooks_payload_templates = dashboard.networks.getNetworkWebhooksPayloadTemplates(net['id'])
        with open(f'{dir}/network/{net["name"]}/webhooks/webhooks_servers.json', 'w') as fp:
            json.dump(webhooks_servers, fp)
            fp.close()
        with open(f'{dir}/network/{net["name"]}/webhooks/webhooks_payload_templates.json', 'w') as fp:
            json.dump(webhooks_payload_templates, fp)
            fp.close()
        operation['status'] = "Complete"
    except meraki.APIError as e:
        logger.error(e)
        operation['status'] = e
    return operation


def backupNetworkSyslog(net, dir, dashboard, logger):
    """
    Back up Network Syslog
    :param net: Network to get Syslog for
    :param dir: Path to backup
    :param dashboard: Meraki API Client
    :return: operation: operation performed and its status
    """
    operation = {"network": net, "operation_type": "network", "operation": "backupNetworkSyslog", "status": ""}
    try:
        if not os.path.exists(dir):
            os.makedirs(dir)
        if not os.path.exists(f'{dir}/network'):
            os.makedirs(f'{dir}/network')
        if not os.path.exists(f'{dir}/network/{net["name"]}'):
            os.makedirs(f'{dir}/network/{net["name"]}')
        if not os.path.exists(f'{dir}/network/{net["name"]}/syslog'):
            os.makedirs(f'{dir}/network/{net["name"]}/syslog')
        syslog = dashboard.networks.getNetworkSyslogServers(net['id'])
        with open(f'{dir}/network/{net["name"]}/syslog/syslog.json', 'w') as fp:
            json.dump(syslog, fp)
            fp.close()
        operation['status'] = "Complete"
    except meraki.APIError as e:
        logger.error(e)
        operation['status'] = e
    return operation

def backupNetworkSnmp(net, dir, dashboard, logger):
    """
    Back up Network SNMP
    :param net: Network to get SNMP for
    :param dir: Path to backup
    :param dashboard: Meraki API Client
    :return: operation: operation performed and its status
    """
    operation = {"network": net, "operation_type": "network", "operation": "backupNetworkSnmp", "status": ""}
    try:
        if not os.path.exists(dir):
            os.makedirs(dir)
        if not os.path.exists(f'{dir}/network'):
            os.makedirs(f'{dir}/network')
        if not os.path.exists(f'{dir}/network/{net["name"]}'):
            os.makedirs(f'{dir}/network/{net["name"]}')
        if not os.path.exists(f'{dir}/network/{net["name"]}/snmp'):
            os.makedirs(f'{dir}/network/{net["name"]}/snmp')
        snmp = dashboard.networks.getNetworkSnmp(net['id'])
        with open(f'{dir}/network/{net["name"]}/snmp/snmp.json', 'w') as fp:
            json.dump(snmp, fp)
            fp.close()
        operation['status'] = "Complete"
    except meraki.APIError as e:
        logger.error(e)
        operation['status'] = e
    return operation

def backupNetworkFirmwareVersions(net, dir, dashboard, logger):
    """
    Back up Network Firmware Versions
    :param net: Network to get firmware versions for
    :param dir: Path to backup
    :param dashboard: Meraki API Client
    :return: operation: operation performed and its status
    """
    operation = {"network": net, "operation_type": "network", "operation": "backupNetworkFirmwareVersions", "status": ""}
    try:
        if not os.path.exists(dir):
            os.makedirs(dir)
        if not os.path.exists(f'{dir}/network'):
            os.makedirs(f'{dir}/network')
        if not os.path.exists(f'{dir}/network/{net["name"]}'):
            os.makedirs(f'{dir}/network/{net["name"]}')
        if not os.path.exists(f'{dir}/network/{net["name"]}/firmware'):
            os.makedirs(f'{dir}/network/{net["name"]}/firmware')
        firmware = dashboard.networks.getNetworkFirmwareUpgrades(net['id'])
        with open(f'{dir}/network/{net["name"]}/firmware/firmware.json', 'w') as fp:
            json.dump(firmware, fp)
            fp.close()
        operation['status'] = "Complete"
    except meraki.APIError as e:
        logger.error(e)
        operation['status'] = e
    return operation

def backupSwitchStaticRouting(net, dir, dashboard, logger):
    """
    Back up Switch Static Routes
    :param net: Network to get switch static routes for
    :param dir: Path to backup
    :param dashboard: Meraki API Client
    :return: operation: operation performed and its status
    """
    operation = {"network": net, "operation_type": "switch", "operation": "backupSwitchStaticRouting", "status": ""}
    try:
        if not os.path.exists(dir):
            os.makedirs(dir)
        if not os.path.exists(f'{dir}/network'):
            os.makedirs(f'{dir}/network')
        if not os.path.exists(f'{dir}/network/{net["name"]}'):
            os.makedirs(f'{dir}/network/{net["name"]}')
        if not os.path.exists(f'{dir}/network/{net["name"]}/switch'):
            os.makedirs(f'{dir}/network/{net["name"]}/switch')
        if not os.path.exists(f'{dir}/network/{net["name"]}/switch/switch_routing'):
            os.makedirs(f'{dir}/network/{net["name"]}/switch/switch_routing')
        # Get all devices in network
        devices = dashboard.networks.getNetworkDevices(networkId=net['id'])
        # If device is an MS that supports static routes, get their static routes
        for device in devices:
            if 'MS' in device['model'] and ('120' or '125') not in device['model']:
                static_routes = dashboard.switch.getDeviceSwitchRoutingStaticRoutes(serial=device['serial'])
                if not os.path.exists(f'{dir}/network/{net["name"]}/switch/switch_routing/{device["serial"]}'):
                    os.makedirs(f'{dir}/network/{net["name"]}/switch/switch_routing/{device["serial"]}')
                with open(f'{dir}/network/{net["name"]}/switch/switch_routing/{device["serial"]}/static_routes.json', 'w') as fp:
                    json.dump(static_routes, fp)
                    fp.close()
        operation['status'] = "Complete"
    except meraki.APIError as e:
        logger.error(e)
        operation['status'] = e
    return operation

def backupSwitchStormControl(net, dir, dashboard, logger):
    """
    Back up Switch Storm Control
    :param net: Network to get storm control for
    :param dir: Path to backup
    :param dashboard: Meraki API Client
    :return: operation: operation performed and its status
    """
    operation = {"network": net, "operation_type": "switch", "operation": "backupSwitchStormControl", "status": ""}
    try:
        if not os.path.exists(dir):
            os.makedirs(dir)
        if not os.path.exists(f'{dir}/network'):
            os.makedirs(f'{dir}/network')
        if not os.path.exists(f'{dir}/network/{net["name"]}'):
            os.makedirs(f'{dir}/network/{net["name"]}')
        if not os.path.exists(f'{dir}/network/{net["name"]}/switch'):
            os.makedirs(f'{dir}/network/{net["name"]}/switch')
        if not os.path.exists(f'{dir}/network/{net["name"]}/switch/switch_settings'):
            os.makedirs(f'{dir}/network/{net["name"]}/switch/switch_settings')
        # Get all switch Storm Control Settings
        switch_storm_control = dashboard.switch.getNetworkSwitchStormControl(networkId=net['id'])
        with open(f'{dir}/network/{net["name"]}/switch/switch_settings/switch_storm_control.json', 'w') as fp:
            json.dump(switch_storm_control, fp)
            fp.close()
        operation['status'] = "Complete"
    except meraki.APIError as e:
        logger.error(e)
        operation['status'] = e
    return operation

def backupOrganizationPolicyObjects(org, dir, dashboard, logger):
    """
    Back up organization Policy Objects
    :param org: Organization to get policy objects from
    :param dir: Path to backup
    :param dashboard: Meraki API Client
    :return: operation: operation performed and its status
    """
    operation = {"network": "Organization", "operation_type": "organization", "operation": "backupOrganizationPolicyObjects", "status": ""}
    try:
        if not os.path.exists(dir):
            os.makedirs(dir)
        if not os.path.exists(f'{dir}/organization'):
            os.makedirs(f'{dir}/organization')
        if not os.path.exists(f'{dir}/organization/policy_objects'):
            os.makedirs(f'{dir}/organization/policy_objects')
        # Get all Organization Policy Objects
        organization_policy_objects = dashboard.organizations.getOrganizationPolicyObjects(org['id'])
        organization_policy_objects_groups = dashboard.organizations.getOrganizationPolicyObjectsGroups(org['id'])
        with open(f'{dir}/organization/policy_objects/policy_objects.json', 'w') as fp:
            json.dump(organization_policy_objects, fp)
            fp.close()
        with open(f'{dir}/organization/policy_objects/policy_objects_groups.json', 'w') as fp:
            json.dump(organization_policy_objects_groups, fp)
            fp.close()
        operation['status'] = "Complete"
    except meraki.APIError as e:
        logger.error(e)
        operation['status'] = e
    return operation

def backupOrganizationMxVpnFirewall(org, dir, dashboard, logger):
    """
    Back up organization VPN Firewall rules
    :param org: Organization to get policy objects from
    :param dir: Path to backup
    :param dashboard: Meraki API Client
    :return: operation: operation performed and its status
    """
    operation = {"network": "Organization", "operation_type": "organization", "operation": "backupOrganizationVpnFirewall", "status": ""}
    try:
        if not os.path.exists(dir):
            os.makedirs(dir)
        if not os.path.exists(f'{dir}/organization'):
            os.makedirs(f'{dir}/organization')
        if not os.path.exists(f'{dir}/organization/vpn_firewall'):
            os.makedirs(f'{dir}/organization/vpn_firewall')
        # Get all Organization VPN Firewall
        organization_vpn_firewall = dashboard.appliance.getOrganizationApplianceVpnVpnFirewallRules(org['id'])
        with open(f'{dir}/organization/vpn_firewall/vpn_firewall.json', 'w') as fp:
            json.dump(organization_vpn_firewall, fp)
            fp.close()
        operation['status'] = "Complete"
    except meraki.APIError as e:
        logger.error(e)
        operation['status'] = e
    return operation

def backupOrganizationMxIpsecVpn(org, dir, dashboard, logger):
    """
    Back up organization VPN Firewall rules
    :param org: Organization to get policy objects from
    :param dir: Path to backup
    :param dashboard: Meraki API Client
    :return: operation: operation performed and its status
    """
    operation = {"network": "Organization", "operation_type": "organization", "operation": "backupOrganizationVpnFirewall", "status": ""}
    try:
        if not os.path.exists(dir):
            os.makedirs(dir)
        if not os.path.exists(f'{dir}/organization'):
            os.makedirs(f'{dir}/organization')
        if not os.path.exists(f'{dir}/organization/ipsec_vpn'):
            os.makedirs(f'{dir}/organization/ipsec_vpn')
        # Get all Organization IPsec VPN
        organization_ipsec_vpn = dashboard.appliance.getOrganizationApplianceVpnThirdPartyVPNPeers(org['id'])
        with open(f'{dir}/organization/ipsec_vpn/ipsec_vpn.json', 'w') as fp:
            json.dump(organization_ipsec_vpn, fp)
            fp.close()
        operation['status'] = "Complete"
    except meraki.APIError as e:
        logger.error(e)
        operation['status'] = e
    return operation

def backupMxBgp(net, dir, dashboard, logger):
    """
    Back up MX BGP Settings
    :param net: Network to get BGP settings for
    :param dir: Path to backup
    :param dashboard: Meraki API Client
    :return: operation: operation performed and its status
    """
    operation = {"network": net, "operation_type": "appliance", "operation": "backupMxBgpSettings", "status": ""}
    try:
        if not os.path.exists(dir):
            os.makedirs(dir)
        if not os.path.exists(f'{dir}/network'):
            os.makedirs(f'{dir}/network')
        if not os.path.exists(f'{dir}/network/{net["name"]}'):
            os.makedirs(f'{dir}/network/{net["name"]}')
        if not os.path.exists(f'{dir}/network/{net["name"]}/appliance'):
            os.makedirs(f'{dir}/network/{net["name"]}/appliance')
        if not os.path.exists(f'{dir}/network/{net["name"]}/appliance/bgp_settings'):
            os.makedirs(f'{dir}/network/{net["name"]}/appliance/bgp_settings')
        # Get BGP Settings
        bgp = dashboard.appliance.getNetworkApplianceVpnBgp(net['id'])
        with open(f'{dir}/network/{net["name"]}/appliance/bgp_settings/bgp.json', 'w') as fp:
            json.dump(bgp, fp)
            fp.close()
        operation['status'] = "Complete"
    except meraki.APIError as e:
        logger.error(e)
        operation['status'] = e
    return operation

def backupMxSettings(net, dir, dashboard, logger):
    """
    Back up MX Settings
    :param net: Network to get MX settings for
    :param dir: Path to backup
    :param dashboard: Meraki API Client
    :return: operation: operation performed and its status
    """
    settings = []
    operation = {"network": net, "operation_type": "appliance", "operation": "backupMxSettings", "status": ""}
    try:
        if not os.path.exists(dir):
            os.makedirs(dir)
        if not os.path.exists(f'{dir}/network'):
            os.makedirs(f'{dir}/network')
        if not os.path.exists(f'{dir}/network/{net["name"]}'):
            os.makedirs(f'{dir}/network/{net["name"]}')
        if not os.path.exists(f'{dir}/network/{net["name"]}/appliance'):
            os.makedirs(f'{dir}/network/{net["name"]}/appliance')
        if not os.path.exists(f'{dir}/network/{net["name"]}/appliance/settings'):
            os.makedirs(f'{dir}/network/{net["name"]}/appliance/settings')
        # Get MX Settings
        settings = dashboard.appliance.getNetworkApplianceSettings(net['id'])
        with open(f'{dir}/network/{net["name"]}/appliance/settings/settings.json', 'w') as fp:
            json.dump(settings, fp)
            fp.close()
        operation['status'] = "Complete"
    except meraki.APIError as e:
        logger.error(e)
        operation['status'] = e
    return settings, operation

def backupSwitchDai(net, dir, dashboard, logger):
    """
    Back up Switch Dynamic ARP Inspection Trusted Servers
    :param net: Network to get DAI settings for
    :param dir: Path to backup
    :param dashboard: Meraki API Client
    :return: operation: operation performed and its status
    """
    operation = {"network": net, "operation_type": "switch", "operation": "backupSwitchDai", "status": ""}
    try:
        if not os.path.exists(dir):
            os.makedirs(dir)
        if not os.path.exists(f'{dir}/network'):
            os.makedirs(f'{dir}/network')
        if not os.path.exists(f'{dir}/network/{net["name"]}'):
            os.makedirs(f'{dir}/network/{net["name"]}')
        if not os.path.exists(f'{dir}/network/{net["name"]}/switch'):
            os.makedirs(f'{dir}/network/{net["name"]}/switch')
        if not os.path.exists(f'{dir}/network/{net["name"]}/switch/switch_settings'):
            os.makedirs(f'{dir}/network/{net["name"]}/switch/switch_settings')
        # Get all switch Dynamic ARP Inspection Trusted Servers
        switch_dai = dashboard.switch.getNetworkSwitchDhcpServerPolicyArpInspectionTrustedServers(net['id'])
        with open(f'{dir}/network/{net["name"]}/switch/switch_settings/switch_dynamic_arp_inspection_servers.json', 'w') as fp:
            json.dump(switch_dai, fp)
            fp.close()
        operation['status'] = "Complete"
    except meraki.APIError as e:
        logger.error(e)
        operation['status'] = e
    return operation

def backupSwitchDscpCosMap(net, dir, dashboard, logger):
    """
        Back up Switch DSCP COS Map
        :param net: Network to get DSCP COS Mappings for
        :param dir: Path to backup
        :param dashboard: Meraki API Client
        :return: operation: operation performed and its status
        """
    operation = {"network": net, "operation_type": "switch", "operation": "backupSwitchDscpCosMap", "status": ""}
    try:
        if not os.path.exists(dir):
            os.makedirs(dir)
        if not os.path.exists(f'{dir}/network'):
            os.makedirs(f'{dir}/network')
        if not os.path.exists(f'{dir}/network/{net["name"]}'):
            os.makedirs(f'{dir}/network/{net["name"]}')
        if not os.path.exists(f'{dir}/network/{net["name"]}/switch'):
            os.makedirs(f'{dir}/network/{net["name"]}/switch')
        if not os.path.exists(f'{dir}/network/{net["name"]}/switch/switch_settings'):
            os.makedirs(f'{dir}/network/{net["name"]}/switch/switch_settings')
        # Get all switch DSCP to COS Map
        switch_dscp_cos = dashboard.switch.getNetworkSwitchDscpToCosMappings(net['id'])
        with open(f'{dir}/network/{net["name"]}/switch/switch_settings/switch_dscp_cos.json',
                  'w') as fp:
            json.dump(switch_dscp_cos, fp)
            fp.close()
        operation['status'] = "Complete"
    except meraki.APIError as e:
        logger.error(e)
        operation['status'] = e
    return operation

def backupSwitchLinkAggregations(net, dir, dashboard, logger):
    """
    Back up Switch Link Aggregations
    :param net: Network to get Link Aggs for
    :param dir: Path to backup
    :param dashboard: Meraki API Client
    :return: operation: operation performed and its status
    """
    operation = {"network": net, "operation_type": "switch", "operation": "backupSwitchLinkAggregations", "status": ""}
    try:
        if not os.path.exists(dir):
            os.makedirs(dir)
        if not os.path.exists(f'{dir}/network'):
            os.makedirs(f'{dir}/network')
        if not os.path.exists(f'{dir}/network/{net["name"]}'):
            os.makedirs(f'{dir}/network/{net["name"]}')
        if not os.path.exists(f'{dir}/network/{net["name"]}/switch'):
            os.makedirs(f'{dir}/network/{net["name"]}/switch')
        if not os.path.exists(f'{dir}/network/{net["name"]}/switch/switch_settings'):
            os.makedirs(f'{dir}/network/{net["name"]}/switch/switch_settings')
        # Get all switch Link Aggs
        switch_link_aggregations = dashboard.switch.getNetworkSwitchLinkAggregations(net['id'])
        with open(f'{dir}/network/{net["name"]}/switch/switch_settings/switch_link_aggregations.json',
                  'w') as fp:
            json.dump(switch_link_aggregations, fp)
            fp.close()
        operation['status'] = "Complete"
    except meraki.APIError as e:
        logger.error(e)
        operation['status'] = e
    return operation

def backupSwitchMtu(net, dir, dashboard, logger):
    """
    Back up Switch MTU Settings
    :param net: Network to get MTU Settings for
    :param dir: Path to backup
    :param dashboard: Meraki API Client
    :return: operation: operation performed and its status
    """
    operation = {"network": net, "operation_type": "switch", "operation": "backupSwitchMtu", "status": ""}
    try:
        if not os.path.exists(dir):
            os.makedirs(dir)
        if not os.path.exists(f'{dir}/network'):
            os.makedirs(f'{dir}/network')
        if not os.path.exists(f'{dir}/network/{net["name"]}'):
            os.makedirs(f'{dir}/network/{net["name"]}')
        if not os.path.exists(f'{dir}/network/{net["name"]}/switch'):
            os.makedirs(f'{dir}/network/{net["name"]}/switch')
        if not os.path.exists(f'{dir}/network/{net["name"]}/switch/switch_settings'):
            os.makedirs(f'{dir}/network/{net["name"]}/switch/switch_settings')
        # Get all switch MTU settings
        switch_mtu = dashboard.switch.getNetworkSwitchMtu(net['id'])
        with open(f'{dir}/network/{net["name"]}/switch/switch_settings/switch_mtu.json', 'w') as fp:
            json.dump(switch_mtu, fp)
            fp.close()
        operation['status'] = "Complete"
    except meraki.APIError as e:
        logger.error(e)
        operation['status'] = e
    return operation

def backupSwitchStacks(net, dir, dashboard, logger):
    """
    Back up Switch Stack Settings
    :param net: Network to get Stack Settings for
    :param dir: Path to backup
    :param dashboard: Meraki API Client
    :return: operation: operation performed and its status
    """
    operation = {"network": net, "operation_type": "switch", "operation": "backupSwitchStacks", "status": ""}
    try:
        if not os.path.exists(dir):
            os.makedirs(dir)
        if not os.path.exists(f'{dir}/network'):
            os.makedirs(f'{dir}/network')
        if not os.path.exists(f'{dir}/network/{net["name"]}'):
            os.makedirs(f'{dir}/network/{net["name"]}')
        if not os.path.exists(f'{dir}/network/{net["name"]}/switch'):
            os.makedirs(f'{dir}/network/{net["name"]}/switch')
        if not os.path.exists(f'{dir}/network/{net["name"]}/switch/switch_settings'):
            os.makedirs(f'{dir}/network/{net["name"]}/switch/switch_settings')
        # Get all switch Stack Settings
        switch_stacks = dashboard.switch.getNetworkSwitchStacks(net['id'])
        with open(f'{dir}/network/{net["name"]}/switch/switch_settings/switch_stacks.json',
                  'w') as fp:
            json.dump(switch_stacks, fp)
            fp.close()
        operation['status'] = "Complete"
    except meraki.APIError as e:
        logger.error(e)
        operation['status'] = e
    return operation

def backupSwitchRoutingMulticast(net, dir, dashboard, logger):
    """
    Back up Switch Multicast Settings
    :param net: Network to get Multicast Settings for
    :param dir: Path to backup
    :param dashboard: Meraki API Client
    :return: operation: operation performed and its status
    """
    operation = {"network": net, "operation_type": "switch", "operation": "backupSwitchRoutingMulticast", "status": ""}
    try:
        if not os.path.exists(dir):
            os.makedirs(dir)
        if not os.path.exists(f'{dir}/network'):
            os.makedirs(f'{dir}/network')
        if not os.path.exists(f'{dir}/network/{net["name"]}'):
            os.makedirs(f'{dir}/network/{net["name"]}')
        if not os.path.exists(f'{dir}/network/{net["name"]}/switch'):
            os.makedirs(f'{dir}/network/{net["name"]}/switch')
        if not os.path.exists(f'{dir}/network/{net["name"]}/switch/switch_routing'):
            os.makedirs(f'{dir}/network/{net["name"]}/switch/switch_routing')
        # Get all switch Multicast Settings
        switch_routing_multicast = dashboard.switch.getNetworkSwitchRoutingMulticast(net['id'])
        switch_routing_multicast_rps = dashboard.switch.getNetworkSwitchRoutingMulticastRendezvousPoints(net['id'])
        with open(f'{dir}/network/{net["name"]}/switch/switch_routing/switch_routing_multicast.json', 'w') as fp:
            json.dump(switch_routing_multicast, fp)
            fp.close()
        with open(f'{dir}/network/{net["name"]}/switch/switch_routing/switch_routing_multicast_rps.json', 'w') as fp:
            json.dump(switch_routing_multicast_rps, fp)
            fp.close()
        operation['status'] = "Complete"
    except meraki.APIError as e:
        logger.error(e)
        operation['status'] = e
    return operation

def backupMrBluetooth(net, dir, dashboard, logger):
    """
    Back up MR Bluetooth Configs
    :param net: Network to get Bluetooth configs for
    :param dir: Path to backup
    :param dashboard: Meraki API Client
    :return: operation: operation performed and its status
    """
    operation = {"network": net, "operation_type": "wireless", "operation": "backupMrBluetooth", "status": ""}
    try:
        # Check folder structure exists for switch settings, if not, create it
        if not os.path.exists(dir):
            os.makedirs(dir)
        if not os.path.exists(f'{dir}/network'):
            os.makedirs(f'{dir}/network')
        if not os.path.exists(f'{dir}/network/{net["name"]}'):
            os.makedirs(f'{dir}/network/{net["name"]}')
        if not os.path.exists(f'{dir}/network/{net["name"]}/wireless'):
            os.makedirs(f'{dir}/network/{net["name"]}/wireless')
        if not os.path.exists(f'{dir}/network/{net["name"]}/wireless/bluetooth_settings'):
            os.makedirs(f'{dir}/network/{net["name"]}/wireless/bluetooth_settings')
        network_bluetooth_settings = dashboard.wireless.getNetworkWirelessBluetoothSettings(net['id'])
        with open(f'{dir}/network/{net["name"]}/wireless/bluetooth_settings/network_bluetooth_settings.json', 'w') as fp:
            json.dump(network_bluetooth_settings, fp)
            fp.close()
        if network_bluetooth_settings['advertisingEnabled']==True:
            if network_bluetooth_settings['majorMinorAssignmentMode']=="Unique":
                # Get devices in network
                devices = dashboard.networks.getNetworkDevices(networkId=net['id'])
                # For every device that is an MR, get their bluetooth_settings settings
                for device in devices:
                    if 'MR' in device['model'] or device['model'] in ['CW9166I', 'CW9164I', 'CW9162I']:
                        try:
                            bluetooth_settings = dashboard.wireless.getDeviceWirelessBluetoothSettings(serial=device['serial'])
                            if not os.path.exists(f'{dir}/network/{net["name"]}/wireless/bluetooth_settings/{device["serial"]}'):
                                os.makedirs(f'{dir}/network/{net["name"]}/wireless/bluetooth_settings/{device["serial"]}')
                            with open(
                                    f'{dir}/network/{net["name"]}/wireless/bluetooth_settings/{device["serial"]}/bluetooth_settings.json',
                                    'w') as fp:
                                json.dump(bluetooth_settings, fp)
                                fp.close()
                        except meraki.APIError as e:
                            logger.error(e)
        operation['status'] = "Complete"
    except meraki.APIError as e:
        logger.error(e)
        operation['status'] = e
    return operation

def backupMrWirelessSettings(net, dir, dashboard, logger):
    """
    Back up MR Network Wireless Settings
    :param net: Network to get Network Wireless Settings for
    :param dir: Path to backup
    :param dashboard: Meraki API Client
    :return: operation: operation performed and its status
    """
    operation = {"network": net, "operation_type": "wireless", "operation": "backupMrWirelessSettings", "status": ""}
    try:
        if not os.path.exists(dir):
            os.makedirs(dir)
        if not os.path.exists(f'{dir}/network'):
            os.makedirs(f'{dir}/network')
        if not os.path.exists(f'{dir}/network/{net["name"]}'):
            os.makedirs(f'{dir}/network/{net["name"]}')
        if not os.path.exists(f'{dir}/network/{net["name"]}/wireless'):
            os.makedirs(f'{dir}/network/{net["name"]}/wireless')
        if not os.path.exists(f'{dir}/network/{net["name"]}/wireless/network_wireless_settings'):
            os.makedirs(f'{dir}/network/{net["name"]}/wireless/network_wireless_settings')
        network_wireless_settings = dashboard.wireless.getNetworkWirelessSettings(net['id'])
        with open(f'{dir}/network/{net["name"]}/wireless/network_wireless_settings/network_wireless_settings.json', 'w') as fp:
            json.dump(network_wireless_settings, fp)
            fp.close()
        operation['status'] = "Complete"
    except meraki.APIError as e:
        logger.error(e)
        operation['status'] = e
    return operation

def backupSwitchSettings(net, dir, dashboard, logger):
    """
    Back up Switch Multicast Settings
    :param net: Network to get Multicast Settings for
    :param dir: Path to backup
    :param dashboard: Meraki API Client
    :return: operation: operation performed and its status
    """
    operation = {"network": net, "operation_type": "switch", "operation": "backupSwitchSettings", "status": ""}
    try:
        if not os.path.exists(dir):
            os.makedirs(dir)
        if not os.path.exists(f'{dir}/network'):
            os.makedirs(f'{dir}/network')
        if not os.path.exists(f'{dir}/network/{net["name"]}'):
            os.makedirs(f'{dir}/network/{net["name"]}')
        if not os.path.exists(f'{dir}/network/{net["name"]}/switch'):
            os.makedirs(f'{dir}/network/{net["name"]}/switch')
        if not os.path.exists(f'{dir}/network/{net["name"]}/switch/switch_settings'):
            os.makedirs(f'{dir}/network/{net["name"]}/switch/switch_settings')
        # Get all switch Settings
        switch_settings = dashboard.switch.getNetworkSwitchSettings(net['id'])
        with open(f'{dir}/network/{net["name"]}/switch/switch_settings/switch_settings.json', 'w') as fp:
            json.dump(switch_settings, fp)
            fp.close()
        operation['status'] = "Complete"
    except meraki.APIError as e:
        logger.error(e)
        operation['status'] = e
    return operation

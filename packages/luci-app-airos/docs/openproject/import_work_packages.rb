#!/usr/bin/env ruby

require 'csv'
require 'json'
require 'net/http'
require 'uri'

BASE_URL = ENV.fetch('OPENPROJECT_URL', 'https://project.airpro.cloud').sub(%r{/$}, '')
PROJECT = ENV.fetch('OPENPROJECT_PROJECT', 'airpro-standalone-ui')
TOKEN = ENV.fetch('OPENPROJECT_TOKEN')
CSV_PATH = ARGV[0] || File.join(__dir__, 'AIRUI_WORK_PACKAGES.csv')
DRY_RUN = ENV['DRY_RUN'] == '1'
UPDATE_EXISTING = ENV['UPDATE_EXISTING'] == '1'

class OpenProject
  def initialize(base_url, token)
    @base = base_url
    @token = token
  end

  def get(path)
    request(Net::HTTP::Get, path)
  end

  def post(path, payload)
    request(Net::HTTP::Post, path, payload)
  end

  def patch(path, payload)
    request(Net::HTTP::Patch, path, payload)
  end

  private

  def request(klass, path, payload = nil)
    uri = URI("#{@base}#{path}")
    request = klass.new(uri)
    request.basic_auth('apikey', @token)
    request['Accept'] = 'application/hal+json'
    if payload
      request['Content-Type'] = 'application/json'
      request.body = JSON.generate(payload)
    end

    response = Net::HTTP.start(uri.hostname, uri.port, use_ssl: uri.scheme == 'https') do |http|
      http.request(request)
    end
    body = response.body.to_s.empty? ? {} : JSON.parse(response.body)
    return body if response.is_a?(Net::HTTPSuccess)

    message = body['message'] || body.dig('_embedded', 'errors') || response.body
    raise "#{response.code} #{response.message}: #{message}"
  end
end

def elements(collection)
  collection.dig('_embedded', 'elements') || []
end

def normalize(value)
  value.to_s.downcase.gsub(/[^a-z0-9]+/, ' ').strip
end

def find_named(items, preferred)
  names = preferred.map { |name| normalize(name) }
  items.find { |item| names.include?(normalize(item['name'])) }
end

def expected_output(row)
  object = row['UBUS Object'].to_s
  method = row['UBUS Method'].to_s
  outputs = {
    'airui.system.health' => 'An AirUI envelope whose data identifies the daemon, API/schema version, uptime and availability of each registered AirUI object.',
    'airui.system.capabilities' => 'An AirUI envelope containing hardware-derived platform and radio capabilities, supported bands, channels, widths and configurable features.',
    'airui.system.wan_management_config' => 'An AirUI envelope containing protocol, base interface, effective VLAN interface, VLAN ID, IPv4 address, netmask, gateway, DNS, lease and connection state.',
    'airui.system.wan_management_set' => 'A validation/apply envelope containing the normalized requested configuration, effective interface, changed UCI sections, warnings and any validation or rollback errors.',
    'airui.system.apply_status' => 'An AirUI envelope containing apply state, operation ID, affected services, elapsed time, rollback deadline and final result.',
    'airui.status.summary' => 'An AirUI envelope containing uplink, unique associated-client count, radios, uptime, CPU counters, physical core data, load, memory, storage and operating mode.',
    'airui.status.overview' => 'The same response schema and values as airui.status summary.',
    'airui.status.device_status' => 'An AirUI envelope containing device identity, firmware, platform, management addressing, wired uplink, radio state, serving SSIDs and live client counts.',
    'airui.status.clients' => 'An AirUI envelope containing deduplicated wireless and directly connected LAN client arrays with MAC, IP, hostname, OS, interface, SSID, RSSI and duration where available.',
    'airui.status.client_disconnect' => 'An AirUI envelope containing the requested MAC, resolved hostapd interface, disconnect command result and success or actionable failure details.',
    'airui.status.statistics' => 'An AirUI envelope containing CPU counters and core topology, load averages, memory, LAN RX/TX counters, radio survey utilization, retry data and per-SSID counters.',
    'airui.network.interface_config' => 'An AirUI envelope containing normalized network, DHCP and firewall UCI sections together with current interface runtime state.',
    'airui.network.interface_validate' => 'A dry-run envelope containing the normalized interface plan, planned UCI changes, warnings and field-level validation errors without modifying configuration.',
    'airui.network.interface_add' => 'An AirUI envelope containing the created logical interface, VLAN/bridge device, DHCP and firewall changes, plus commit requirements.',
    'airui.network.interface_set' => 'An AirUI envelope containing the updated logical interface and the exact network, DHCP and firewall changes applied or planned.',
    'airui.network.interface_delete' => 'An AirUI envelope listing removed sections, affected SSID mappings, retained dependencies and any blocked-deletion reason.',
    'airui.network.interface_apply' => 'An AirUI envelope containing committed packages, restarted services, rollback timer/state and final reachability result.',
    'airui.network.interface_map_ssid' => 'An AirUI envelope containing the wireless section, previous network, selected network and persistence result.',
    'airui.network.wireless_config' => 'An AirUI envelope containing radio and wifi-iface UCI values, runtime interfaces/stations and enterprise wireless metadata.',
    'airui.network.wireless_set' => 'An AirUI envelope containing normalized radio/SSID values, changed fields, validation warnings and save/apply result.',
    'airui.network.wireless_add' => 'An AirUI envelope containing the new wireless section, stable VIF identity, radio, SSID, network mapping and persistence result.',
    'airui.network.wireless_delete' => 'An AirUI envelope containing the deleted wireless section, released references and save/apply result.',
    'airui.network.lanwan_config' => 'An AirUI envelope containing LAN/WAN role assignments, routes, gateways, forwarding policy and effective runtime state.',
    'airui.network.lanwan_set' => 'An AirUI envelope containing validated route and role changes, affected services, rollback information and apply result.',
    'airui.mode.controller_status' => 'An AirUI envelope containing current mode, configuration source, controller type/address, discovery state, adoption state and safe-apply state.',
    'airui.security.rules' => 'An AirUI envelope containing configured access-control rules, normalized match/action fields and effective firewall state.',
    'airui.security.mac_filter_config' => 'An AirUI envelope containing each SSID filtering state, allow/deny mode, MAC entries and aggregate policy counts.',
    'airui.security.mac_filter_set' => 'An AirUI envelope containing the target SSID, normalized enabled/mode values, changed UCI fields and apply result.',
    'airui.security.mac_filter_entry_add' => 'An AirUI envelope containing the normalized MAC, label, target SSID, resulting entry list and duplicate/validation result.',
    'airui.security.mac_filter_entry_delete' => 'An AirUI envelope containing the target SSID, removed MAC, resulting entry list and persistence result.',
    'airui.maintenance.config' => 'An AirUI envelope containing installed firmware, platform, device identity, timezone and supported maintenance operations.',
    'airui.maintenance.device_management_get' => 'An AirUI envelope containing hostname, zonename, timezone, model, firmware and platform details.',
    'airui.maintenance.device_management_set' => 'An AirUI envelope containing normalized hostname/timezone values, changed UCI fields and save/apply result.',
    'airui.maintenance.logs' => 'An AirUI envelope containing bounded log records or text, collection timestamp, source and truncation metadata.',
    'airui.maintenance.reboot' => 'An AirUI envelope confirming validation/dry-run or accepted reboot scheduling before the connection closes.',
    'airui.maintenance.factory_reset' => 'An AirUI envelope confirming validation/dry-run or accepted reset scheduling; invalid confirmation returns a structured error.',
    'airui.maintenance.firmware_validate' => 'An AirUI envelope containing file metadata, checksum where available, image/platform compatibility, forceability, warnings and validation result.',
    'airui.maintenance.firmware_upgrade' => 'An AirUI envelope confirming validation and accepted upgrade scheduling, including keep-settings/force choices, before the connection closes.',
    'stamond.client.identity' => 'Identity data containing found, macaddr, ipAddress, hostname, osInfo and clientType.',
    'network.reload' => 'A UBUS success response when netifd accepts the reload request, or a transport/status error.',
    'file.write; stat; remove' => 'File-operation responses confirming bytes written, file metadata or removal, restricted to approved temporary firmware paths.'
  }

  exact = outputs["#{object}.#{method}"]
  return exact if exact

  if object.start_with?('hostapd.') && method == 'get_clients'
    return 'A station map keyed by MAC address containing association flags, signal/RSSI, byte counters, rates and connected time when exposed by the driver.'
  end
  if object.start_with?('hostapd.') && method == 'del_client'
    return 'A UBUS success response after hostapd accepts the disconnect, or a driver/association error identifying why the client was not removed.'
  end
  if object.start_with?('network.interface.') && method == 'status'
    return 'Runtime interface data containing up, pending, available, uptime, protocol, device, IPv4/IPv6 addresses, routes and DNS information.'
  end

  return row['Acceptance Criteria'] if row['Type'] == 'Phase'

  "A successful AirUI response envelope: `ok`, `data`, `warnings`, `errors`, and `meta`. The `data` payload must satisfy the acceptance criteria below."
end

def ubus_request(row)
  key = "#{row['UBUS Object']}.#{row['UBUS Method']}"
  requests = {
    'airui.system.wan_management_set' => { proto: 'dhcp', vlan_id: 0, dry_run: true },
    'airui.status.client_disconnect' => { macaddr: '26:80:68:AD:C7:6C' },
    'airui.network.interface_validate' => { type: 'vlan', name: 'guest', vlan_id: 10, parent_device: 'lan', bridge_name: 'br-guest', proto: 'static', ipaddr: '192.168.10.1', netmask: '255.255.255.0', dhcp: { enabled: true, start: 100, limit: 100, leasetime: '12h' }, firewall: { enabled: true, zone: 'guest', input: 'REJECT', output: 'ACCEPT', forward: 'REJECT', allow_dhcp: true, allow_dns: true, forward_to: 'wan', enable_masquerade_on_uplink: false }, dry_run: true },
    'airui.network.interface_add' => { type: 'vlan', name: 'guest', vlan_id: 10, parent_device: 'lan', bridge_name: 'br-guest', proto: 'static', ipaddr: '192.168.10.1', netmask: '255.255.255.0', dhcp: { enabled: true }, firewall: { enabled: true, zone: 'guest' }, dry_run: true },
    'airui.network.interface_set' => { type: 'vlan', name: 'guest', vlan_id: 10, parent_device: 'lan', bridge_name: 'br-guest', proto: 'static', ipaddr: '192.168.10.1', netmask: '255.255.255.0', dhcp: { enabled: true }, firewall: { enabled: true, zone: 'guest' }, dry_run: true },
    'airui.network.interface_delete' => { name: 'guest', delete_ssid_mappings: false, dry_run: true },
    'airui.network.interface_apply' => { commit: false, restart: false, services: ['network'], rollback_timeout: 60 },
    'airui.network.interface_map_ssid' => { section: 'wlan1', network: 'lan', dry_run: true },
    'airui.network.wireless_set' => { section: 'wlan1', type: 'wifi-iface', device: 'wifi1', mode: 'ap', disabled: false, ssid: 'Zeronet', encryption: 'psk2', network: 'lan', dry_run: true },
    'airui.network.wireless_add' => { section: 'wlan3', type: 'wifi-iface', device: 'wifi1', mode: 'ap', network: 'lan', ssid: 'Guest', encryption: 'psk2', disabled: false, dry_run: true },
    'airui.network.wireless_delete' => { section: 'wlan3', dry_run: true },
    'airui.security.mac_filter_set' => { section: 'wlan1', enabled: true, mode: 'deny', dry_run: true },
    'airui.security.mac_filter_entry_add' => { section: 'wlan1', mac: '26:80:68:AD:C7:6C', label: 'Test client', dry_run: true },
    'airui.security.mac_filter_entry_delete' => { section: 'wlan1', mac: '26:80:68:AD:C7:6C', dry_run: true },
    'airui.maintenance.device_management_set' => { hostname: 'AirPro-AP520', zonename: 'Asia/Kolkata', timezone: 'IST-5:30', dry_run: true },
    'airui.maintenance.reboot' => { dry_run: true },
    'airui.maintenance.factory_reset' => { dry_run: true, confirm: 'RESET' },
    'airui.maintenance.firmware_validate' => { path: '/tmp/firmware.bin' },
    'airui.maintenance.firmware_upgrade' => { path: '/tmp/firmware.bin', keep_settings: true, force: false, dry_run: true, confirm: 'UPGRADE' },
    'stamond.client.identity' => { macaddr: '26:80:68:AD:C7:6C' },
    'hostapd.<interface>.get_clients' => {},
    'hostapd.<interface>.del_client' => { addr: '26:80:68:AD:C7:6C', reason: 5, deauth: true, ban_time: 60000 },
    'network.interface.<name>.status' => {},
    'network.reload' => {},
    'file.write; stat; remove' => { path: '/tmp/firmware.bin' }
  }

  requests.fetch(key, {})
end

def ubus_command(row)
  object = row['UBUS Object'].to_s
  method = row['UBUS Method'].to_s
  return 'N/A — summary work package covering multiple methods.' if row['Type'] == 'Phase'
  return 'N/A — method is proposed and has not been registered yet.' if method.include?(';') || method.include?('future')

  payload = JSON.generate(ubus_request(row))
  callable_object = object.sub('hostapd.<interface>', 'hostapd.phy0-ap0').sub('network.interface.<name>', 'network.interface.lan')
  "ubus call #{callable_object} #{method} '#{payload}'"
end

def sample_response(row)
  return 'N/A — see the child work packages for method-level responses.' if row['Type'] == 'Phase'

  object = row['UBUS Object'].to_s
  method = row['UBUS Method'].to_s
  if object == 'stamond' && method == 'client.identity'
    return JSON.pretty_generate({ hostname: 'I2217', ipAddress: '192.168.23.164', osInfo: 'Android', clientType: 'wireless', found: true })
  end
  if object.start_with?('hostapd.')
    return JSON.pretty_generate({ result: 'Driver-specific hostapd response; verify against an associated test station.' })
  end
  if object.start_with?('network.interface.')
    return JSON.pretty_generate({ up: true, available: true, proto: 'static', device: 'br-lan', uptime: 3600, 'ipv4-address': [{ address: '192.168.1.2', mask: 24 }] })
  end
  if object == 'network' && method == 'reload'
    return JSON.pretty_generate({ result: 'Reload request accepted by netifd.' })
  end
  if object == 'file'
    return JSON.pretty_generate({ result: 'File operation accepted for the approved temporary path.' })
  end

  JSON.pretty_generate({
    ok: true,
    data: { result: expected_output(row) },
    warnings: [],
    errors: [],
    meta: { source: object, method: method }
  })
end

def description(row)
  value_or_na = lambda do |name|
    value = row[name].to_s
    value.empty? ? 'N/A' : value
  end

  <<~TEXT.strip
    **External ID:** #{row['External ID']}
    **Tab:** #{value_or_na.call('Tab')}
    **UI route:** #{value_or_na.call('UI Route')}
    **Frontend view:** #{value_or_na.call('Frontend View')}
    **UBUS object:** #{value_or_na.call('UBUS Object')}
    **UBUS method:** #{value_or_na.call('UBUS Method')}
    **Backend source:** #{value_or_na.call('Backend Source')}
    **Verification target:** #{value_or_na.call('Verification Target')}

    **UBUS command**

    ```sh
    #{ubus_command(row)}
    ```

    **Example output**

    ```json
    #{sample_response(row)}
    ```

    **Expected output details**

    #{expected_output(row)}

    **Acceptance criteria**

    #{value_or_na.call('Acceptance Criteria')}

    **Notes**

    #{row['Notes'].to_s.empty? ? 'None.' : row['Notes']}
  TEXT
end

api = OpenProject.new(BASE_URL, TOKEN)
project = api.get("/api/v3/projects/#{PROJECT}")
project_id = project['id']

types = elements(api.get("/api/v3/projects/#{project_id}/types"))
statuses = elements(api.get('/api/v3/statuses'))
priorities = elements(api.get('/api/v3/priorities'))
existing = elements(api.get("/api/v3/projects/#{project_id}/work_packages?pageSize=500"))

summary_type = find_named(types, ['Summary task', 'Phase']) || find_named(types, ['Task'])
task_type = find_named(types, ['Task']) || summary_type
raise 'No usable work-package type found' unless summary_type && task_type

status_preferences = {
  'Closed' => ['Closed', 'Done'],
  'In progress' => ['In progress', 'In Progress'],
  'New' => ['New', 'Open']
}
priority_preferences = {
  'Critical' => ['Immediate', 'Urgent', 'High'],
  'High' => ['High', 'Urgent'],
  'Normal' => ['Normal']
}

rows = CSV.read(CSV_PATH, headers: true).reject { |row| row['External ID'] == 'AIRUI-000' }
by_external_id = {}
existing_by_external_id = {}
existing.each do |work_package|
  external_id = work_package.dig('description', 'raw').to_s[/\*\*External ID:\*\*\s+(AIRUI-\d+)/, 1]
  if external_id
    by_external_id[external_id] = work_package['id']
    existing_by_external_id[external_id] = work_package
  end
end

rows.sort_by { |row| row['Parent ID'].to_s.empty? ? 0 : 1 }.each do |row|
  external_id = row['External ID']
  existing_work_package = existing_by_external_id[external_id]
  if existing_work_package && !UPDATE_EXISTING
    puts "SKIP #{external_id}: already exists as ##{by_external_id[external_id]}"
    next
  end

  parent_id = by_external_id[row['Parent ID']]
  if !row['Parent ID'].to_s.empty? && row['Parent ID'] != 'AIRUI-000' && !parent_id
    raise "Parent #{row['Parent ID']} has not been created for #{external_id}"
  end

  is_parent = row['Type'] == 'Phase'
  status = find_named(statuses, status_preferences.fetch(row['Status'], [row['Status']]))
  priority = find_named(priorities, priority_preferences.fetch(row['Priority'], [row['Priority']]))
  payload = {
    'subject' => row['Subject'],
    'description' => { 'format' => 'markdown', 'raw' => description(row) },
    '_links' => {
      'type' => { 'href' => "/api/v3/types/#{(is_parent ? summary_type : task_type)['id']}" },
      'project' => { 'href' => "/api/v3/projects/#{project_id}" }
    }
  }
  payload['_links']['status'] = { 'href' => "/api/v3/statuses/#{status['id']}" } if status
  payload['_links']['priority'] = { 'href' => "/api/v3/priorities/#{priority['id']}" } if priority
  payload['_links']['parent'] = { 'href' => "/api/v3/work_packages/#{parent_id}" } if parent_id

  if existing_work_package
    payload['lockVersion'] = existing_work_package['lockVersion']

    if DRY_RUN
      puts "UPDATE #{external_id}: ##{existing_work_package['id']} #{row['Subject']}"
    else
      updated = api.patch("/api/v3/work_packages/#{existing_work_package['id']}", payload)
      by_external_id[external_id] = updated['id']
      existing_by_external_id[external_id] = updated
      puts "UPDATED #{external_id} as ##{updated['id']}: #{row['Subject']}"
    end
  elsif DRY_RUN
    puts "CREATE #{external_id}: #{row['Subject']}#{parent_id ? " under ##{parent_id}" : ''}"
    by_external_id[external_id] = "dry-#{external_id}"
  else
    created = api.post("/api/v3/projects/#{project_id}/work_packages", payload)
    by_external_id[external_id] = created['id']
    puts "CREATED #{external_id} as ##{created['id']}: #{row['Subject']}"
  end
end

puts DRY_RUN ? 'Dry run complete; no work packages were changed.' : 'Import complete.'

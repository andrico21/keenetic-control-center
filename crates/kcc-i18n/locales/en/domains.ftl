# Router domain names: system, interfaces, Wi-Fi, clients, routing, VPN and services.

domains-system = System
domains-uptime = Uptime
domains-firmware = Firmware
domains-model = Model
domains-serial = Serial number
domains-cpu-load = CPU load
domains-memory = Memory
domains-interfaces = Interfaces
domains-interface-up = Up
domains-interface-down = Down
domains-wifi = Wi-Fi
domains-wifi-ssid = Network name (SSID)
domains-wifi-band = Band
domains-clients = Clients
domains-clients-online =
    { $count ->
        [one] { $count } client online
       *[other] { $count } clients online
    }
domains-routing = Routing
domains-static-routes = Static routes
domains-vpn = VPN
domains-vpn-tunnels = VPN tunnels
domains-firewall = Firewall
domains-dns = DNS
domains-dhcp = DHCP

# Machine-assisted translation - native review pending

domains-system = Система
domains-uptime = Время работы
domains-firmware = Прошивка
domains-model = Модель
domains-serial = Серийный номер
domains-cpu-load = Загрузка ЦП
domains-memory = Память
domains-interfaces = Интерфейсы
domains-interface-up = Активен
domains-interface-down = Неактивен
domains-wifi = Wi-Fi
domains-wifi-ssid = Имя сети (SSID)
domains-wifi-band = Диапазон
domains-clients = Клиенты
domains-clients-online =
    { $count ->
        [one] { $count } клиент в сети
        [few] { $count } клиента в сети
        [many] { $count } клиентов в сети
       *[other] { $count } клиента в сети
    }
domains-routing = Маршрутизация
domains-static-routes = Статические маршруты
domains-vpn = VPN
domains-vpn-tunnels = VPN-туннели
domains-firewall = Межсетевой экран
domains-dns = DNS
domains-dhcp = DHCP

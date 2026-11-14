# Machine-assisted translation - native review pending

errors-forbidden = У вас нет прав на это действие.
errors-auth-failed = Неверное имя пользователя или пароль.
errors-router-auth = Роутер отклонил учётные данные.
errors-timeout = Время ожидания операции истекло.
errors-outbound-refused = kcc не подключается к { $address }: адрес не входит в сети параметра [outbound] allowed_networks. Добавьте сеть роутера, например 192.168.1.0/24, в allowed_networks в kcc.toml (или суффикс его имени хоста в allowed_suffixes); запущенный kcc serve применит изменение после перезапуска. Адреса облачных метаданных запрещены всегда.
errors-outbound-metadata = kcc никогда не подключается к { $address }: это адрес облачных метаданных, его не разрешает ни один параметр.
errors-outbound-loopback = kcc не подключается к { $address }: для адресов обратной петли укажите [outbound] allow_loopback = true в kcc.toml; запущенный kcc serve применит изменение после перезапуска.
errors-outbound-never = kcc никогда не подключается к { $address }: адрес такого типа не разрешает ни один параметр.
errors-secret-file-permissions = Файл { $path } могут читать другие пользователи. Выполните chmod 600 { $path } и повторите попытку.

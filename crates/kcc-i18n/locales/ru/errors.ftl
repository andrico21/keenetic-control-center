# Machine-assisted translation - native review pending

errors-internal = Произошла внутренняя ошибка.
errors-not-found = Не найдено.
errors-forbidden = У вас нет прав на это действие.
errors-auth-failed = Неверное имя пользователя или пароль.
errors-account-locked = Слишком много неудачных попыток. Повторите через { $minutes } мин.
errors-router-unreachable = Роутер { $name } недоступен.
errors-router-auth = Роутер отклонил учётные данные.
errors-invalid-input = Недопустимое значение поля { $field }.
errors-unsupported-firmware = Прошивка { $version } не поддерживается.
errors-timeout = Время ожидания операции истекло.
errors-csrf = Срок действия формы истёк. Обновите страницу и повторите попытку.
errors-outbound-refused = kcc не подключается к { $address }: адрес не входит в сети параметра [outbound] allowed_networks. Добавьте сеть роутера, например 192.168.1.0/24, в allowed_networks в kcc.toml (или суффикс его имени хоста в allowed_suffixes); запущенный kcc serve применит изменение после перезапуска. Адреса облачных метаданных запрещены всегда.
errors-outbound-metadata = kcc никогда не подключается к { $address }: это адрес облачных метаданных, его не разрешает ни один параметр.
errors-outbound-loopback = kcc не подключается к { $address }: для адресов обратной петли укажите [outbound] allow_loopback = true в kcc.toml; запущенный kcc serve применит изменение после перезапуска.
errors-outbound-never = kcc никогда не подключается к { $address }: адрес такого типа не разрешает ни один параметр.

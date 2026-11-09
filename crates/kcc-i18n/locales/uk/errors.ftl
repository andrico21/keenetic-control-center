# Machine-assisted translation - native review pending

errors-internal = Сталася внутрішня помилка.
errors-not-found = Не знайдено.
errors-forbidden = У вас немає прав на цю дію.
errors-auth-failed = Неправильне імʼя користувача або пароль.
errors-account-locked = Забагато невдалих спроб. Спробуйте через { $minutes } хв.
errors-router-unreachable = Роутер { $name } недоступний.
errors-router-auth = Роутер відхилив облікові дані.
errors-invalid-input = Неприпустиме значення поля { $field }.
errors-unsupported-firmware = Прошивка { $version } не підтримується.
errors-timeout = Час очікування операції минув.
errors-csrf = Термін дії форми минув. Оновіть сторінку й спробуйте ще раз.
errors-outbound-refused = kcc не підключається до { $address }: адреса не входить до мереж параметра [outbound] allowed_networks. Додайте мережу роутера, наприклад 192.168.1.0/24, до allowed_networks у kcc.toml (або суфікс його імені хоста до allowed_suffixes); запущений kcc serve застосує зміну після перезапуску. Адреси хмарних метаданих заборонені завжди.
errors-outbound-metadata = kcc ніколи не підключається до { $address }: це адреса хмарних метаданих, її не дозволяє жоден параметр.
errors-outbound-loopback = kcc не підключається до { $address }: для адрес зворотного зв’язку вкажіть [outbound] allow_loopback = true у kcc.toml; запущений kcc serve застосує зміну після перезапуску.

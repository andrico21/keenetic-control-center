# Machine-assisted translation - native review pending

common-app-name = Keenetic Control Center
common-yes = Так
common-no = Ні
common-ok = ОК
common-cancel = Скасувати
common-save = Зберегти
common-apply = Застосувати
common-delete = Видалити
common-edit = Змінити
common-close = Закрити
common-back = Назад
common-enabled = Увімкнено
common-disabled = Вимкнено
common-unknown = Невідомо
common-language = Мова
common-items-count =
    { $count ->
        [one] { $count } елемент
        [few] { $count } елементи
        [many] { $count } елементів
       *[other] { $count } елемента
    }
common-unit-bytes = { $value } Б
common-unit-kilobytes = { $value } КБ
common-unit-megabytes = { $value } МБ
common-unit-gigabytes = { $value } ГБ
common-unit-terabytes = { $value } ТБ
common-unit-bits = { $value } біт/с
common-unit-kilobits = { $value } Кбіт/с
common-unit-megabits = { $value } Мбіт/с
common-unit-gigabits = { $value } Гбіт/с
common-percent = { $value }%
common-duration-days = { $count } дн.
common-duration-hours = { $count } год
common-duration-minutes = { $count } хв
common-duration-seconds = { $count } с

management-disarm-failed = Зміну налаштувань керування застосовано, але вимкнути таймер відновлення не вдалося. Вважайте таймер активним: він може відновити збережену конфігурацію та скасувати всі незбережені зміни. Перевірте роутер перед подальшими змінами.

management-outcome-unknown-armed = Невідомо, чи було застосовано зміну налаштувань керування. Таймер відновлення залишається активним і відновить збережену конфігурацію, скасувавши всі незбережені зміни.

management-mode-unknown = kcc не може визначити, як цей роутер відновиться після втрати зв’язку: він не повідомляє ні придатного режиму роботи, ні таймера відкату. Нічого не надіслано.

management-not-sent-armed = Нічого не змінено, але роутер, можливо, досі веде зворотний відлік до відкату або перезавантаження. Перевірте таймер відновлення, перш ніж пробувати знову.

management-not-applied = Нічого не застосовано, таймер відновлення вимкнено.

audit-entry-pending = Готово. Журнал аудиту зайнятий; запис про цю зміну буде додано, щойно він звільниться.

management-timer-in-use = Нічого не надіслано: таймер відновлення роутера вже запустив хтось інший. kcc залишає цей таймер його власникові. Спочатку підтвердьте або вимкніть його, потім спробуйте ще раз.

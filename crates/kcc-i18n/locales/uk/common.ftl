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

notify-router-down = [kcc] Роутер { $router } недоступний з { $time }.
notify-router-up = [kcc] Роутер { $router } знову доступний; він був недоступний { $duration }.
notify-router-login = [kcc] Роутер { $router } відхилив вхід kcc. Перевірте збережений для нього пароль.
notify-firmware = [kcc] Для роутера { $router } доступна прошивка { $version }.
notify-new-devices = [kcc] Нові незареєстровані пристрої на роутері { $router }: { $devices }.
notify-client-details = { $name } ({ $address })
notify-change-failed = [kcc] Зміну { $action } на роутері { $router } ({ $actor }) не виконано.
notify-change-failed-fleet = [kcc] Зміну { $action } ({ $actor }) не виконано.
notify-change-fail-safe = Таймер відновлення роутера досі зведений: якщо зміну не підтвердити, роутер поверне збережену конфігурацію.
notify-account-locked = [kcc] Обліковий запис { $user } заблоковано після невдалих входів до { $time }.
notify-audit-repaired = [kcc] Журнал аудиту відновлено: обірваний останній запис перенесено до { $file }.
notify-audit-stopped = [kcc] Запис журналу аудиту зупинився. kcc serve завершує роботу.
notify-job-failed = [kcc] Завдання { $kind } на роутері { $router } завершилося помилкою.
notify-job-failed-fleet = [kcc] Завдання { $kind } завершилося помилкою.
notify-dropped = [kcc] Сповіщення, які не вдалося вчасно доставити, відкинуто: { $count }.
notify-test = [kcc] Тестове повідомлення: сповіщення доходять до цього чату.
notify-scheduled-done-policy = [kcc] Запланована дія «{ $name }» на роутері { $router } увімкнула політику підключення { $policy }.
notify-scheduled-done-backup = [kcc] Запланована дія «{ $name }» на роутері { $router } зберегла резервну копію стартової конфігурації.
notify-scheduled-done-reboot = [kcc] Запланована дія «{ $name }» перезапустила роутер { $router }; він знову відповідає.
notify-scheduled-failed = [kcc] Запланована дія «{ $name }» на роутері { $router } завершилася помилкою: { $reason }.
notify-scheduled-skipped = [kcc] Запланована дія «{ $name }» на роутері { $router } не виконана: { $reason }.
notify-scheduled-missed = [kcc] Заплановану дію «{ $name }» на роутері { $router } не вдалося виконати вчасно; пропущено запусків: { $count }, останній о { $time }. Пропущені запуски не надолужуються.
notify-scheduled-paused = [kcc] Заплановану дію «{ $name }» на роутері { $router } призупинено: { $reason }.
notify-scheduled-interrupted = [kcc] Заплановану дію «{ $name }» на роутері { $router } перервано зупинкою kcc, і повторно вона не виконується.
notify-scheduled-unsaved = Не збережено; перезапуск роутера скасовує зміну.
notify-scheduled-reason-router-busy = роутер був зайнятий ще десять хвилин після запланованого часу
notify-scheduled-reason-client-unknown = клієнт не зареєстрований на роутері
notify-scheduled-reason-policy-unknown = на роутері немає політики підключення з такою назвою
notify-scheduled-reason-did-not-come-back = роутер не відповів знову протягом 15 хвилин
notify-scheduled-reason-preset-unavailable = шаблон неможливо застосувати
notify-scheduled-reason-owner-unavailable = її власник відсутній, вимкнений або більше не охоплює цей роутер
notify-scheduled-reason-forbidden = роль власника більше не дозволяє цю дію
notify-scheduled-reason-router-removed = роутер видалено з kcc
notify-scheduled-reason-other = помилка { $reason }

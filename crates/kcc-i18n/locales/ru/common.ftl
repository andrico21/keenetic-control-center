# Machine-assisted translation - native review pending

common-app-name = Keenetic Control Center
common-yes = Да
common-no = Нет
common-ok = ОК
common-cancel = Отмена
common-save = Сохранить
common-apply = Применить
common-delete = Удалить
common-edit = Изменить
common-close = Закрыть
common-back = Назад
common-enabled = Включено
common-disabled = Выключено
common-unknown = Неизвестно
common-language = Язык
common-items-count =
    { $count ->
        [one] { $count } элемент
        [few] { $count } элемента
        [many] { $count } элементов
       *[other] { $count } элемента
    }
common-unit-bytes = { $value } Б
common-unit-kilobytes = { $value } КБ
common-unit-megabytes = { $value } МБ
common-unit-gigabytes = { $value } ГБ
common-unit-terabytes = { $value } ТБ
common-unit-bits = { $value } бит/с
common-unit-kilobits = { $value } Кбит/с
common-unit-megabits = { $value } Мбит/с
common-unit-gigabits = { $value } Гбит/с
common-percent = { $value } %
common-duration-days = { $count } дн.
common-duration-hours = { $count } ч
common-duration-minutes = { $count } мин
common-duration-seconds = { $count } с

management-disarm-failed = Изменение настроек управления применено, но отключить таймер восстановления не удалось. Считайте таймер активным: он может восстановить сохранённую конфигурацию и отменить все несохранённые изменения. Проверьте роутер перед дальнейшими изменениями.

management-outcome-unknown-armed = Неизвестно, было ли применено изменение настроек управления. Таймер восстановления остаётся активным и восстановит сохранённую конфигурацию, отменив все несохранённые изменения.

management-mode-unknown = kcc не может определить, как этот роутер восстановится после потери связи: он не сообщает ни подходящего режима работы, ни таймера отката. Ничего не отправлено.

management-not-sent-armed = Ничего не изменено, но роутер, возможно, всё ещё ведёт обратный отсчёт до отката или перезагрузки. Проверьте таймер восстановления, прежде чем пробовать снова.

management-not-applied = Ничего не применено, таймер восстановления выключен.

audit-entry-pending = Готово. Журнал аудита занят; запись об этом изменении будет добавлена, как только он освободится.

management-timer-in-use = Ничего не отправлено: таймер восстановления роутера уже запущен кем-то другим. kcc оставляет этот таймер его владельцу. Сначала подтвердите или отключите его, затем повторите попытку.

notify-router-down = [kcc] Роутер { $router } недоступен с { $time }.
notify-router-up = [kcc] Роутер { $router } снова доступен; он был недоступен { $duration }.
notify-router-login = [kcc] Роутер { $router } отклонил вход kcc. Проверьте сохранённый для него пароль.
notify-firmware = [kcc] Для роутера { $router } доступна прошивка { $version }.
notify-new-devices = [kcc] Новые незарегистрированные устройства на роутере { $router }: { $devices }.
notify-client-details = { $name } ({ $address })
notify-change-failed = [kcc] Изменение { $action } на роутере { $router } ({ $actor }) не выполнено.
notify-change-failed-fleet = [kcc] Изменение { $action } ({ $actor }) не выполнено.
notify-change-fail-safe = Таймер восстановления роутера всё ещё взведён: если изменение не подтвердить, роутер вернёт сохранённую конфигурацию.
notify-account-locked = [kcc] Учётная запись { $user } заблокирована после неудачных входов до { $time }.
notify-audit-repaired = [kcc] Журнал аудита восстановлен: оборванная последняя запись перенесена в { $file }.
notify-audit-stopped = [kcc] Запись журнала аудита остановилась. kcc serve завершает работу.
notify-job-failed = [kcc] Задание { $kind } на роутере { $router } завершилось ошибкой.
notify-job-failed-fleet = [kcc] Задание { $kind } завершилось ошибкой.
notify-dropped = [kcc] Уведомления, которые не удалось вовремя доставить, отброшены: { $count }.
notify-test = [kcc] Тестовое сообщение: уведомления доходят до этого чата.

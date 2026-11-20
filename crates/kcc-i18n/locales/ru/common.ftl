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
notify-scheduled-done-policy = [kcc] Запланированное действие «{ $name }» на роутере { $router } включило политику подключения { $policy }.
notify-scheduled-done-backup = [kcc] Запланированное действие «{ $name }» на роутере { $router } сохранило резервную копию стартовой конфигурации.
notify-scheduled-done-reboot = [kcc] Запланированное действие «{ $name }» перезапустило роутер { $router }; он снова отвечает.
notify-scheduled-failed = [kcc] Запланированное действие «{ $name }» на роутере { $router } завершилось ошибкой: { $reason }.
notify-scheduled-skipped = [kcc] Запланированное действие «{ $name }» на роутере { $router } не выполнено: { $reason }.
notify-scheduled-missed = [kcc] Запланированное действие «{ $name }» на роутере { $router } не удалось выполнить вовремя; пропущено запусков: { $count }, последний в { $time }. Пропущенные запуски не наверстываются.
notify-scheduled-paused = [kcc] Запланированное действие «{ $name }» на роутере { $router } приостановлено: { $reason }.
notify-scheduled-interrupted = [kcc] Запланированное действие «{ $name }» на роутере { $router } прервано остановкой kcc и повторно не выполняется.
notify-scheduled-unsaved = Не сохранено; перезапуск роутера отменяет изменение.
notify-scheduled-reason-router-busy = роутер был занят ещё десять минут после запланированного времени
notify-scheduled-reason-client-unknown = клиент не зарегистрирован на роутере
notify-scheduled-reason-policy-unknown = на роутере нет политики подключения с таким именем
notify-scheduled-reason-did-not-come-back = роутер не ответил снова в течение 15 минут
notify-scheduled-reason-preset-unavailable = шаблон нельзя применить
notify-scheduled-reason-owner-unavailable = его владелец отсутствует, отключён или больше не охватывает этот роутер
notify-scheduled-reason-forbidden = роль владельца больше не разрешает это действие
notify-scheduled-reason-router-removed = роутер удалён из kcc
notify-scheduled-reason-other = ошибка { $reason }
notify-scheduled-done-preset = [kcc] Запланированное действие «{ $name }» на роутере { $router } применило шаблон { $preset } и проверило его.
notify-scheduled-reason-firmware = прошивка роутера старше, чем у шаблона, или не поддерживается
notify-scheduled-reason-documentation-tier = роутер работает на линейке прошивки, поддержанной только по документации, а расписание этого не подтверждает
notify-scheduled-reason-not-ready = шаблону нужны данные или он конфликтует с конфигурацией роутера
notify-scheduled-reason-management-lines = шаблон меняет то, как kcc подключается к роутеру или входит в него
notify-scheduled-reason-wireguard-key = шаблон задаёт закрытый ключ WireGuard
notify-scheduled-reason-preset-failed = шаблон не удалось применить
notify-scheduled-reason-preset-failed-armed = шаблон не удалось применить; аварийный таймер роутера может быть ещё взведён и тогда перезапустит роутер с сохранённой конфигурацией
notify-scheduled-reason-preset-rolled-back = изменения не прошли проверку и откачены к сохранённой конфигурации
notify-scheduled-reason-preset-restored = запуск не удалось завершить; роутер восстановил сохранённую конфигурацию
notify-scheduled-reason-preset-state-unknown = запуск не удалось завершить, и состояние роутера неизвестно; проверьте роутер

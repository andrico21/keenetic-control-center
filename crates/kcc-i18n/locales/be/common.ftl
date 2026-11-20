# Machine-assisted translation - native review pending

common-app-name = Keenetic Control Center
common-yes = Так
common-no = Не
common-ok = ОК
common-cancel = Скасаваць
common-save = Захаваць
common-apply = Ужыць
common-delete = Выдаліць
common-edit = Змяніць
common-close = Закрыць
common-back = Назад
common-enabled = Уключана
common-disabled = Выключана
common-unknown = Невядома
common-language = Мова
common-items-count =
    { $count ->
        [one] { $count } элемент
        [few] { $count } элементы
        [many] { $count } элементаў
       *[other] { $count } элемента
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
common-percent = { $value } %
common-duration-days = { $count } дн.
common-duration-hours = { $count } гадз
common-duration-minutes = { $count } хв
common-duration-seconds = { $count } с

management-disarm-failed = Змена налад кіравання ўжыта, але адключыць таймер аднаўлення не ўдалося. Лічыце таймер актыўным: ён можа аднавіць захаваную канфігурацыю і скасаваць усе незахаваныя змены. Праверце роўтар перад далейшымі зменамі.

management-outcome-unknown-armed = Невядома, ці была ўжыта змена налад кіравання. Таймер аднаўлення застаецца актыўным і адновіць захаваную канфігурацыю, скасаваўшы ўсе незахаваныя змены.

management-mode-unknown = kcc не можа вызначыць, як гэты роўтар аднавіцца пасля страты сувязі: ён не паведамляе ні прыдатнага рэжыму працы, ні таймера адкату. Нічога не адпраўлена.

management-not-sent-armed = Нічога не зменена, але роўтар, магчыма, усё яшчэ вядзе зваротны адлік да адкату або перазагрузкі. Праверце таймер аднаўлення, перш чым спрабаваць зноў.

management-not-applied = Нічога не прыменена, таймер аднаўлення выключаны.

audit-entry-pending = Гатова. Журнал аўдыту заняты; запіс пра гэтую змену будзе дададзены, як толькі ён вызваліцца.

management-timer-in-use = Нічога не адпраўлена: таймер аднаўлення роўтара ўжо запусціў нехта іншы. kcc пакідае гэты таймер яго ўладальніку. Спачатку пацвердзіце або адключыце яго, потым паспрабуйце зноў.

notify-router-down = [kcc] Роўтар { $router } недаступны з { $time }.
notify-router-up = [kcc] Роўтар { $router } зноў даступны; ён быў недаступны { $duration }.
notify-router-login = [kcc] Роўтар { $router } адхіліў уваход kcc. Праверце захаваны для яго пароль.
notify-firmware = [kcc] Для роўтара { $router } даступная прашыўка { $version }.
notify-new-devices = [kcc] Новыя незарэгістраваныя прылады на роўтары { $router }: { $devices }.
notify-client-details = { $name } ({ $address })
notify-change-failed = [kcc] Змяненне { $action } на роўтары { $router } ({ $actor }) не выканана.
notify-change-failed-fleet = [kcc] Змяненне { $action } ({ $actor }) не выканана.
notify-change-fail-safe = Таймер аднаўлення роўтара ўсё яшчэ ўзведзены: калі змяненне не пацвердзіць, роўтар верне захаваную канфігурацыю.
notify-account-locked = [kcc] Уліковы запіс { $user } заблакаваны пасля няўдалых уваходаў да { $time }.
notify-audit-repaired = [kcc] Журнал аўдыту адноўлены: абарваны апошні запіс перанесены ў { $file }.
notify-audit-stopped = [kcc] Запіс журнала аўдыту спыніўся. kcc serve завяршае працу.
notify-job-failed = [kcc] Заданне { $kind } на роўтары { $router } завяршылася памылкай.
notify-job-failed-fleet = [kcc] Заданне { $kind } завяршылася памылкай.
notify-dropped = [kcc] Апавяшчэнні, якія не ўдалося своечасова даставіць, адкінуты: { $count }.
notify-test = [kcc] Тэставае паведамленне: апавяшчэнні даходзяць да гэтага чата.

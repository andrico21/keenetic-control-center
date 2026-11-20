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
notify-scheduled-done-policy = [kcc] Запланаванае дзеянне «{ $name }» на роўтары { $router } уключыла палітыку падключэння { $policy }.
notify-scheduled-done-backup = [kcc] Запланаванае дзеянне «{ $name }» на роўтары { $router } захавала рэзервовую копію стартавай канфігурацыі.
notify-scheduled-done-reboot = [kcc] Запланаванае дзеянне «{ $name }» перазапусціла роўтар { $router }; ён зноў адказвае.
notify-scheduled-failed = [kcc] Запланаванае дзеянне «{ $name }» на роўтары { $router } завяршылася памылкай: { $reason }.
notify-scheduled-skipped = [kcc] Запланаванае дзеянне «{ $name }» на роўтары { $router } не выканана: { $reason }.
notify-scheduled-missed = [kcc] Запланаванае дзеянне «{ $name }» на роўтары { $router } не ўдалося выканаць своечасова; прапушчана запускаў: { $count }, апошні ў { $time }. Прапушчаныя запускі не наганяюцца.
notify-scheduled-paused = [kcc] Запланаванае дзеянне «{ $name }» на роўтары { $router } прыпынена: { $reason }.
notify-scheduled-interrupted = [kcc] Запланаванае дзеянне «{ $name }» на роўтары { $router } перапынена спыненнем kcc і паўторна не выконваецца.
notify-scheduled-unsaved = Не захавана; перазапуск роўтара адмяняе змяненне.
notify-scheduled-reason-router-busy = роўтар быў заняты яшчэ дзесяць хвілін пасля запланаванага часу
notify-scheduled-reason-client-unknown = кліент не зарэгістраваны на роўтары
notify-scheduled-reason-policy-unknown = на роўтары няма палітыкі падключэння з такой назвай
notify-scheduled-reason-did-not-come-back = роўтар не адказаў зноў на працягу 15 хвілін
notify-scheduled-reason-preset-unavailable = шаблон нельга ўжыць
notify-scheduled-reason-owner-unavailable = яго ўладальнік адсутнічае, адключаны або больш не ахоплівае гэты роўтар
notify-scheduled-reason-forbidden = роля ўладальніка больш не дазваляе гэта дзеянне
notify-scheduled-reason-router-removed = роўтар выдалены з kcc
notify-scheduled-reason-other = памылка { $reason }
notify-scheduled-done-preset = [kcc] Запланаванае дзеянне «{ $name }» на роўтары { $router } ужыла шаблон { $preset } і праверыла яго.
notify-scheduled-reason-firmware = прашыўка роўтара старэйшая, чым у шаблона, або не падтрымліваецца
notify-scheduled-reason-documentation-tier = роўтар працуе на лінейцы прашыўкі, падтрыманай толькі па дакументацыі, а расклад гэтага не пацвярджае
notify-scheduled-reason-not-ready = шаблону патрэбныя даныя або ён канфліктуе з канфігурацыяй роўтара
notify-scheduled-reason-management-lines = шаблон мяняе тое, як kcc падключаецца да роўтара або ўваходзіць у яго
notify-scheduled-reason-wireguard-key = шаблон задае закрыты ключ WireGuard
notify-scheduled-reason-preset-failed = шаблон не ўдалося ўжыць
notify-scheduled-reason-preset-failed-armed = шаблон не ўдалося ўжыць; аварыйны таймер роўтара можа быць яшчэ ўключаны і тады перазапусціць роўтар з захаванай канфігурацыяй
notify-scheduled-reason-preset-rolled-back = змяненні не прайшлі праверку і адкочаны да захаванай канфігурацыі
notify-scheduled-reason-preset-restored = запуск не ўдалося завяршыць; роўтар аднавіў захаваную канфігурацыю
notify-scheduled-reason-preset-state-unknown = запуск не ўдалося завяршыць, і стан роўтара невядомы; праверце роўтар

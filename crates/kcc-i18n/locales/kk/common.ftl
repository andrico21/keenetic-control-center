# Machine-assisted translation - native review pending

common-app-name = Keenetic Control Center
common-yes = Иә
common-no = Жоқ
common-ok = ОК
common-cancel = Бас тарту
common-save = Сақтау
common-apply = Қолдану
common-delete = Жою
common-edit = Өңдеу
common-close = Жабу
common-back = Артқа
common-enabled = Қосулы
common-disabled = Өшірулі
common-unknown = Белгісіз
common-language = Тіл
common-items-count =
    { $count ->
        [one] { $count } элемент
       *[other] { $count } элемент
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
common-percent = { $value }%
common-duration-days = { $count } күн
common-duration-hours = { $count } сағ
common-duration-minutes = { $count } мин
common-duration-seconds = { $count } с

management-disarm-failed = Басқару параметрлерінің өзгерісі қолданылды, бірақ қалпына келтіру таймерін өшіру мүмкін болмады. Таймерді әлі қосулы деп есептеңіз: ол сақталған конфигурацияны қалпына келтіріп, барлық сақталмаған өзгерістерді жоюы мүмкін. Қосымша өзгерістер енгізбес бұрын роутерді тексеріңіз.

management-outcome-unknown-armed = Басқару параметрлерінің өзгерісі қолданылғаны белгісіз. Қалпына келтіру таймері қосулы қалады және барлық сақталмаған өзгерістерді жойып, сақталған конфигурацияны қалпына келтіреді.

management-mode-unknown = kcc байланыс үзілгеннен кейін бұл роутердің қалай қалпына келетінін анықтай алмайды: ол жарамды жұмыс режимін де, қайтару таймерін де хабарламайды. Ештеңе жіберілмеді.

management-not-sent-armed = Ештеңе өзгертілмеді, бірақ роутер әлі де кері қайтаруға немесе қайта жүктеуге дейін кері санақ жүргізіп жатуы мүмкін. Қайта әрекет етпес бұрын қалпына келтіру таймерін тексеріңіз.

management-not-applied = Ештеңе қолданылмады, қалпына келтіру таймері өшірулі.

audit-entry-pending = Дайын. Аудит журналы бос емес; бұл өзгеріс туралы жазба ол босаған бойда жазылады.

management-timer-in-use = Ештеңе жіберілмеді: роутердің қалпына келтіру таймерін басқа біреу іске қосып қойған. kcc бұл таймерді оның иесіне қалдырады. Алдымен оны растаңыз немесе өшіріңіз, содан кейін қайталап көріңіз.

notify-router-down = [kcc] { $router } роутері { $time } бастап қолжетімсіз.
notify-router-up = [kcc] { $router } роутері қайта қолжетімді; ол { $duration } бойы қолжетімсіз болды.
notify-router-login = [kcc] { $router } роутері kcc кіруінен бас тартты. Ол үшін сақталған құпиясөзді тексеріңіз.
notify-firmware = [kcc] { $router } роутері үшін { $version } микробағдарламасы қолжетімді.
notify-new-devices = [kcc] { $router } роутеріндегі тіркелмеген жаңа құрылғылар: { $devices }.
notify-client-details = { $name } ({ $address })
notify-change-failed = [kcc] { $router } роутеріндегі { $action } өзгерісі ({ $actor }) орындалмады.
notify-change-failed-fleet = [kcc] { $action } өзгерісі ({ $actor }) орындалмады.
notify-change-fail-safe = Роутердің қалпына келтіру таймері әлі қосулы: өзгеріс расталмаса, роутер сақталған конфигурацияны қайтарады.
notify-account-locked = [kcc] { $user } тіркелгісі сәтсіз кірулерден кейін { $time } дейін бұғатталды.
notify-audit-repaired = [kcc] Аудит журналы қалпына келтірілді: үзілген соңғы жазба { $file } файлына жылжытылды.
notify-audit-stopped = [kcc] Аудит журналын жазу тоқтады. kcc serve жұмысын аяқтап жатыр.
notify-job-failed = [kcc] { $router } роутеріндегі { $kind } тапсырмасы қатемен аяқталды.
notify-job-failed-fleet = [kcc] { $kind } тапсырмасы қатемен аяқталды.
notify-dropped = [kcc] Уақытында жеткізілмеген хабарландырулар тасталды: { $count }.
notify-test = [kcc] Сынақ хабары: хабарландырулар осы чатқа жетеді.

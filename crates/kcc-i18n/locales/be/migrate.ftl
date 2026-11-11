# Machine-assisted translation - native review pending

migrate-title = Перанос канфігурацыі
migrate-source = Зыходны роўтар
migrate-target = Мэтавы роўтар
migrate-plan = План пераносу
migrate-step = Крок { $current } з { $total }
migrate-unsupported =
    { $count ->
        [one] { $count } параметр нельга перанесці
        [few] { $count } параметры нельга перанесці
        [many] { $count } параметраў нельга перанесці
       *[other] { $count } параметра нельга перанесці
    }
migrate-start = Пачаць перанос
migrate-done = Перанос завершаны.
migrate-rollback = Адкаціць
migrate-backup-created = Рэзервовая копія канфігурацыі мэтавага роўтара захавана.
migrate-reason-copy = Скапіявана без змен.
migrate-reason-remap = Скапіявана з выбраным супастаўленнем.
migrate-reason-skip-hardware = Прапушчана як налада абсталявання крыніцы.
migrate-reason-skip-identity = Прапушчана як ідэнтыфікатар крыніцы.
migrate-reason-needs-input = Патрабуецца рашэнне аператара.
migrate-reason-unsupported = Мэтавы роўтар не падтрымлівае гэту наладу.
migrate-reason-prune = Выдалена паводле выбару аператара.
migrate-apply-verified = Перанос правераны. Выберыце захаванне або адкат; змены яшчэ не захаваны.
migrate-apply-failed = Перанос спынены. Праверце вынік перад адкатам.
migrate-job-start-failed = Не ўдалося запусціць заданне. Паўтарыце каманду.
migrate-apply-restored = Праверка пераносу скончылася памылкай. kcc аўтаматычна выканаў адкат і аднавіў стартавую канфігурацыю.
migrate-apply-router-rollback = Роўтар аднавіў захаваную канфігурацыю пасля заканчэння таймера аднаўлення.
migrate-apply-tier = Пацвердзіце перанос на прашыўку, падтрымка якой заснавана толькі на дакументацыі.
migrate-apply-agreement = Пацвердзіце бягучае пагадненне роўтара перад працягам.
migrate-apply-residual = Захавана налад толькі мэтавага роўтара: { $count }.
finish-saved-armed = Канфігурацыя захавана, але адключыць таймер аднаўлення не ўдалося. Лічыце таймер актыўным: роўтар можа перазагрузіцца з захаванай канфігурацыяй, якая змяшчае гэтыя змены.
migrate-committed-not-saved = Міграцыя дзейнічае, таймер аднаўлення адключаны, але стартавая канфігурацыя не захавана. Паўтарыце фіксацыю, каб захаваць яе.
migrate-rollback-saved = Роўтар перазагружаецца з захаванай канфігурацыяй, якая ўжо можа змяшчаць перанесеныя налады.

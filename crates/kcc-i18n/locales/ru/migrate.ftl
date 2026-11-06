# Machine-assisted translation - native review pending

migrate-title = Перенос конфигурации
migrate-source = Исходный роутер
migrate-target = Целевой роутер
migrate-plan = План переноса
migrate-step = Шаг { $current } из { $total }
migrate-unsupported =
    { $count ->
        [one] { $count } параметр нельзя перенести
        [few] { $count } параметра нельзя перенести
        [many] { $count } параметров нельзя перенести
       *[other] { $count } параметра нельзя перенести
    }
migrate-start = Начать перенос
migrate-done = Перенос завершён.
migrate-rollback = Откатить
migrate-backup-created = Резервная копия конфигурации целевого роутера сохранена.
migrate-reason-copy = Скопировано без изменений.
migrate-reason-remap = Скопировано с выбранным сопоставлением.
migrate-reason-skip-hardware = Пропущено как настройка оборудования источника.
migrate-reason-skip-identity = Пропущено как идентификатор источника.
migrate-reason-needs-input = Требуется решение оператора.
migrate-reason-unsupported = Целевой роутер не поддерживает эту настройку.
migrate-reason-prune = Удалено по выбору оператора.
migrate-apply-verified = Перенос проверен. Выберите сохранение или откат; изменения ещё не сохранены.
migrate-apply-failed = Перенос остановлен. Проверьте результат перед откатом.
migrate-apply-router-rollback = Роутер восстановил сохранённую конфигурацию после истечения таймера восстановления.
migrate-apply-tier = Подтвердите перенос на прошивку, поддержка которой основана только на документации.
migrate-apply-agreement = Подтвердите текущее соглашение роутера перед продолжением.
migrate-apply-residual = Сохранено настроек только целевого роутера: { $count }.

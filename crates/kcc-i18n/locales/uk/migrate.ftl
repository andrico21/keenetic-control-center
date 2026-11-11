# Machine-assisted translation - native review pending

migrate-title = Перенесення конфігурації
migrate-source = Вихідний роутер
migrate-target = Цільовий роутер
migrate-plan = План перенесення
migrate-step = Крок { $current } з { $total }
migrate-unsupported =
    { $count ->
        [one] { $count } параметр не можна перенести
        [few] { $count } параметри не можна перенести
        [many] { $count } параметрів не можна перенести
       *[other] { $count } параметра не можна перенести
    }
migrate-start = Почати перенесення
migrate-done = Перенесення завершено.
migrate-rollback = Відкотити
migrate-backup-created = Резервну копію конфігурації цільового роутера збережено.
migrate-reason-copy = Скопійовано без змін.
migrate-reason-remap = Скопійовано з вибраним зіставленням.
migrate-reason-skip-hardware = Пропущено як налаштування обладнання джерела.
migrate-reason-skip-identity = Пропущено як ідентифікатор джерела.
migrate-reason-needs-input = Потрібне рішення оператора.
migrate-reason-unsupported = Цільовий роутер не підтримує це налаштування.
migrate-reason-prune = Видалено за вибором оператора.
migrate-apply-verified = Перенесення перевірено. Виберіть збереження або відкат; зміни ще не збережено.
migrate-apply-failed = Перенесення зупинено. Перевірте результат перед відкатом.
migrate-apply-restored = Перевірка перенесення завершилася помилкою. kcc автоматично виконав відкат і відновив стартову конфігурацію.
migrate-apply-router-rollback = Роутер відновив збережену конфігурацію після завершення таймера відновлення.
migrate-apply-tier = Підтвердьте перенесення на прошивку, підтримка якої базується лише на документації.
migrate-apply-agreement = Підтвердьте поточну угоду роутера перед продовженням.
migrate-apply-residual = Збережено налаштувань лише цільового роутера: { $count }.
finish-saved-armed = Конфігурацію збережено, але вимкнути таймер відновлення не вдалося. Вважайте таймер активним: роутер може перезавантажитися зі збереженою конфігурацією, яка містить ці зміни.
migrate-rollback-saved = Роутер перезавантажується зі збереженою конфігурацією, яка вже може містити перенесені налаштування.

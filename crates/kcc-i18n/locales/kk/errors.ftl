# Machine-assisted translation - native review pending

errors-internal = Ішкі қате орын алды.
errors-not-found = Табылмады.
errors-forbidden = Бұл әрекетке рұқсатыңыз жоқ.
errors-auth-failed = Пайдаланушы аты немесе құпиясөз қате.
errors-account-locked = Сәтсіз әрекеттер тым көп. { $minutes } минуттан кейін қайталаңыз.
errors-router-unreachable = { $name } роутері қолжетімсіз.
errors-router-auth = Роутер тіркелгі деректерін қабылдамады.
errors-invalid-input = { $field } өрісінің мәні жарамсыз.
errors-unsupported-firmware = { $version } микробағдарламасына қолдау көрсетілмейді.
errors-timeout = Операцияның күту уақыты бітті.
errors-csrf = Форманың мерзімі өтті. Бетті қайта жүктеп, әрекетті қайталаңыз.
errors-outbound-refused = kcc { $address } мекенжайына қосылмайды: мекенжай [outbound] allowed_networks параметріндегі желілерге кірмейді. Роутер желісін, мысалы 192.168.1.0/24, kcc.toml ішіндегі allowed_networks тізіміне (немесе хост атауының жұрнағын allowed_suffixes тізіміне) қосыңыз; іске қосылған kcc serve өзгерісті қайта іске қосылғаннан кейін қолданады. Бұлттық метадеректер мекенжайларына әрқашан тыйым салынған.
errors-outbound-metadata = kcc { $address } мекенжайына ешқашан қосылмайды: бұл бұлттық метадеректер мекенжайы, оған ешбір параметр рұқсат бермейді.
errors-outbound-loopback = kcc { $address } мекенжайына қосылмайды: кері байланыс мекенжайлары үшін kcc.toml ішінде [outbound] allow_loopback = true мәнін орнатыңыз; іске қосылған kcc serve өзгерісті қайта іске қосылғаннан кейін қолданады.
errors-outbound-never = kcc { $address } мекенжайына ешқашан қосылмайды: мұндай мекенжайға ешбір параметр рұқсат бермейді.
errors-secret-file-permissions = { $path } файлын басқа пайдаланушылар оқи алады. chmod 600 { $path } командасын орындап, әрекетті қайталаңыз.

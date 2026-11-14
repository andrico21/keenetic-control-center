# Machine-assisted translation - native review pending

errors-forbidden = Бұл әрекетке рұқсатыңыз жоқ.
errors-auth-failed = Пайдаланушы аты немесе құпиясөз қате.
errors-router-auth = Роутер тіркелгі деректерін қабылдамады.
errors-timeout = Операцияның күту уақыты бітті.
errors-outbound-refused = kcc { $address } мекенжайына қосылмайды: мекенжай [outbound] allowed_networks параметріндегі желілерге кірмейді. Роутер желісін, мысалы 192.168.1.0/24, kcc.toml ішіндегі allowed_networks тізіміне (немесе хост атауының жұрнағын allowed_suffixes тізіміне) қосыңыз; іске қосылған kcc serve өзгерісті қайта іске қосылғаннан кейін қолданады. Бұлттық метадеректер мекенжайларына әрқашан тыйым салынған.
errors-outbound-metadata = kcc { $address } мекенжайына ешқашан қосылмайды: бұл бұлттық метадеректер мекенжайы, оған ешбір параметр рұқсат бермейді.
errors-outbound-loopback = kcc { $address } мекенжайына қосылмайды: кері байланыс мекенжайлары үшін kcc.toml ішінде [outbound] allow_loopback = true мәнін орнатыңыз; іске қосылған kcc serve өзгерісті қайта іске қосылғаннан кейін қолданады.
errors-outbound-never = kcc { $address } мекенжайына ешқашан қосылмайды: мұндай мекенжайға ешбір параметр рұқсат бермейді.
errors-secret-file-permissions = { $path } файлын басқа пайдаланушылар оқи алады. chmod 600 { $path } командасын орындап, әрекетті қайталаңыз.

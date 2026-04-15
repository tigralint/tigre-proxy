package tigralint.tgproxy.util

import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue

object Texts {
    var isRu by mutableStateOf(true)

    // Dashboard
    val dashboard get() = if (isRu) "Главная" else "Dashboard"
    val proxyActive get() = if (isRu) "Прокси активен" else "Proxy Active"
    val proxyStopped get() = if (isRu) "Прокси остановлен" else "Proxy Stopped"
    val starting get() = if (isRu) "Запуск..." else "Starting..."
    val error get() = if (isRu) "Ошибка" else "Error"
    val startProxy get() = if (isRu) "Запустить прокси" else "Start Proxy"
    val stopProxy get() = if (isRu) "Остановить прокси" else "Stop Proxy"
    val proxyLink get() = if (isRu) "Ссылка на прокси" else "Proxy Link"
    val openInTelegram get() = if (isRu) "Открыть в Telegram" else "Open in Telegram"
    val copied get() = if (isRu) "Скопировано!" else "Copied!"
    val copy get() = if (isRu) "Копировать" else "Copy"
    val trafficUsed get() = if (isRu) "Трафик" else "Traffic"
    val uploaded get() = if (isRu) "Отправлено" else "Uploaded"
    val downloaded get() = if (isRu) "Скачано" else "Downloaded"

    // Settings
    val settings get() = if (isRu) "Настройки" else "Settings"
    val stopToChange get() = if (isRu) "Остановите прокси для изменения настроек" else "Stop proxy to change settings"
    
    val antiBlock get() = if (isRu) "Режим Анти-блокировки" else "Anti-Block Mode"
    val antiBlockDesc get() = if (isRu) "Использовать скрытые пути для обхода блокировок РКН" else "Use hidden paths to bypass censorship"
    
    val antiDpi get() = if (isRu) "Обход ТСПУ (Anti-DPI)" else "Anti-DPI / TSPU Bypass"
    val antiDpiDesc get() = if (isRu) "Маскировка TLS-отпечатка под Chrome + Padding. Помогает при жестких блокировках." else "Chrome TLS fingerprint + Padding. Helps against strict mobile filtering."
    
    val advancedSettings get() = if (isRu) "Продвинутые настройки (Для гиков)" else "Advanced Settings (For geeks)"
    
    val connection get() = if (isRu) "Подключение" else "Connection"
    val secret get() = if (isRu) "Секрет (32 hex символа)" else "Secret (32 hex chars)"
    val localPort get() = if (isRu) "Локальный порт" else "Local Port"
    val fakeTls get() = if (isRu) "FakeTLS (Обход DPI)" else "FakeTLS (DPI Bypass)"
    val maskingDomain get() = if (isRu) "Домен маскировки" else "Masking Domain"
    val egGoogle get() = if (isRu) "напр. google.com" else "e.g. google.com"
    val leaveEmptyFakeTls get() = if (isRu) "Оставьте пустым для отключения" else "Leave empty to disable"
    val cfFallback get() = if (isRu) "Фолбэк через Cloudflare" else "Cloudflare Fallback"
    val cfPriority get() = if (isRu) "Приоритет Cloudflare" else "Cloudflare Priority"
    val cfPriorityDesc get() = if (isRu) "Первым пробовать CF прокси вместо прямого TCP. Рекомендуется при жёстких блокировках." else "Try CF proxy before direct TCP. Recommended when direct IPs are blocked."
    val enableCf get() = if (isRu) "Включить CF Прокси" else "Enable CF Proxy"
    val customCfDomain = if (isRu) "Свой Cloudflare домен" else "Custom Cloudflare Domain"
    val leaveEmptyAuto = if (isRu) "Пусто = публичные шлюзы" else "Leave empty for public gateways"
    val dcMappings get() = if (isRu) "Маршрутизация DC → IP" else "DC → IP Mappings"
    val dcIps get() = if (isRu) "DC:IP (по одному на строку)" else "DC:IP (one per line)"

    val useDoh get() = if (isRu) "DNS over HTTPS (ECH)" else "DNS over HTTPS (ECH)"
    val useDohDesc get() = if (isRu) "Шифрует SNI через Cloudflare DoH. Предотвращает обнаружение домена." else "Encrypts SNI via DoH. Prevents domain-based detection."
    
    val useTrafficShaping get() = if (isRu) "Обфускация таймингов" else "Traffic Shaping"
    val useTrafficShapingDesc get() = if (isRu) "Вносит микро-задержки в handshake для размытия сигнатур MTProto." else "Adds micro-delays to handshake to blur MTProto signatures."
    
    val system get() = if (isRu) "Система" else "System"
    val batteryOpt get() = if (isRu) "Фоновая работа" else "Background execution"
    val batteryNotDisabled get() = if (isRu) "Внимание: система может закрывать прокси" else "Warning: system might kill the proxy"
    val batteryDisabled get() = if (isRu) "Прокси работает стабильно в фоне" else "Proxy runs reliably in the background"
    val fix get() = if (isRu) "Исправить" else "Fix"
    val autoStart get() = if (isRu) "Автозапуск (Huawei/Xiaomi/Oppo)" else "AutoStart (Huawei/Xiaomi/Oppo)"
    val autoStartDesc get() = if (isRu) "Нажмите, если приложение вылетает в фоне" else "Tap if app is killed in background"
    val saveSettings get() = if (isRu) "Сохранить настройки" else "Save Settings"
    
    // Language
    val language get() = "Язык / Language"
    val russian get() = "Русский"
    val english get() = "English"

    val noTelegram get() = if (isRu) "Telegram не установлен" else "Telegram not installed"

    // Logs
    val logsTitle get() = if (isRu) "Логи" else "Logs"
    val logsClear get() = if (isRu) "Очистить" else "Clear"

    // FAQ
    val faq get() = "FAQ"
    val faqTitle1 get() = if (isRu) "Что это за приложение?" else "What is this app?"
    val faqText1 get() = if (isRu) 
        "Локальный MTProto прокси для Telegram. Позволяет обходить блокировки (например, РКН) прозрачно и безопасно. Трафик не идёт через VPN-сервер, а маскируется." else 
        "A local MTProto proxy for Telegram. Enables seamless and secure censorship bypass. Traffic isn't routed through a VPN server, it is cryptographically masked."
    
    val faqTitle2 get() = if (isRu) "Что делать, если прокси не коннектится?" else "What if the proxy won't connect?"
    val faqText2 get() = if (isRu) 
        "Убедитесь, что 'Режим Анти-блокировки' включен. Если поле 'Свой Cloudflare домен' пустое, приложение само найдёт и использует рабочие публичные шлюзы." else 
        "Ensure 'Anti-Block Mode' is enabled. If the 'Custom Cloudflare Domain' field is empty, the app will automatically find and use working public gateways."

    val faqTitle3 get() = if (isRu) "Это безопасно?" else "Is it safe?"
    val faqText3 get() = if (isRu)
        "Абсолютно. Прокси работает ТОЛЬКО локально на вашем телефоне. Вся магия обхода (шифрование, Cloudflare) происходит прямо на вашем устройстве, ключи шифрования в безопасности." else
        "Absolutely. The proxy runs strictly LOCALLY on your phone. All circumvention magic happens entirely on your device."

    val faqTitle4 get() = if (isRu) "Прокси выключается сам по себе в фоне" else "Proxy kills itself in the background"
    val faqText4 get() = if (isRu)
        "На Huawei (EMUI) и Xiaomi (MIUI/HyperOS) агрессивный режим энергосбережения принудительно убивает прокси при выключении экрана. Чтобы исправить: Настройки -> Батарея -> Запуск приложений -> найдите Tigre Proxy -> отключите 'Управлять автоматически' и обязательно включите все 3 галочки внутри (Автозапуск, Работа в фоне). Также закрепите приложение 'замочком' в недавних." else
        "On Huawei and Xiaomi, aggressive battery saving forcefully kills the proxy when the screen turns off. Fix it: Settings -> Battery -> App Launch -> find Tigre Proxy -> disable 'Manage automatically' and enable all 3 toggles (Auto-launch, Run in background). Also lock the app in recent apps."

    val developedBy get() = if (isRu) "Разработчик: @tigralint" else "Developer: @tigralint"
}

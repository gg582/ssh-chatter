#include "matrix_client.h"
#define SSH_CHATTER_STRONG_CIPHERS "chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes256-ctr"
#define SSH_CHATTER_STRONG_MACS "hmac-sha2-512,hmac-sha2-256"
#define SSH_CHATTER_SECURE_COMPRESSION "none"
    "misc",
  const char *help_misc_title;
        .help_hint_extra = "See %sadvanced or %smisc for optional commands.",
        .help_misc_title = "Miscellaneous commands:",
        .help_hint_extra = "%sadvanced나 %smisc에서 선택 명령을 확인하세요.",
        .help_misc_title = "기타 명령:",
        .help_hint_extra = "追加コマンドは %sadvanced または %smisc で確認できます。",
        .help_misc_title = "その他のコマンド:",
        .help_hint_extra = "更多命令请查看 %sadvanced 或 %smisc。",
        .help_misc_title = "杂项命令：",
        .help_hint_extra = "Дополнительные команды смотрите в %sadvanced или %smisc.",
        .help_misc_title = "Прочие команды:",
    {
        .kind = SESSION_HELP_ENTRY_COMMAND,
        .label = "misc",
        .description = {
            "Browse creative and social extras.",
            "창의적인 부가기능을 둘러봅니다.",
            "クリエイティブ系の追加機能を表示します。",
            "浏览创意与社交类附加功能。",
            "Посмотреть творческие и социальные дополнения.",
        },
    },
};

static const session_help_entry_t kSessionHelpMisc[] = {
    {
        .kind = SESSION_HELP_ENTRY_COMMAND,
        .label = "profilepic",
        .description = {
            "Open the ASCII art profile picture composer.",
            "ASCII 아트 프로필 편집기를 엽니다.",
            "ASCII アートのプロフィール作成ツールを開きます。",
            "打开 ASCII 头像编辑器。",
            "Открыть редактор ASCII-аватаров.",
        },
    },
    {
        .kind = SESSION_HELP_ENTRY_COMMAND,
        .label = "asciiart",
        .description = {
            "Open the ASCII art composer (max 128 lines, 1/10 min per IP).",
            "ASCII 아트 작성기를 엽니다 (최대 128줄, IP당 10분에 1회).",
            "ASCII アート作成ツールを開きます（最大128行、IPごと10分に1回）。",
            "打开 ASCII 艺术编辑器（最多128行，每个 IP 10 分钟一次）。",
            "Открыть редактор ASCII-арта (до 128 строк, раз в 10 минут на IP).",
        },
    },
    {
        .kind = SESSION_HELP_ENTRY_COMMAND,
        .label = "game <tetris|liargame|alpha>",
        .description = {
            "Start a minigame in chat (use %ssuspend! or Ctrl+Z to exit).",
            "채팅에서 미니게임을 시작합니다 (%ssuspend! 또는 Ctrl+Z로 종료).",
            "チャットでミニゲームを開始します（終了は %ssuspend! か Ctrl+Z）。",
            "在聊天中启动小游戏（使用 %ssuspend! 或 Ctrl+Z 退出）。",
            "Запустить мини-игру в чате (выход — %ssuspend! или Ctrl+Z).",
        },
    },
    {
        .kind = SESSION_HELP_ENTRY_COMMAND,
        .label = "color (text;highlight[;bold])",
        .description = {
            "Style your handle.",
            "사용자 이름 색상을 꾸밉니다.",
            "ハンドル名の配色を設定します。",
            "设置昵称的配色。",
            "Настроить оформление вашего ника.",
        },
    },
    {
        .kind = SESSION_HELP_ENTRY_COMMAND,
        .label = "systemcolor (fg;background[;highlight][;bold])",
        .description = {
            "Customize interface colors (reset with %ssystemcolor reset).",
            "인터페이스 색상을 조정합니다 (%ssystemcolor reset으로 초기화).",
            "インターフェースの色を調整します（%ssystemcolor reset で初期化）。",
            "自定义界面颜色（用 %ssystemcolor reset 重置）。",
            "Настроить цвета интерфейса (сброс — %ssystemcolor reset).",
        },
    },
    {
        .kind = SESSION_HELP_ENTRY_COMMAND,
        .label = "palette <name>",
        .description = {
            "Apply a predefined interface palette (%spalette list).",
            "미리 정의된 팔레트를 적용합니다 (%spalette list 참고).",
            "定義済みの配色を適用します（%spalette list を参照）。",
            "应用预设的界面配色（参见 %spalette list）。",
            "Применить готовую палитру интерфейса (см. %spalette list).",
        },
    },
    {
        .kind = SESSION_HELP_ENTRY_COMMAND,
        .label = "weather <region> <city>",
        .description = {
            "Show weather for a region and city.",
            "지역과 도시의 날씨를 보여줍니다.",
            "地域と都市の天気を表示します。",
            "显示指定地区和城市的天气。",
            "Показать погоду для региона и города.",
        },
    },
    {
        .kind = SESSION_HELP_ENTRY_COMMAND,
        .label = "today",
        .description = {
            "Discover today's function (once per day).",
            "오늘의 기능을 확인합니다 (하루 1회).",
            "本日の機能を確認します（1日1回）。",
            "查看今日功能（每天一次）。",
            "Узнать сегодняшнюю функцию (раз в день).",
        },
    },
    {
        .kind = SESSION_HELP_ENTRY_COMMAND,
        .label = "date <timezone>",
        .description = {
            "View the server time in another timezone.",
            "다른 시간대의 서버 시간을 확인합니다.",
            "別のタイムゾーンでサーバー時刻を表示します。",
            "查看其他时区的服务器时间。",
            "Показать серверное время в другом часовом поясе.",
        },
    },
    {
        .kind = SESSION_HELP_ENTRY_COMMAND,
        .label = "birthday YYYY-MM-DD",
        .description = {
            "Register your birthday.",
            "생일을 등록합니다.",
            "誕生日を登録します。",
            "登记你的生日。",
            "Зарегистрировать дату рождения.",
        },
    },
    {
        .kind = SESSION_HELP_ENTRY_COMMAND,
        .label = "soulmate",
        .description = {
            "List users sharing your birthday.",
            "생일이 같은 사용자를 나열합니다.",
            "同じ誕生日のユーザーを一覧表示します。",
            "列出与你同生日的用户。",
            "Показать пользователей с той же датой рождения.",
        },
    },
    {
        .kind = SESSION_HELP_ENTRY_COMMAND,
        .label = "pair",
        .description = {
            "List users sharing your recorded OS.",
            "등록한 OS가 같은 사용자를 나열합니다.",
            "同じOSを登録したユーザーを表示します。",
            "列出记录的操作系统相同的用户。",
            "Показать пользователей с той же записанной ОС.",
        },
    },
    {
        .kind = SESSION_HELP_ENTRY_COMMAND,
        .label = "connected",
        .description = {
            "Privately list everyone connected.",
            "현재 접속 중인 사용자 목록을 비공개로 확인합니다.",
            "接続中のユーザーを自分だけに一覧表示します。",
            "私下查看所有在线用户。",
            "Получить приватный список всех подключённых.",
        },
    },
    {
        .kind = SESSION_HELP_ENTRY_COMMAND,
        .label = "alpha-centauri-landers",
        .description = {
            "View the Immigrants' Flag hall of fame.",
            "Immigrants' Flag 명예의 전당을 확인합니다.",
            "Immigrants' Flag 殿堂を表示します。",
            "查看 Immigrants' Flag 名人堂。",
            "Открыть зал славы Immigrants' Flag.",
        },
    },
    {
        .kind = SESSION_HELP_ENTRY_COMMAND,
        .label = "poke <username>",
        .description = {
            "Send a bell to call a user.",
            "사용자를 호출하는 종소리를 보냅니다.",
            "ユーザーを呼び出すベルを送ります。",
            "向用户发送提醒铃声。",
            "Отправить звуковой сигнал пользователю.",
        },
    },
static void session_print_help_misc(session_ctx_t *ctx);
    const char *args[] = {prefix, prefix};
static void session_print_help_misc(session_ctx_t *ctx) {
  if (ctx == NULL) {
    return;
  }

  const session_ui_locale_t *locale = session_ui_get_locale(ctx);

  if (locale->help_misc_title != NULL && locale->help_misc_title[0] != '\0') {
    session_send_system_line(ctx, locale->help_misc_title);
  }

  session_help_send_entries(ctx, kSessionHelpMisc,
                            sizeof(kSessionHelpMisc) / sizeof(kSessionHelpMisc[0]));

  session_send_system_line(ctx, "");
}

  else if (session_parse_command(line, "/misc", &args)) {
    session_print_help_misc(ctx);
    return;
  }

      const char *args[] = {prefix, prefix};
  host->matrix_client = NULL;
  host->security_layer_initialized = security_layer_init(&host->security_layer);
  if (!host->security_layer_initialized) {
    humanized_log_error("security", "failed to initialise layered message encryption", errno != 0 ? errno : EIO);
  }
    if (host->security_layer_initialized) {
      host->matrix_client = matrix_client_create(host, host->clients, &host->security_layer);
      if (host->matrix_client == NULL) {
        humanized_log_error("matrix", "matrix backend inactive; check CHATTER_MATRIX_* configuration", EINVAL);
      }
    }

  if (host->matrix_client != NULL) {
    matrix_client_destroy(host->matrix_client);
    host->matrix_client = NULL;
  }
  if (host->security_layer_initialized) {
    security_layer_free(&host->security_layer);
    host->security_layer_initialized = false;
  }
    host_bind_set_optional_string(bind_handle, SSH_BIND_OPTIONS_CIPHERS_C_S, SSH_CHATTER_STRONG_CIPHERS,
                                  "failed to configure forward cipher suite");
    host_bind_set_optional_string(bind_handle, SSH_BIND_OPTIONS_CIPHERS_S_C, SSH_CHATTER_STRONG_CIPHERS,
                                  "failed to configure reverse cipher suite");
    host_bind_set_optional_string(bind_handle, SSH_BIND_OPTIONS_HMAC_C_S, SSH_CHATTER_STRONG_MACS,
                                  "failed to configure forward MAC list");
    host_bind_set_optional_string(bind_handle, SSH_BIND_OPTIONS_HMAC_S_C, SSH_CHATTER_STRONG_MACS,
                                  "failed to configure reverse MAC list");
#ifdef SSH_BIND_OPTIONS_COMPRESSION_C_S
    host_bind_set_optional_string(bind_handle, SSH_BIND_OPTIONS_COMPRESSION_C_S, SSH_CHATTER_SECURE_COMPRESSION,
                                  "failed to restrict forward compression mode");
#endif
#ifdef SSH_BIND_OPTIONS_COMPRESSION_S_C
    host_bind_set_optional_string(bind_handle, SSH_BIND_OPTIONS_COMPRESSION_S_C, SSH_CHATTER_SECURE_COMPRESSION,
                                  "failed to restrict reverse compression mode");
#endif

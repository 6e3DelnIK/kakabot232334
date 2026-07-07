import crypto from "crypto";

const BASE32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

function base32ToBuffer(base32: string) {
  const cleaned = base32.replace(/=+$/, "").toUpperCase().replace(/[^A-Z2-7]/g, "");

  let bits = "";
  for (const char of cleaned) {
    const val = BASE32_ALPHABET.indexOf(char);
    if (val === -1) throw new Error("Invalid base32 character");
    bits += val.toString(2).padStart(5, "0");
  }

  const bytes = [];
  for (let i = 0; i + 8 <= bits.length; i += 8) {
    bytes.push(parseInt(bits.slice(i, i + 8), 2));
  }

  return Buffer.from(bytes);
}

function generateTOTP(secret: string, digits = 6, period = 30, timestamp = Date.now()) {
  const key = base32ToBuffer(secret);
  const counter = Math.floor(timestamp / 1000 / period);

  const counterBuf = Buffer.alloc(8);
  counterBuf.writeBigUInt64BE(BigInt(counter));

  const hmac = crypto.createHmac("sha1", key).update(counterBuf).digest();

  const offset = hmac[hmac.length - 1] & 0xf;
  const code =
    ((hmac[offset] & 0x7f) << 24) |
    ((hmac[offset + 1] & 0xff) << 16) |
    ((hmac[offset + 2] & 0xff) << 8) |
    (hmac[offset + 3] & 0xff);

  const otp = (code % 10 ** digits).toString().padStart(digits, "0");
  return otp;
}

const apiRoot = `https://api.telegram.org/bot${process.env.TG_BOT_TOKEN}/`;

async function apiCall(method: string, body?: any): Promise<any> {
  const response = await fetch(`${apiRoot}${method}`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json"
    },
    body: body ? JSON.stringify(body) : "{}"
  });

  return response.json();
}

async function tgHandleErrors(promise: Promise<any>) {
  const result = await promise;
  if (!result.ok)
    throw new Error(`${result.error_code}: ${result.description}`);
  return result.result;
}

// ------------------------------------------------------------
// Новая функция: извлекает логин, пароль, секрет из строки
// ------------------------------------------------------------
function parseCredentials(rawLine: string): { login: string; password: string; secret: string } | null {
  let line = rawLine.trim();

  // Убираем начальную нумерацию вида "1.", "1)", "1-", "1," и т.п.
  line = line.replace(/^\d+[.)\]\-:,]?\s*/, "").trim();

  // Приводим все разделители '|' к ':'
  line = line.replace(/\|/g, ":");

  // Разбиваем по ':'
  const parts = line.split(":").map(p => p.trim()).filter(p => p !== "");

  // Нужно как минимум три части
  if (parts.length < 3) return null;

  // Берём первые три: логин, пароль, секрет
  const [login, password, secret] = parts;

  // Дополнительно отсекаем возможные "хвосты" в секрете, если он содержит пробелы (маловероятно, но безопасно)
  // Просто берём первое слово секрета, если он случайно оказался с пробелом после предыдущей обработки
  const cleanSecret = secret.split(/\s+/)[0];

  return { login, password, secret: cleanSecret };
}

async function main() {
  let maxUpdateId = 0;

  while (true) {
    const updates = await tgHandleErrors(apiCall("getUpdates", {
      offset: maxUpdateId == 0 ? undefined : (maxUpdateId + 1),
      timeout: 0
    }));

    for (const update of updates) {
      if (update.update_id > maxUpdateId)
        maxUpdateId = update.update_id;

      console.log(update);
      if (update.message) {
        const message = update.message;
        if (!message.text) continue;

        const lines = message.text.split("\n");
        for (const line of lines) {
          // Пробуем извлечь учётные данные
          const creds = parseCredentials(line);
          if (!creds) continue; // невалидная строка – пропускаем

          // Отправляем логин
          await apiCall("sendMessage", { chat_id: message.chat.id, text: creds.login });
          // Отправляем пароль
          await apiCall("sendMessage", { chat_id: message.chat.id, text: creds.password });

          // Отправляем секрет и запоминаем сообщение для ответа
          let sentMsg;
          try {
            sentMsg = await tgHandleErrors(apiCall("sendMessage", { chat_id: message.chat.id, text: creds.secret }));
          } catch (err) {
            console.error("Ошибка отправки секрета:", err);
            continue;
          }

          // Генерируем TOTP
          let code;
          try {
            code = generateTOTP(creds.secret);
          } catch (err: any) {
            await apiCall("sendMessage", {
              chat_id: message.chat.id,
              text: `❌ Не удалось создать TOTP для секрета "${creds.secret}": ${err.message}`
            });
            continue;
          }

          // Отправляем код с кнопкой «Обновить»
          await apiCall("sendMessage", {
            chat_id: message.chat.id,
            text: `TOTP Код: <code>${code}</code>`,
            parse_mode: "HTML",
            reply_parameters: {
              message_id: sentMsg.message_id
            },
            reply_markup: {
              inline_keyboard: [[
                {
                  text: "Обновить",
                  callback_data: creds.secret
                }
              ]]
            }
          });
        }
      }
      else if (update.callback_query) {
        const callback_query = update.callback_query;
        const message = callback_query.message;
        const data = callback_query.data;
        const code = generateTOTP(data);
        apiCall("answerCallbackQuery", {
          callback_query_id: callback_query.id,
          text: "Updated"
        });
        await apiCall("editMessageText", {
          chat_id: message.chat.id,
          message_id: message.message_id,
          text: `TOTP Код: <code>${code}</code>`,
          parse_mode: "HTML",
          reply_markup: {
            inline_keyboard: [[
              {
                text: "Обновить",
                callback_data: data
              }
            ]]
          }
        });
      }
    }
  }
}

main();
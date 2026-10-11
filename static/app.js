const form = document.getElementById("setup-form");
const usernameInput = document.getElementById("username");
const adminCheckbox = document.getElementById("admin-mode");
const adminPasswordArea = document.getElementById("admin-password-area");
const adminPasswordInput = document.getElementById("admin-password");
const statusMessage = document.getElementById("status");

const USERNAME_KEY = "vyslo_chat_username";

function updateAdminField() {
  adminPasswordArea.hidden = !adminCheckbox.checked;
  adminPasswordInput.required = adminCheckbox.checked;

  if (!adminCheckbox.checked) {
    adminPasswordInput.value = "";
  }
}

function loadSavedUsername() {
  try {
    const savedUsername = localStorage.getItem(USERNAME_KEY);
    if (savedUsername) {
      usernameInput.value = savedUsername;
      statusMessage.textContent = "前回のユーザー名を読み込んだよ。";
    }
  } catch {
    statusMessage.textContent = "このブラウザではユーザー名を保存できないみたい。";
  }
}

adminCheckbox.addEventListener("change", updateAdminField);

form.addEventListener("submit", (event) => {
  event.preventDefault();

  const username = usernameInput.value.trim();
  if (!username) {
    statusMessage.textContent = "ユーザー名を入力してね。";
    usernameInput.focus();
    return;
  }

  if (adminCheckbox.checked) {
    statusMessage.textContent =
      "管理者認証はまだ未実装だよ。今は一般ユーザー設定だけ保存できるよ。";
    return;
  }

  try {
    localStorage.setItem(USERNAME_KEY, username);
    statusMessage.textContent =
      `ユーザー名「${username}」をこのブラウザに保存したよ。`;
  } catch {
    statusMessage.textContent =
      "保存できなかったよ。ブラウザの保存設定を確認してね。";
  }
});

loadSavedUsername();
updateAdminField();

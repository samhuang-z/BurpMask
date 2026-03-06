# BurpMask

Burp Suite MCP 資料遮罩代理工具。架設在 Claude Code 與 Burp Suite MCP server 之間，自動遮罩敏感的客戶資料（域名、關鍵字），確保真實資訊不會傳送到 AI API。

A de-identification proxy between Claude Code and Burp Suite's MCP server. Automatically masks sensitive client data (domains, keywords) so that real information never reaches the AI API.

## 架構 / Architecture

```
+---------------------------------------------------+
|                Anthropic Cloud                    |
|                                                   |
| Claude AI 只看到: mail.target-a.test, TargetA     |
| (永遠不知道真實目標是 google.com)                 |
+-------------------------+-------------------------+
                          |
              +-----------+-----------+
              |      Claude Code      |
              |     (你的電腦上)      |
              +-----------+-----------+
                          | JSON-RPC (stdio)
           +--------------+--------------+
           |          BurpMask           |
           |                             |
           | 往上 (Burp -> Claude):      |
           |   google.com                |
           |   -> target-a.test          |
           |   Google -> TargetA         |
           |   ! 洩漏檢查                |
           |                             |
           | 往下 (Claude -> Burp):      |
           |   target-a.test             |
           |   -> google.com             |
           |   (僅替換域名)              |
           +--------------+--------------+
                          | JSON-RPC (stdio)
              +-----------+-----------+
              |    mcp-proxy.jar      |
              |   (stdio <-> SSE)     |
              +-----------+-----------+
                          | SSE (localhost:9876)
              +-----------+-----------+
              |   Burp Suite + MCP    |
              |                       |
              |   這裡是真實域名      |
              |   google.com          |
              +-----------------------+
```

**核心原則**：Claude 永遠看不到真實域名或關鍵字。真實資料只存在於本地端的 proxy 與 Burp Suite 之間。

## 資料流 / Data Flow

| 方向 | 處理方式 |
|---|---|
| Burp -> Claude（stdout） | 真實域名與關鍵字被替換為假的 |
| Claude -> Burp（stdin） | 假**域名**被還原為真實域名（關鍵字**不會**反向替換，避免誤判） |
| 安全防護 | 送出給 Claude 之前，額外掃描是否殘留真實資料，若有則**攔截不送出** |

## 前置需求 / Prerequisites

- **Java**（執行 `mcp-proxy.jar`）
- **Python 3**（執行 BurpMask）
- **Burp Suite** 並安裝 [MCP Extension](https://github.com/PortSwigger/mcp-server)
- **Claude Code** CLI

## 檔案結構 / File Structure

```
toolkit/mcp/
  burpmask.py              # BurpMask 主程式
  mcp-proxy.jar            # Burp MCP stdio-to-SSE 橋接（需自行取得）
  deid-config.json         # 遮罩規則設定檔（不納入版控，含敏感資料）
  deid-config.example.json # 範例設定檔
  README.md                # 本文件
```

## 設定步驟 / Setup

### 1. 設定 Burp Suite MCP Extension

1. 開啟 Burp Suite
2. 前往 **Extensions** > **BApp Store**
3. 搜尋 **MCP Server** 並安裝
4. 前往 Burp Suite 中的 **MCP** 分頁
5. 確認 SSE server 正在運行（預設：`http://localhost:9876/`）

### 2. 設定遮罩規則

複製範例設定檔並編輯：

```bash
cp deid-config.example.json deid-config.json
```

編輯 `deid-config.json` 定義替換規則：

```json
{
  "replacements": {
    "domains": {
      "mail.google.com": "mail.target-a.test",
      "*.google.com": "*.target-a.test"
    },
    "keywords": {
      "Google": "TargetA",
      "google": "target-a"
    },
    "patterns": {}
  }
}
```

以上範例會將所有 `google.com` 相關域名替換為 `target-a.test`，關鍵字 `Google` 替換為 `TargetA`。Claude 只會看到 `target-a.test`，永遠不會知道真實目標是 Google。

#### 替換類型 / Replacement Types

| 類型 | 格式 | 範例 | 方向 |
|---|---|---|---|
| **精確域名** | `"真實": "假的"` | `"mail.google.com": "mail.target-a.test"` | 雙向（正向 + 反向） |
| **萬用字元域名** | `"*.真實": "*.假的"` | `"*.google.com": "*.target-a.test"` | 雙向（正向 + 反向） |
| **關鍵字** | `"真實": "假的"` | `"Google": "TargetA"` | 僅正向（Burp -> Claude） |
| **正規表達式** | `"regex": "replacement"` | `"\\d{3}-\\d{4}": "XXX-XXXX"` | 僅正向（Burp -> Claude） |

> **注意**：只有域名替換會雙向運作。關鍵字和正規表達式僅在正向（Burp -> Claude）生效，避免反向替換時短字串造成誤判。

#### 小提示

- 精確域名會優先於萬用字元匹配
- 較長的 pattern 會優先匹配，防止部分替換
- 假域名建議使用 `.test` TLD（這是保留的 TLD，不會被解析到真實伺服器）

### 3. 在 Claude Code 註冊 MCP Server

執行以下指令：

```bash
claude mcp add burpsuite -s user -- \
  python3 /path/to/toolkit/mcp/burpmask.py \
  --sse-url http://localhost:9876/
```

將 `/path/to/toolkit/mcp/` 替換為實際路徑。

`-s user` 代表註冊在使用者層級，所有專案皆可使用。

### 4. 驗證連線

在 Claude Code 中輸入：

```
> 查看 Burp proxy 歷史紀錄
```

若連線成功，Claude 可以讀取 proxy 歷史紀錄，且所有敏感資料皆已被遮罩。

## 安全防護機制 / Safety Net

Proxy 內建安全防護：

1. 對 Burp 回應進行遮罩處理後，額外掃描輸出內容是否仍包含真實域名或關鍵字
2. 若偵測到**任何**未遮罩的真實資料（例如編碼邊界情況），該訊息會被**整筆攔截**
3. Claude 只會收到 `[BLOCKED]` 錯誤訊息，並在 stderr 記錄警告
4. 即使替換邏輯有 bug，真實資料也不會洩漏到 AI API

## 疑難排解 / Troubleshooting

### 連線逾時

- 確認 Burp Suite 正在執行且 MCP 擴充套件為啟用狀態
- 確認 SSE 端點 URL（預設為 `http://localhost:9876/`，注意**不是** `/sse`）

### Claude 發送的請求無法到達目標

- 確認假域名已列在 `deid-config.json` 的 `domains` 中
- Proxy 只反向替換域名，因此 `Host` header 和 URL 必須使用已設定的假域名

### stderr 出現 BLOCKED 訊息

- 表示遮罩後的回應中仍偵測到真實資料
- 檢查 `deid-config.json` 是否有遺漏的替換規則
- 在 Burp 中查看原始回應，找出哪些資料沒有被遮罩

### Claude 收到亂碼

- 確認替換規則之間沒有重疊或衝突
- 較長的 pattern 應優先（proxy 會自動依長度排序）

## 已知限制 / Limitations

- **二進位資料**：Proxy 只處理文字（JSON 和原始字串），二進位內容會直接通過不做修改。
- **編碼資料**：Base64、URL encode 等編碼內的資料不會被遮罩，但安全防護機制會偵測到並攔截。
- **關鍵字反向替換已刻意停用**：Claude -> Burp 方向不會反向替換關鍵字，因為短字串（如公司名稱）可能出現在不相關的內容中，造成封包資料損壞。只有完整域名會被反向替換。

# CapCut Team Auto-Invite API

API endpoint untuk auto-invite akun CapCut ke workspace menggunakan Express.js dan Node.js.

## 📋 Fitur

- ✅ Auto-login akun CapCut
- ✅ Auto-resolve short link
- ✅ Auto-join workspace dengan invite link
- ✅ Support multiple accounts (banyak akun, 1 link)
- ✅ Parallel processing dengan workers
- ✅ IP restriction (hanya dari IP yang sama)
- ✅ PM2 process management
- ✅ Auto-restart jika crash

## 🚀 Instalasi

### 1. Install Dependencies

```bash
npm install
```

### 2. Install PM2 (Global)

```bash
npm install -g pm2
```

## ⚙️ Konfigurasi

### Port

Default port adalah `8001`. Anda bisa mengubahnya di:
- `ecosystem.config.js` - untuk PM2
- `server.js` - variabel `PORT` atau environment variable

### Proxy (Opsional)

Proxy sudah dikonfigurasi di `server.js`. Jika tidak menggunakan proxy, set `PROXY = null`.

## 📡 Endpoint

### POST `/api/join`

Endpoint utama untuk join workspace dengan multiple accounts.

#### Request Body

```json
{
  "link": "https://www.capcut.com/sv2/xxxxx/",
  "accounts": [
    ["email1@example.com", "password1"],
    ["email2@example.com", "password2"],
    ["email3@example.com", "password3"]
  ],
  "workers": 10
}
```

#### Parameters

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `link` | string | ✅ Yes | - | Link invite CapCut workspace |
| `accounts` | array | ✅ Yes | - | Array of accounts (format: `[email, password]`) |
| `workers` | number | ❌ No | 10 | Jumlah parallel workers/threads |

#### Account Format

Accounts bisa dalam 3 format:

1. **Array format** (recommended):
```json
[
  ["email1@example.com", "password1"],
  ["email2@example.com", "password2"]
]
```

2. **Object format**:
```json
[
  {"email": "email1@example.com", "password": "password1"},
  {"email": "email2@example.com", "password": "password2"}
]
```

3. **String format** (pipe separated):
```json
[
  "email1@example.com|password1",
  "email2@example.com|password2"
]
```

#### Response

**Success Response:**
```json
{
  "success": true,
  "summary": {
    "total_accounts": 3,
    "successfully_joined": 2,
    "already_member": 0,
    "failed": 1,
    "time_elapsed": "12.34s"
  },
  "results": [
    {
      "email": "email1@example.com",
      "status": "success",
      "message": "Successfully Joined!"
    },
    {
      "email": "email2@example.com",
      "status": "success",
      "message": "Successfully Joined!"
    },
    {
      "email": "email3@example.com",
      "status": "failed",
      "message": "login_failed"
    }
  ]
}
```

**Error Response:**
```json
{
  "error": "Link is required"
}
```

#### Status Codes

| Status | Description |
|--------|-------------|
| `success` | Berhasil join workspace |
| `already` | Akun sudah menjadi member |
| `member_full` | Workspace sudah penuh (member limit) |
| `login_failed` | Gagal login |
| `failed` | Gagal join (error lainnya) |
| `error` | Error teknis |

### GET `/health`

Health check endpoint (tidak ada IP restriction).

**Response:**
```json
{
  "status": "ok"
}
```

## 🔒 Security

### IP Restriction

Endpoint `/api/join` hanya bisa diakses dari:
- `localhost` (127.0.0.1)
- IP yang sama dengan server
- Tidak ada domain whitelist

Request dari IP lain akan mendapat response `403 Forbidden`.

## 💻 Contoh Penggunaan

### cURL

```bash
curl -X POST http://localhost:8001/api/join \
  -H "Content-Type: application/json" \
  -d '{
    "link": "https://www.capcut.com/sv2/ZSHcvxuQ2QwDy-G6jXB/",
    "accounts": [
      ["email1@capcut.team", "password1"],
      ["email2@capcut.team", "password2"],
      ["email3@capcut.team", "password3"]
    ],
    "workers": 3
  }'
```

### JavaScript (Fetch)

```javascript
const response = await fetch('http://localhost:8001/api/join', {
  method: 'POST',
  headers: {
    'Content-Type': 'application/json'
  },
  body: JSON.stringify({
    link: 'https://www.capcut.com/sv2/ZSHcvxuQ2QwDy-G6jXB/',
    accounts: [
      ['email1@capcut.team', 'password1'],
      ['email2@capcut.team', 'password2'],
      ['email3@capcut.team', 'password3']
    ],
    workers: 5
  })
});

const data = await response.json();
console.log(data);
```

### Python (Requests)

```python
import requests

url = "http://localhost:8001/api/join"
payload = {
    "link": "https://www.capcut.com/sv2/ZSHcvxuQ2QwDy-G6jXB/",
    "accounts": [
        ["email1@capcut.team", "password1"],
        ["email2@capcut.team", "password2"],
        ["email3@capcut.team", "password3"]
    ],
    "workers": 10
}

response = requests.post(url, json=payload)
print(response.json())
```

## 🎮 PM2 Commands

### Start Server

```bash
npm run pm2:start
# atau
pm2 start ecosystem.config.js
```

### Status

```bash
npm run pm2:status
# atau
pm2 status
```

### Logs

```bash
npm run pm2:logs
# atau
pm2 logs capcut-join-api

# Logs real-time
pm2 logs capcut-join-api --lines 100

# Error logs only
pm2 logs capcut-join-api --err
```

### Restart

```bash
npm run pm2:restart
# atau
pm2 restart capcut-join-api
```

### Stop

```bash
npm run pm2:stop
# atau
pm2 stop capcut-join-api
```

### Delete

```bash
npm run pm2:delete
# atau
pm2 delete capcut-join-api
```

### Auto-start on Boot

```bash
# Generate startup script
pm2 startup

# Save current process list
pm2 save
```

## 📁 Struktur Project

```
ccteam/
├── server.js              # Main server file
├── ecosystem.config.js    # PM2 configuration
├── package.json           # Dependencies & scripts
├── logs/                  # PM2 logs directory
│   ├── pm2-error.log
│   └── pm2-out.log
└── README.md              # Documentation
```

## ⚠️ Catatan Penting

1. **Workspace Full**: Jika workspace sudah penuh (`member_full`), semua proses akan dihentikan otomatis
2. **Rate Limiting**: Gunakan `workers` yang wajar (1-10) untuk menghindari rate limit
3. **IP Restriction**: Pastikan request dikirim dari IP yang sama dengan server
4. **Proxy**: Proxy sudah dikonfigurasi, sesuaikan jika perlu

## 🐛 Troubleshooting

### Port Already in Use

```bash
# Cek port yang digunakan
netstat -ano | findstr :8001

# Atau ubah port di ecosystem.config.js
```

### PM2 Process Not Found

```bash
# List semua PM2 processes
pm2 list

# Start ulang
pm2 start ecosystem.config.js
```

### Connection Refused

- Pastikan server sudah running: `pm2 status`
- Cek IP restriction (harus dari IP yang sama)
- Cek firewall settings

## 📝 License

ISC

## 👤 Author

CapCut Team


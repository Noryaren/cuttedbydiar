# cuttedbydiar

`cuttedbydiar` adalah aplikasi manajemen dan kontrol jaringan lokal (LAN) berbasis Python yang terinspirasi dari tool populer seperti NetCut. Aplikasi ini mendukung sistem operasi **Windows** dan **Linux**, dilengkapi dengan fitur **Whitelist** untuk melindungi perangkat penting agar tidak ikut terputus.

---

## 🛠️ Fitur Utama
1. **Device Discovery**: Melakukan ARP scan untuk mendeteksi semua perangkat aktif di satu segmen jaringan (IP, MAC Address, Hostname).
2. **Gateway Detection**: Otomatis mendeteksi IP dan MAC Address router/gateway utama.
3. **ARP Spoofing Engine**: Memutus koneksi perangkat target di jaringan lokal secara real-time.
4. **Whitelist Protection**: Mencegah perangkat penting (misalnya HP atau laptop Anda sendiri) agar tidak terkena pemutusan koneksi.
5. **Dual Interface**: Mendukung **CLI (Command Line Interface)** untuk terminal ringan maupun **GUI (Graphical User Interface)** berbasis Tkinter (native, tanpa instalasi GTK tambahan).

---

## 📦 Cara Membuat Executable (`.exe`) di Windows

Jika Anda ingin mengemas aplikasi ini menjadi file `.exe` mandiri di Windows sehingga dapat dijalankan tanpa perlu mengetik perintah Python:

1. Pastikan **Python 3** sudah terinstal dan terdaftar di PATH.
2. Pastikan Anda telah menginstal **[Npcap](https://npcap.com/)** (wajib untuk Scapy di Windows).
3. Buka folder proyek `cuttedbydiar` di **Command Prompt (CMD)** atau **PowerShell** sebagai **Administrator**.
4. Jalankan script otomatis `build.bat`:
   ```cmd
   build.bat
   ```
5. Script ini akan otomatis:
   * Menginstal pustaka yang diperlukan (`scapy`, `pyinstaller`).
   * Membuat file `.exe` standalone di dalam folder `dist\`:
     * **`cuttedbydiar-gui.exe`** (Aplikasi dengan tampilan jendela/GUI).
     * **`cuttedbydiar-cli.exe`** (Aplikasi berbasis Command Line).

---

## 🚀 Cara Menjalankan Aplikasi

Karena aplikasi ini berinteraksi langsung dengan lalu lintas jaringan (mengirim paket ARP mentah), **Anda wajib menjalankannya dengan hak akses Administrator (Windows) atau Root/sudo (Linux)**.

### 🪟 Di Windows (Menggunakan `.exe`)
* Klik kanan pada **`cuttedbydiar-gui.exe`** → pilih **"Run as administrator"**.
* Atau melalui CMD (As Admin):
  ```cmd
  dist\cuttedbydiar-gui.exe
  ```

### 🐧 Di Linux (Termasuk Linux Mint, Ubuntu, Debian, dll.)
1. Cukup jalankan perintah berikut di terminal (script otomatis mengurus venv dan dependensi):
   * **Menjalankan GUI (Tampilan Jendela):**
     ```bash
     sudo ./run.sh gui
     ```
   * **Menjalankan Scan Jaringan (CLI):**
     ```bash
     sudo ./run.sh scan
     ```

*(Catatan: Jika ada masalah dengan pustaka grafis, instal terlebih dahulu via `sudo apt install python3-tk`).*

---

## ⚖️ Peringatan Etika & Keamanan (Disclaimer)

> **PERINGATAN PENTING:**
> Aplikasi **`cuttedbydiar`** dibuat semata-mata untuk **keperluan edukasi, pengujian keamanan jaringan pribadi (*penetration testing*), dan manajemen perangkat di jaringan yang Anda miliki secara sah**.
> 
> * **Jangan disalahgunakan** untuk mengganggu, merugikan, atau melakukan *denial of service* (DoS) pada jaringan publik, jaringan kantor, atau jaringan orang lain tanpa izin tertulis.
> * Tindakan ARP spoofing tanpa izin di pihak lain adalah **ilegal** dan melanggar hukum siber di berbagai yurisdiksi.
> * Selalu gunakan aplikasi ini dengan bijak dan bertanggung jawab.
# cuttedbydiar

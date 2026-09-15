# 🚀 Tool Get Token Facebook Katana

![Python Version](https://img.shields.io/badge/Python-3.8%2B-blue.svg)
![Status](https://img.shields.io/badge/Status-Active-brightgreen)
![Author](https://img.shields.io/badge/Author-HuyCoder-orange)

Một công cụ tự động hoá bằng **Python** hỗ trợ đăng nhập và bóc tách `Access Token Katana` cùng `Cookies` Facebook với hiệu suất cao. Tool sử dụng cơ chế mã hoá mật khẩu **RSA / AES-GCM** trực tiếp qua Graph API Katana, vượt qua cơ chế xác thực 2 lớp một cách mượt mà và an toàn.

---

## 🌟 Tính Năng Nổi Bật

- 🔐 **Mã hoá mật khẩu an toàn:** Sử dụng thuật toán mã hoá `FB4A` (`#PWD_FB4A`) giúp giả lập thiết bị Android chuẩn xác, tránh bị checkpoint khi lấy token.
- 🔑 **Tự động xử lý 2FA:** Tự động tạo và lấy mã xác thực 2 yếu tố ngay trong quá trình đăng nhập.
- ⚡ **Xử lý đa luồng:** Đăng nhập và bóc tách token hàng loạt với tốc độ cực nhanh
- 🍪 **Bóc tách Cookie chuẩn:** Lấy trọn bộ Session Cookies chính xác.
- 📁 **Xuất báo cáo tự động:**
  - `Acc_Live.txt`: Lưu lại các tài khoản đăng nhập thành công kèm Token & Cookie.
  - `Acc_Die.txt`: Lưu lại danh sách tài khoản thất bại để kiểm tra sau.

---

## 🛠️ Yêu Cầu Hệ Thống & Cài Đặt

### 1. Yêu cầu
- **Python 3.8** trở lên.
- Các thư viện Python cần thiết: `requests`, `pycryptodome`, `pyotp`.

### 2. Cài đặt các thư viện phụ thuộc

Mở Terminal / Command Prompt hoặc Termux và chạy lệnh:

```bash
pip install requests pycryptodome pyotp

# Live Dashboard

Web quản lý ca live realtime.

## Cấu trúc

- `index.html`: file chạy chính của website.

## Deploy Cloudflare Pages

Cloudflare Pages setting:

- Framework preset: None
- Build command: để trống hoặc `exit 0`
- Build output directory: `/`

Sau khi kết nối GitHub với Cloudflare Pages, mỗi lần sửa `index.html` và commit lên GitHub, Cloudflare sẽ tự deploy lại.

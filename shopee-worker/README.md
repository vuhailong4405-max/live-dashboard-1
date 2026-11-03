# Gooby Shopee Worker

Worker `shopee-performance-sync`: kết nối Shopee (OAuth), lấy số liệu phiên live mỗi phút và ghi vào máy chủ dữ liệu VPS của Gooby Live Dashboard.

- Cloudflare Workers Builds tự deploy mỗi khi có commit mới trên nhánh `main`.
- Biến và khóa bí mật đặt trong Cloudflare → Worker → Settings → Variables and Secrets; **không** đưa khóa vào kho này.
- Thư mục này nằm trong kho web; Worker build với Root directory = `shopee-worker`.
- Bản gốc và kiểm thử nằm trong thư mục dự án dashboard (`Shopee_Live_Worker_V40_VPS.js`, `tests/worker-vps.mjs`).

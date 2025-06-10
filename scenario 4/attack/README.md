**Mô tả:** SMB Enumeration qua dịch vụ samba bằng enum4linux

**Câu lệnh thực thi:**
```bash
enum4linux -a <ip-target>
```
enum4linux: Công cụ dùng để thu thập thông tin từ các dịch vụ SMB (Server Message Block) đang chạy trên hệ thống mục tiêu.
- `-a`: Thực hiện tất cả các kiểm tra mặc định bao gồm:
    - Danh sách người dùng (-U)
    - Danh sách nhóm (-G)
    - Danh sách chia sẻ (-S)
    - Các thông tin máy chủ (-i, -n, -o, -s, -e, -r, -l, -d)
- `<ip-target>`: Địa chỉ IP của mục tiêu (có dịch vụ SMB hoạt động).
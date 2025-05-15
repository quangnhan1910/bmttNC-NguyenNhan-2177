so_gio_lam = float(input("Nhập số giờ làm mỗi tuần: "))
Luong_gio = float(input("Nhập thù lao trên mỗi giờ làm tiêu chuẩn: "))
gio_tieu_chuan = 44 # Số giờ làm chuẩn mỗi tuần
gio_vuot_chuan = max(0, so_gio_lam - gio_tieu_chuan) # Số giờ làm vượt chuẩn mỗi tuần
thuc_linh = gio_tieu_chuan * Luong_gio + gio_vuot_chuan * Luong_gio * 1.5 # Tính tổng thu nhập
print(f"Số tiền thực lĩnh của nhân viên: {thuc_linh}")
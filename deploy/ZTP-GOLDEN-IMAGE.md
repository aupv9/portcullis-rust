# A6 Runbook — Golden image ZTP cho RUTM11 (cắm điện là online)

> Mục tiêu: build engine `.ipk` + nướng agent claim-by-serial + `FLEET_SECRET` vào
> **1 firmware duy nhất**. Nhân viên chỉ flash 1 lần rồi **cắm nguồn + WAN** → router
> tự claim theo serial → engine dial Attach edge → **online trong CP**. Không SSH, không token.
>
> Trạng thái phần khác: **CP live + verified** (`/api/enroll/claim`), **FE admin live**
> (đăng ký serial / bulk / QR / RMA), **agent A1–A4 đã verify trên RUTM11 thật** (xem
> `portcullis-enroll.init`). Runbook này là bước build/flash — chạy trong **RutOS SDK**.

---

## 0. Chuẩn bị (một lần)
- **RutOS SDK** đúng model/firmware RUTM11 (ramips/mt7621). Tải từ Teltonika (SDK khớp
  bản firmware đang dùng — sai bản → kernel mod lệch).
- **Rust nightly + build-std** (target tier-3 `mipsel-unknown-linux-musl`):
  `rustup toolchain install nightly && rustup component add rust-src --toolchain nightly`.
- Repo `portcullis-rust` (chứa `deploy/`).
- Giá trị **`FLEET_SECRET`** = **một** entry trong `FLEET_BOOTSTRAP_SECRETS` của CP.
  (Dev hiện tại CP đang dùng 1 secret; prod nên sinh mới `openssl rand -hex 32` per batch.)

Gói `.ipk` (theo `deploy/Makefile`) cài các file:
```
/usr/sbin/portcullis                      engine binary
/etc/init.d/portcullis                    engine service (START=95)
/etc/init.d/portcullis-enroll             ZTP claim agent (START=94)  ← A1
/etc/config/portcullis                    UCI mặc định (section 'main')
/etc/portcullis/bootstrap.conf            batch config (conffile)      ← A2
/etc/uci-defaults/99-portcullis           first-boot: user/dir/garden
/etc/uci-defaults/99-portcullis-enroll    first-boot: enable+kick agent ← A3
/etc/capabilities/portcullis.json         CAP_NET_ADMIN
```
DEPENDS: `nftables kmod-nft-core kmod-nft-nat dnsmasq-full curl ca-bundle openssl-util`
(engine + agent chạy offline-của-opkg ngoài field).

---

## 1. Build engine `.ipk` (RutOS SDK)
```sh
cd <rutos-sdk>
# Trỏ package portcullis vào SDK (deploy/.. == workspace root của crate).
ln -s /path/to/portcullis-rust/deploy package/portcullis
./scripts/feeds update -a && ./scripts/feeds install -a
make defconfig
make package/portcullis/compile V=s
# Output:
#   bin/packages/<arch>/base/portcullis_0.1.0-1_<arch>.ipk   (arch ~ mipsel_24kc)
```
Kiểm tra .ipk chứa `etc/init.d/portcullis-enroll` + `etc/portcullis/bootstrap.conf`:
```sh
tar tzf bin/packages/*/base/portcullis_*.ipk   # hoặc: ar t + data.tar.gz
```

---

## 2. Điền `bootstrap.conf` cho batch
`deploy/config/bootstrap.conf` ship với `FLEET_SECRET=""` (ZTP tắt). Điền per batch —
**hai cách**:

**Cách A (khuyến nghị) — overlay lúc bake image** (không sửa repo, secret không commit):
tạo `files/etc/portcullis/bootstrap.conf`:
```sh
CP_DOMAIN="cp.wifihub.internal"
CP_RESOLVE_IP="<IP-của-CP-host>"      # dev/LAN: IP máy chạy k3d (ingress :443). Prod: để rỗng (DNS thật).
CLAIM_URL="https://cp.wifihub.internal/api/enroll/claim"
FLEET_SECRET="<hex-secret khớp CP>"
WAN_IF="wan"                          # RUTM11 (agent tự derive từ uci network.wan.device)
```
> `CP_RESOLVE_IP` cực quan trọng ở dev: router phải resolve `cp.wifihub.internal` → IP host
> CP thì mới POST claim được (agent tự ghi `/etc/hosts`). Prod dùng DNS thật → để rỗng.

**Cách B — sửa file trong repo trước khi build .ipk** (đơn giản khi 1 batch cố định). Vì
là conffile, sysupgrade giữ nguyên.

---

## 3. Bake golden image (Image Builder)
Dùng **Image Builder** của RUTM11 (SDK khớp) để ra firmware `.bin` có sẵn engine + deps + config:
```sh
cd <rutos-imagebuilder>
# Cho Image Builder thấy .ipk custom:
mkdir -p packages && cp <sdk>/bin/packages/*/base/portcullis_*.ipk packages/
make image \
  PROFILE=<rutm11-profile> \
  PACKAGES="portcullis" \
  FILES=./files          # overlay chứa etc/portcullis/bootstrap.conf (Cách A)
# Output: bin/targets/ramips/mt7621/*-sysupgrade.bin  (hoặc -factory.bin)
```
- `PACKAGES="portcullis"` kéo theo toàn bộ DEPENDS (nftables/dnsmasq-full/curl/openssl-util…).
- `FILES=./files` nướng `bootstrap.conf` đã điền secret.
- **Nghiệm thu 1 con** trước khi nhân bản batch (Part 5).

> Bench shortcut (không reproducible, chỉ để thử): flash stock → `opkg install portcullis_*.ipk`
> → đặt `/etc/portcullis/bootstrap.conf` → reboot. Dùng để kiểm nhanh; batch thật phải qua Image Builder.

---

## 4. CP-side (đã sẵn, chỉ checklist)
- [ ] `FLEET_BOOTSTRAP_SECRETS` trên CP chứa đúng `FLEET_SECRET` đã bake (k3d: `overlays/dev/secret.env`).
- [ ] Router resolve được `cp.wifihub.internal`: dev = `CP_RESOLVE_IP` (Part 2); prod = DNS thật trỏ ingress.
- [ ] Đăng ký serial trên **Admin → Routers → Đăng ký serial / Nhập hàng loạt** (đã có).
- [ ] Edge (`:8443`) reachable từ router (k3d map host `8443`; prod = LB TCP passthrough).

---

## 5. Field flow + verify
1. **Flash** golden `.bin` (WebUI Firmware / RMS / bench).
2. Đăng ký serial trên CP (nếu chưa) — thứ tự bất kỳ, agent retry.
3. **Cắm nguồn + WAN.** Xong việc field.
4. Theo dõi tự động:
   - CP Admin → router chuyển **Chờ enroll → (đã claim) → Online**.
   - Trên router (nếu cần soi): `logread | grep portcullis-enroll` → dòng `enrolled nas_id=<serial>`;
     `ls /etc/portcullis/enrolled` (marker); `ls /etc/portcullis/tls/` (client.crt/key, cp-ca.crt);
     `logread | grep portcullis` → engine dial + adopt.

Nghiệm thu đạt = "flash → cắm điện → online" **không SSH**.

## 6. RMA / thay thiết bị
Router hỏng → con mới (cùng/khác serial): Admin bấm **"Thay thiết bị (reset claim)"** (hoặc đăng ký
serial mới) → flash con mới bằng cùng golden image → cắm điện → tự claim lại (agent idempotent, cấp cert mới).

## 7. Xoay `FLEET_SECRET`
- CP hỗ trợ **list** nhiều secret (`FLEET_BOOTSTRAP_SECRETS=old,new`) → image cũ+mới cùng hợp lệ khi rotate.
- Đổi batch: sinh secret mới → bake image mới → thêm vào list CP → sau khi hết image cũ, bỏ secret cũ.

## 8. Troubleshooting
| Triệu chứng | Nguyên nhân / cách xử |
|---|---|
| Router không online, `logread` thấy claim `401` | serial chưa đăng ký / đã online (phase gate) / `FLEET_SECRET` lệch CP / clock lệch >300s (NTP chưa sync — agent tự retry) |
| `no 10-digit serial from mnf_info` | dùng `mnf_info -s`? (đã verify đúng). Model khác RUTM11 → check flag |
| claim OK nhưng vẫn không online | engine `.ipk` thiếu trong image, hoặc không reach edge `:8443`, hoặc CP domain không resolve |
| `openssl HMAC failed` | thiếu `openssl-util` trong image (đã thêm vào DEPENDS) |
| claim không tới CP | `CP_RESOLVE_IP` sai / DNS không resolve `cp.wifihub.internal` |

---
**Files liên quan:** `deploy/portcullis-enroll.init` (A1), `deploy/config/bootstrap.conf` (A2),
`deploy/uci-defaults/99-portcullis-enroll` (A3), `deploy/Makefile` (A4). CP: `POST /api/enroll/claim`,
`POST /api/admin/routers/register`. Spec: `domain/server/docs/ztp-serial-enrollment.md`.
</content>

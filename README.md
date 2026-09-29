# Local TOTP CLI — Rust

离线 TOTP 与密码生成命令行工具：读取本地 PNG/JPEG 注册二维码，按系统时间生成验证码，
或为账户生成并保存随机密码。TOTP 共享密钥和密码分别存入操作系统凭据库。
运行时不需要 Python，也没有应用主密码或应用主密钥。

这是独立的 Rust 实现，不自动读取、迁移或修改 Python 版本的数据及凭据。

## 平台与构建

| 平台 | 凭据后端 | 运行条件 |
| --- | --- | --- |
| Windows | Windows Credential Manager，本机持久化 | 当前 Windows 用户的凭据存储可用 |
| macOS | macOS Keychain | 登录钥匙串可用；系统可能要求授权或解锁 |
| Linux | Secret Service | 用户 D-Bus 会话和已解锁的持久化 Secret Service，例如 GNOME Keyring |

WSL 按 Linux 处理，不能直接使用 Windows 凭据库。无桌面 Linux 不会回退到明文文件：
需要自行提供 Secret Service；仅列出账户元数据不需要访问凭据库。

源码构建需要 Rust 1.89 或更高版本、Cargo，以及该平台标准 Rust 工具链所需的链接器/SDK。
Windows MSVC 目标通常需要 Visual Studio Build Tools 的链接环境；macOS 需要 Xcode Command Line Tools；
Linux 需要系统链接器。**不编译第三方 C/C++ 库，不等于不需要系统链接器。**

二维码使用 `rqrr` 和仅启用 PNG/JPEG 的 `image`。Linux 凭据后端使用 Rust D-Bus/加密实现，
不依赖 OpenSSL 或 libdbus 开发包。不需要 zxing-cpp、ZBar 或 OpenCV。

在本仓库目录运行：

```sh
cargo build --release --locked
cargo install --path . --locked
totp --help
```

未安装时可直接使用 `target/release/totp`，Windows 对应 `target\release\totp.exe`。
这不是已发布的 crates.io 安装包；也没有已签名的公开发行版。
从源码构建时依赖下载需要网络；二维码导入、密码生成、凭据读取和验证码生成都在本机进行。

## 使用

```sh
totp add work --qr "/absolute/path/enrollment.png"
totp list
totp list --json
totp code work
totp code work --watch
totp doctor
totp remove work
```

Windows PowerShell 示例：

```powershell
.\target\release\totp.exe add work --qr "C:\Users\Alice\Pictures\注册二维码.png"
.\target\release\totp.exe code work
```

`--data-dir PATH` 可放在子命令前或后，只改变元数据位置，密钥仍然存储在系统凭据库。
两种实现都使用 `totp` 作为命令名；同时使用 Python 版本时，应以可执行文件的完整路径区分。

| 命令 | 输出/行为 |
| --- | --- |
| `add NAME --qr PATH` | 导入一个账户；不覆盖同名账户，不修改网站设置或源图片 |
| `enroll NAME --qr PATH` | 为已有账户附加 TOTP，保留密码；不会覆盖已有 TOTP |
| `list` / `list --json` | 列出非密钥元数据及凭据配置状态，不读取密钥或密码 |
| `code NAME` | 标准输出只有验证码及换行，保留前导零 |
| `code NAME --watch` | 需要交互终端；刷新验证码和倒计时，Ctrl+C 清行退出 |
| `password generate NAME [--length N] [--replace]` | 生成并保存密码，不显示密码；已有密码必须显式使用 `--replace` |
| `password show NAME` | 明文输出已保存的密码及换行；可能被终端日志或重定向捕获 |
| `password remove NAME` | 仅删除密码，保留账户元数据及 TOTP |
| `remove NAME` | 删除账户、TOTP 密钥、密码及待清理的密码凭据；不改变网站设置 |
| `doctor` | 显示平台、后端、索引位置、账户数量及待清理密码凭据数量；不会进行凭据读写探测 |

别名允许 1–64 个 Unicode 字符，以字母或数字开头，其余可使用字母、数字、点、下划线、连字符。
采用 NFC 规范化和完整大小写折叠，例如 `Straße` 与 `STRASSE` 是同一别名。
退出码：成功 `0`，操作失败 `1`，参数错误 `2`，处理中断 `130`。错误写入标准错误。

## 生成和查看密码

```powershell
.\target\release\totp.exe password generate user1
.\target\release\totp.exe password show user1
.\target\release\totp.exe password generate user1 --replace --length 20
.\target\release\totp.exe password remove user1
```

- 默认 12 个字符，字符集为 `A-Z`、`a-z`、`0-9`，保证至少包含一个大写字母、一个小写字母和一个数字；不包含符号。
- 使用操作系统的密码学安全随机源及拒绝采样，避免字符选择的取模偏差；不满足字符类别要求时重新生成整个密码。随机源失败时明确报错，不使用弱随机回退。
- `--length` 支持 12–1280 个字符；上限兼容 Windows 凭据的 2560 字节 UTF-16 容量。
- 新别名创建仅有密码的账户；已有 TOTP 账户可使用相同别名附加密码，不改变 TOTP 密钥和参数。
- 只有 `password show` 会输出密码。生成成功只输出保存确认，不接受手工密码、命令行密码值、stdin 导入或剪贴板操作。
- 仅有密码的账户执行 `code` 会明确报告未配置 TOTP。删除最后一个密码后保留无凭据的账户，可再次生成密码，或使用 `remove` 删除整个账户。
- `add NAME --qr PATH` 仍只创建新 TOTP 账户并拒绝重复别名。可先导入 TOTP 再生成密码，也可先生成密码，再使用 `enroll NAME --qr PATH` 为同一账户附加 TOTP。
- 生成或替换仅改变本地保存的密码，**不会更改 Microsoft Entra 或其他网站上的密码**；用户需自行在目标服务设置该密码。

密码替换先保存新凭据，再原子更新索引引用，最后删除旧凭据。新凭据写入或索引提交失败时，
保留旧引用并尝试清理新凭据；清理失败会报告需处理的密码凭据 ID。索引提交成功后若旧凭据清理失败，
错误会明确说明新密码已保存；再次运行 `password generate NAME --replace` 只完成这次待处理清理，
不会再次生成密码。若要随后再生成新密码，待清理完成后重新执行生成命令。
`password remove` 的部分清理失败同样保留待删除引用，可重试原命令。

文本列表保留 TOTP 信息并追加密码状态；JSON 列表保留已有 TOTP 账户的 `id`、`alias`、
`account`、`issuer`、`algorithm`、`digits`、`period` 字段，新增 `has_totp`、
`has_password`、`password_cleanup_pending`。无 TOTP 的账户不输出 TOTP 专有字段。
这些状态只表示索引配置，不保证对应系统凭据当前可访问；列表不显示内部密码凭据 ID。

## 支持范围

- 标准 `otpauth://totp/` 注册信息；默认 SHA1、6 位、30 秒。
- 支持 SHA256、SHA512、8 位和 1–86400 秒整数周期。
- URI 最多 8192 个 UTF-8 字节，拒绝重复/未知参数、非法百分号编码、无效 Base32 和控制字符。
- 允许 `issuer` 参数与 label 中的发行方前缀不同；优先使用非空的 `issuer` 参数，缺失或仅含空白时回退到 label 前缀。两处都没有发行方时保留为空。
- PNG/JPEG 最多 20 MiB、4000 万像素；解码分配预算为 256 MiB，这不是进程总内存的硬上限。
- 为约束解码器的几何运算，检测前将较大图片等比缩至最长边 1024 像素；大截图中的小二维码可能丢失细节，应先裁剪并保留二维码周围留白。本工具不自动裁剪。
- 处理旋转、EXIF 方向、反色和透明背景；不同解码器对模糊/受损图片的识别效果可能不同。
- 成功解码出多个不同的 TOTP 注册候选时，要求裁剪为一个；重复相同二维码可去重。不能保证发现原图所有二维码，包括缩图后无法识别的小码。
- 不支持 HOTP、推送注册、Passkey 或 Google Authenticator 批量迁移二维码。

导入成功只代表保存到本机；若正在开启网站 2FA，仍需将首个验证码提交给网站完成确认。
系统时钟应准确；本工具不联网校时。

## 数据与安全边界

| 平台 | 默认索引 |
| --- | --- |
| Windows | `%LOCALAPPDATA%\local-totp-cli-rs\accounts.json` |
| macOS | `~/Library/Application Support/local-totp-cli-rs/accounts.json` |
| Linux | `${XDG_DATA_HOME:-~/.local/share}/local-totp-cli-rs/accounts.json` |

索引最多 1 MiB，包含格式标识、版本、账户别名、可选 TOTP 参数、密码引用及待清理引用，
**不包含共享密钥或密码**。0.2.0 支持读取旧版格式 1，读取和列出账户不会重写索引；
成功的写操作会原子保存为格式 2。迁移保留现有 TOTP 凭据 ID，不要求重新导入。
升级写入格式 2 后，旧二进制会拒绝该索引，不能直接降级使用。

TOTP 凭据 service 仍为 `local-totp-cli-rs/<UUID>`；密码使用独立的
`local-totp-cli-rs/password/<UUID>`。两者与 Python 版本隔离。
索引格式不兼容时拒绝读取和覆盖，即使误指定了 Python 版本的数据目录。

- 所有索引更新有跨进程锁（最多等 5 秒）及原子替换。导入失败尝试删除刚创建的凭据；删除中断可重试。
- 系统凭据库和 JSON 不是同一个事务系统：断电/强制终止仍可能留下孤立凭据或缺少凭据的索引项。
- 复制 JSON 不会复制凭据；换机需重新导入原始 TOTP 注册信息或在网站重新绑定，并自行处理网站密码。
- 凭据库的底层保护由系统或服务负责；本应用没有额外的主密码，不保证阻止同一用户下的恶意软件。
- 密码与 TOTP 分别保存可避免相互覆盖，但仍共享操作系统凭据库的安全边界；有权读取两者的程序可能同时取得两个认证因素。
- 密钥在计算时会进入进程内存。敏感缓冲区尽量缩短生命周期并清零，但不承诺所有副本和系统内存都被擦除。
- 不记录或输出共享密钥、完整注册 URI 或原始解码器/凭据错误；验证码仅在请求生成时输出，密码仅在显式执行 `password show` 时输出。
- 二维码原图本身包含长期共享密钥。本工具不会删除、上传或备份原图，需用户妥善保管。

## 验证

CI 的质量检查使用滚动更新的 Rust stable；本地 `stable` 名称不代表工具链已更新。
验证前先更新 stable，并检查默认及全部 features；仅在最低支持版本上通过 lint 不足以复现 CI。

```sh
rustup update stable
rustup component add --toolchain stable rustfmt clippy
cargo +stable fmt --all -- --check
cargo +stable clippy --locked --all-targets -- -D warnings
cargo +stable clippy --locked --all-targets --all-features -- -D warnings
cargo +stable test --locked
bash scripts/check-dependencies.sh
cargo +stable build --release --locked
```

最低支持版本单独验证，不替代上述 stable 检查：

```sh
rustup toolchain install 1.89.0 --profile minimal
cargo +1.89.0 test --locked
```

普通测试使用公开 RFC 测试密钥及内存凭据库，涵盖 RFC 6238 全部 18 个向量、严格解析、实际二维码、
密码生成规则、版本迁移、并发进程、替换回滚、部分删除恢复、损坏索引、参数脱敏与 watch 控制。
不会读取真实账户的系统凭据；原生测试的密码和 TOTP 凭据均使用隔离命名空间。

原生测试默认忽略，且必须显式启用编译期 `native-test` feature：
它将凭据 service 前缀和默认元数据目录名改为 `local-totp-cli-rs-native-test`，仍使用真实系统后端。
测试使用临时目录与随机 ID，并尝试清理凭据；CLI 测试会在导入前检查版本标记，拒绝生产二进制。

```sh
cargo test --locked --features native-test --test native --test native_cli -- --ignored --test-threads=1
```

测试构建的 `--version` 包含 `(native-test namespace)`；它不是供日常使用的发行构建。
普通构建不启用该 feature，且没有运行时切换到明文/mock 后端的选项。测试后如需使用同一输出路径，
重新执行 `cargo build --release --locked`（不带 `--features native-test`），并检查版本不含测试标记。

Windows 原生测试应验证本机持久化标记；Linux 需要运行且解锁的 Secret Service。
macOS 可能出现钥匙串授权对话框；不要将“无原生服务环境下普通测试通过”等同于凭据后端可用。

[GitHub Actions 工作流](.github/workflows/ci.yml) 配置 Windows x64、macOS Apple Silicon/Intel、Linux x64 的普通测试、
临时凭据原生测试、依赖审计和 release 构建；Linux 使用独立 D-Bus 会话，macOS 使用临时钥匙串。
另有 Rust 1.89 最低版本测试。工作流配置不代表已经在远程运行通过。

2026-09-25 本机验收：macOS Apple Silicon / Rust 1.89 下 86 项普通测试和 2 项隔离原生测试通过，
默认 release 已构建并做命令冒烟测试。Windows x64、Linux x64、Intel macOS 的交叉检查和 lint 通过，
但尚未在这些平台原生执行。完整命令、结果和边界见[验证记录](docs/validation-2026-09-25.md)。

## 设计记录

- [迁移设计](docs/superpowers/specs/2026-09-25-rust-port-design.md)
- [实施计划](docs/superpowers/plans/2026-09-25-rust-port.md)
- [RFC 6238](https://www.rfc-editor.org/rfc/rfc6238.html)
- [Key URI 格式](https://github.com/google/google-authenticator/wiki/Key-Uri-Format)

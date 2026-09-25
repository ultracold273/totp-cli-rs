# Rust 移植验证记录

日期：2026-09-25。首轮本机验收环境：macOS Apple Silicon，Rust 1.89.0。
本记录区分本机结果、交叉检查和远程 CI 结果；不把配置好的 CI、交叉检查或模拟凭据测试算作其他平台的原生验收。

## 本机验证

| 检查 | 结果 |
| --- | --- |
| `cargo fmt --all -- --check` | 通过 |
| `cargo clippy --locked --all-targets -- -D warnings` | 通过 |
| 同一 Clippy 命令增加 `--all-features` | 通过 |
| `cargo test --locked` | 86 项通过，2 项原生测试按默认配置忽略；无失败 |
| `cargo test --locked --features native-test --lib --test cli --test store` | 42 项通过，覆盖测试命名空间、版本标记和默认目录；与普通测试有重叠 |
| `cargo test --locked --features native-test --test native --test native_cli -- --ignored --test-threads=1` | 2 项通过；真实 macOS Keychain 读写更新删除和 CLI 导入、去重、列出、生成、删除 |
| `cargo test --release --locked --test qr` | 35 项通过，包含 5880×5880 大图、正常/反色候选歧义回归 |
| `cargo build --release --locked --features native-test`，再通过 `TOTP_TEST_BINARY` 执行原生 CLI 测试 | 1 项通过；使用隔离命名空间的实际 release 二进制 |
| 将生产 release 路径传给相同原生 CLI 测试 | 按预期在版本检查处拒绝，退出 101；检查发生在创建测试 Fixture 或导入之前 |
| 最后执行 `cargo build --release --locked` | 通过；最终默认二进制版本为 `totp 0.1.0`，不含测试命名空间标记 |
| 默认 release 的 `--help`、`--version`、空目录 `list --json`、`doctor` | 通过；元数据只读命令没有创建索引目录，`doctor` 明示未探测凭据可用性 |

普通测试分布：库 14、CLI 8、注册解析及 TOTP 9、二维码 35、索引 20。
RFC 6238 全部 18 个向量由一个参数化测试覆盖，不重复计算为 18 个独立测试函数。
仅使用公开测试密钥和随机临时凭据；原生测试使用 `local-totp-cli-rs-native-test` 前缀，不读取真实账户。

`file` 确认最终二进制为 macOS ARM64。`otool -L` 仅列出系统 Framework / 系统库，未列出第三方动态库。
最终二进制位于 `target/release/totp`；未全局安装、签名或发布。

## 交叉检查与依赖审计

对下列三个目标分别执行并通过：

```sh
cargo check --locked --all-targets --target TARGET
cargo clippy --locked --all-targets --target TARGET -- -D warnings
cargo clippy --locked --all-targets --all-features --target TARGET -- -D warnings
bash scripts/check-dependencies.sh TARGET
```

| 目标 | 编译检查 / lint / 依赖审计 | 本机是否实际链接、运行 |
| --- | --- | --- |
| `x86_64-pc-windows-msvc` | 通过 | 否 |
| `x86_64-unknown-linux-gnu` | 通过 | 否 |
| `x86_64-apple-darwin` | 通过 | 否 |

另对本机 `aarch64-apple-darwin` 运行并通过同一依赖审计。
[审计脚本](../scripts/check-dependencies.sh)检查实际启用的 normal/build/dev 依赖图，拒绝列出的
C/C++ 构建工具及 OpenSSL、libdbus、第三方原生二维码/图像库；图片 features 仅启用 PNG/JPEG。
锁文件可能包含其他未启用分支的包，不能仅以锁文件中的名称判断实际构建依赖。
这不等于不需要系统链接器或平台 SDK，也不是对任意未来依赖更新的保证。

## 仍需各平台执行的验证

[CI 工作流](../.github/workflows/ci.yml)包含 Windows x64、macOS ARM/Intel 和 Linux x64 原生 runner：
普通测试、默认和测试 feature 的 lint、隔离原生凭据测试、release 链接及冒烟测试。
Windows 测试读取实际凭据的本机持久化标记；macOS 使用临时钥匙串；Linux 使用独立 D-Bus / Secret Service。
首次远程执行卡在 Clippy，尚未执行这些原生测试，排查见下文；Windows/Linux 的凭据服务行为仍须这些测试实际执行后确认。

## 审查修复

- 以 ICU4X 替换旧大小写折叠表，Georgian 大小写查找/删除及重复别名回归先失败后通过。
- 二维码先统计已解码的唯一 TOTP 候选，再解析参数；参数无效的第二个候选不能被悄悄忽略。
- 大图检测缩至最长边 1024，约束已复现的 `rqrr` 求交整数溢出；小码识别取舍见 [README](../README.md)。
- 原生测试使用独立的编译期命名空间，并拒绝误用生产二进制；无运行时明文或 mock 后端回退。

上述本机验收完成时，原 Python 仓库未修改；Rust 仓库尚未提交，也未创建远程或推送。
后续公开仓库及推送授权另见[设计记录](superpowers/specs/2026-09-25-rust-port-design.md)。

## 首次 GitHub CI 失败排查

同日检查 `ultracold273/totp-cli-rs` 的 run `36094930886`，对应提交 `dbaa70e`：
Rust 1.89.0 的 MSRV job 成功，四个系统矩阵 job 均在第一个 Clippy 步骤失败，未运行到原生凭据测试。
CI 的 rolling stable 实际为 `rustc 1.98.1 (48a229cea 2026-09-01)`，而本机原有 `stable` 仍为 1.89.0。
本机安装独立的 1.98.1 工具链后，用以下命令复现相同的三个 lint 错误，退出码为 101：

```sh
cargo +1.98.1 clippy --locked --all-targets -- -D warnings
```

| 位置 | 错误 | 修复 |
| --- | --- | --- |
| `src/vault/windows.rs` | `manual_is_multiple_of`、`chunks_exact_to_as_chunks` | 使用 `as_chunks::<2>()`，通过 remainder 拒绝奇数字节；保留长度上限和 UTF-16 校验 |
| `tests/native.rs` | `assertions_on_constants` | 断言实际凭据 service 前缀为测试命名空间，在构造原生 fixture 之前拒绝生产构建 |

Windows 编码辅助模块也在其他平台的单元测试中编译，因此它的 lint 会阻塞全部矩阵目标。
修复未修改凭据后端、依赖或 CI 检查强度，没有关闭 `-D warnings` 或固定旧 stable 来绕过检查。
[README](../README.md) 增加了更新 stable、检查两种 feature 配置和单独验证 MSRV 的步骤。

修复后的本机复测（仍为 macOS Apple Silicon）：

| 检查 | 结果 |
| --- | --- |
| Rust 1.98.1 和 1.89.0 的 `cargo fmt --all -- --check` | 均通过 |
| Rust 1.98.1 四目标的 `cargo clippy --locked --all-targets`，分别使用默认 features 和 `--all-features`，均带 `-- -D warnings` | 全部通过；ARM macOS 为本机检查，Windows x64、Linux x64、Intel macOS 为交叉检查 |
| Rust 1.89.0 本机 Clippy，默认及全部 features，均带 `-- -D warnings` | 均通过 |
| `cargo +1.98.1 test --locked --lib vault::windows::tests` | 5 项通过，覆盖编码兼容、UTF-16 字节长度及损坏 blob；这些测试也包含在完整测试中 |
| Rust 1.98.1 和 1.89.0 的 `cargo test --locked` | 各 86 项通过，2 项原生测试默认忽略，无失败 |
| `cargo +1.98.1 test --locked --features native-test --lib --test cli --test store` | 42 项通过，与完整普通测试有重叠 |
| `cargo +1.98.1 test --locked --test native -- --ignored --test-threads=1` | 按预期退出 101，在命名空间断言处拒绝，未构造或访问原生凭据 fixture |
| `cargo +1.98.1 test --locked --features native-test --test native --test native_cli -- --ignored --test-threads=1` | 2 项通过，使用真实 macOS Keychain、随机测试凭据和测试命名空间；未设置 `TOTP_TEST_BINARY` 覆盖 |
| `cargo +1.98.1 build --locked`，随后执行 `target/debug/totp --version` | 通过，恢复默认 debug 二进制为 `totp 0.1.0`，不含测试命名空间标记 |

此处的 1.89.0 复测使用本机尚未更新的 `+stable` 别名，执行前已确认 `rustc +stable --version` 为 1.89.0；
1.98.1 的命令均显式使用 `+1.98.1`。后续重现应使用实际版本，不能假定本地 `stable` 别名指向 CI 的版本。

以上结果记录于修复提交、推送和远程重跑之前，不代表 Windows/Linux/Intel macOS 原生测试、
各平台 release 链接或完整 GitHub Actions 工作流已经通过；这些须由推送修复后的 CI 另行确认。

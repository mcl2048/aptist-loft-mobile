# LOFT 0.1.3-LYNX · loftmobile-1125-02

## 任务范围

| 需求 | 验收内容 |
| --- | --- |
| ✅ 侧栏图标化 | 常驻原生模块轨道仅显示图标。保留模块身份、选中反馈、触控面积、二级菜单和四语无障碍名称 |
| ✅ 本地加密存储 | 已导入的 SOCKS5、HyrakenX、Hyraken Pro 节点完整跨进程保留，包括地址、节点名称、认证材料及协议选项。保留稳定节点 ID 和排序，以及已保存的路由、网络隐私设置及未验证的服务器地址 |

设计以 `guide/guide.md` v3.6 和 `guide/ui-design.md` 为本地输入。以 Android Keystore 和 SQLCipher 实现密钥与数据库边界，以 SQLite 事务先确认持久化再发布内存配置。核对 Android 的备份和设备迁移规则，以及 Compose 导航的无障碍 semantics。参考来源与恢复行为见 [加密存储契约](../docs/contracts/encrypted-storage.md)。

## 基线与开发检查点

- 基线为 `c71f7989117ff1c820440deed2ee9cda515811e8`。开发前远端 `main` 与本地基线一致。Go 源目录树为 `b4117360f3b7c35d5da5ec9d0fac4413800ba3e5`，Gateway 源固定在 `231f14813f2b45cb6f0bde984181c57cba1d02fd`。
- 开发前实际执行 `python3 -m unittest discover -s tests -v`，38 项通过。新增 domain 序列化依赖测试先以 `serde:unapproved_domain_dependency` 如期失败，再调整架构守卫。相同命令 39 项通过，`python3 scripts/verify_architecture.py` 通过。Rusqlite 仍属于适配层。
- 在 `loft-vpn-engine-go/` 实际执行 `python3 tools/verify_owned_sources.py`、`go mod verify`、`go test -tags=with_gvisor -p=1 ./... -count=1`、`go test -race -tags=with_gvisor -p=1 ./... -count=1`、`go vet -tags=with_gvisor -p=1 ./...`。各项退出 0，源检查覆盖 434 个锁定文件及报告的 12 个补丁文件。
- 本次使用独立 API 29 x86_64 AVD。首次使用 `-accel off` 时模拟器拒绝启动，当前主机缺少 KVM。通过 `ANDROID_I_WANT_MY_TCG=yes` 启用软件模拟后 ADB 已识别设备。

## 实现与验证

- Rust 使用 `rusqlite` 0.43.0、SQLCipher 4.20.0、SQLite 3.54.1 和 vendored OpenSSL 3.6.3。`cargo test --manifest-path loft-core-rust/Cargo.toml --workspace --locked --no-fail-fast` 共 102 项通过，格式检查和 `cargo clippy --manifest-path loft-core-rust/Cargo.toml --workspace --all-targets --locked -- -D warnings` 退出 0。`cargo audit --file loft-core-rust/Cargo.lock --json` 检查 150 个锁定依赖，已知漏洞 0，保留 host-only `basic-toml` 维护状态提示。
- 三种协议的 Rust 测试在重开真实库后对比实际服务票据中的协议输入摘要，覆盖 SOCKS5 转义认证、X seed/CA/客户端证书及私钥/服务端证书/非默认选项，以及 Pro seed/证书与传输参数。另有进程中断回滚、部分 SQL 写入失败后的事务原子性、错钥和损坏页、未知 schema、同库并发打开及过期节点移除的检查。
- 数据库加密配置检查起初因 rusqlite 整数接收类型和 SQLCipher 4.20 文本 PRAGMA 值不匹配失败。读取真实加密状态、HMAC 与页面大小后，存储适配器和 FFI 测试通过。Android 资源测试先复现构造锁阻塞，拆分工厂锁后通过。首次 ARM64 原生构建报告缺少工具链 `ranlib`，最终两 ABI 使用 NDK 的 `llvm-ranlib`。首次 Android Release Kotlin 编译在公开 SDK 缺少 `O_DIRECTORY` 处失败，改用受支持的文件描述符打开及 `fstat` 目录检查后通过。
- Go 运行时版本元数据提升至 `0.1.3-LYNX` 后重新执行 `go test -json -tags=with_gvisor -p=1 ./... -count=1` 与 `go test -json -race -tags=with_gvisor -p=1 ./... -count=1`，各 114 个顶层测试及 145 个子测试，失败 0。源锁、模块校验和 `go vet -tags=with_gvisor -p=1 ./...` 同次通过。
- ARM64 `bash scripts/build-android.sh` 成功，APP JVM 79 项加 foundation 117 项全部通过，R8 和资源收缩实际执行。Lint 收录 0 错误、38 警告。候选 APK 对照当前剥离后的原生库逐字节核对，4 个 ARM64 ZIP/ELF 16 KiB 校验、v2/v3 签名、版本、备份规则及索引与 APK 敏感信息扫描通过。

## Android 实测与发行

- API 29 x86_64 共 13 项通过。相同 Debug APP 上，12 项存储与回归测试和 1 项侧栏测试分别使用匹配的 instrumentation APK。通过真实私有 Binder 写入并等待回执，在独立测试调用间执行 `am force-stop net.aptist.loft`，确认 UI 和 `:vpn` 旧进程均已退出。重新读取节点 ID、名称、地址、路由、隐私及服务器草稿，经 Binder 查页仍无认证材料。重开后重复导入仍因完整凭据匹配而拒绝，VPN 从断开状态返回。
- 真实 Android Keystore 验证了密钥丢失后的密文保留、初始化中断后使用同一数据库密钥、认证阶段字段被篡改时拒绝打开、目录别名处理，以及末级数据库符号链接拒绝。首次目录别名测试定位到 `Files.createDirectories` 对符号链接路径的行为。修复后对可信目录解析一次，沿同一路径创建文件及同步目录。
- 侧栏通过 Android accessibility tree 验证选中状态、至少 48 × 56 dp 的命中区，以及通过二级菜单进入节点页后 Network 仍选中。早期测试误把 Compose 虚拟描述节点当作可操作控件，随后又假定节点列表页有返回按钮。最终在实际控件上操作并校验节点页标题和菜单关闭。四语资源各 258 个键。R8 x86 Release 用普通应用 UID 启动，实测匿名网络页和仅图标侧栏。 [运行回执](../docs/validation/android-0.1.3-runtime.json) · [真实界面](../docs/validation/ui/loft-0.1.3-x86-r8-guest.png)
- `bin/loft.apk` 为 ARM64 Release，使用与 0.1.2 相同的本地开发签名。最终 APK 对照 ARM64 构建的原生库、签名、包版本、备份规则和真实 Git 索引扫描。 [构建输入](../docs/validation/build-0.1.3.json) · [成品回执](../docs/validation/apk-0.1.3-release.json)

0.1.2 将节点保存于进程内存，升级后需用原链接重新导入一次。0.1.3 成功导入并提交的节点跨进程重启保留。永久密钥丢失的恢复路径使用 Android Settings 清除 LOFT 数据并重新导入。实体 ARM64、Fold、TalkBack、断电耐久和长期功耗尚未验证。0.1.3 Android 执行使用合成测试节点，真实私有 X/Pro 网络验收见 0.1.2 历史回执。

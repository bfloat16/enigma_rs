# 后续开发规范

本文件是仓库的根规范，适用于所有目录。enigma-rs 是 Rust 编写的 Enigma Protector 静态脱壳与虚拟机分析工具；根 `Cargo.toml` 统一管理构建、依赖和 lint，排版遵循 `cargo fmt`。本文件只记录通用开发规范，不记录具体调试过程、临时实验或当前开发进度。

静态恢复与格式实现以 PE 规范和已验证的壳实际行为为准，不运行输入样本、内嵌 Loader 或宿主 API，不设置人为的文件大小、节数量、导入数量、字符串长度、解压大小、目录深度或 EVB 文件数量限制。配置投影、字段偏移、密钥配方、导入结构、VM 语义和 EVB 参数均从实际指令流、数据流与自校验结构推导；不能靠样本名称、文件哈希、商业版本号或机器码字节特征硬编码分支，也不能为适配工具内部模型而拒绝合法数据、截断内容或改变语义。

## 1. 环境与构建

- 使用 Rust 2024；编译器通过根 `rust-toolchain.toml` 固定为 `1.99.1`，与 `Cargo.toml` 的 `rust-version` 保持一致。升级时查询最新稳定版并固定具体版本号，同步更新两处配置；不使用浮动的 `stable`。开发环境需要目标平台链接工具（Windows x64 MSVC 与 Windows SDK），rustfmt 和 Clippy 由工具链配置安装。
- 保留根 lint：`missing_debug_implementations`、Clippy `all` 为 warn，`unwrap_used`、`expect_used`、`panic` 为 deny。检查必须零告警，不通过全局 `allow` 或降低检查等级规避。
- 优先标准库和已有依赖；新增依赖须必要、维护良好、许可兼容并说明理由，不引入外部反汇编器/编译器（如 LLVM/Clang）或预编译脱壳 runtime。
- Features 只控制可选 GPU 搜索后端（默认启用 `cuda` 和 `wgpu`，`--no-default-features` 仅保留 CPU），不得关闭安全检查或改变恢复语义。
- `build.rs` 仅在启用 `cuda` feature 且本机存在受支持 NVIDIA 驱动时，按官方 redistributable 清单准备最小 CUDA 运行时（头文件、NVRTC 动态库与许可证）到产物同级 `runtime/cuda-<release>`，校验 SHA-256 与归档路径边界，不打包显卡驱动；无可用 GPU 或设置 `ENIGMA_CUDA=0` 时回退到 WGPU/CPU，保持确定性和幂等。

## 2. 目录与模块职责

| 路径 | 职责 |
| --- | --- |
| `src/main.rs` | CLI 唯一入口：参数解析、模式校验、解包与分析结果输出。 |
| `src/common` | 二进制读写、原子目录发布、PE 解析、Enigma LZ 与分支逆滤波、RC4 与 IDEA。 |
| `src/unpack` | OEP 引导与 Loader 提取、配置与节描述符解析、salt 搜索（CUDA/WGPU/CPU）、节还原、导入恢复与 PE 重建。 |
| `src/evb` | 内嵌 EVB 虚拟容器自校验定位、目录树解析与文件内容还原。 |
| `src/devirt` | x86/x64 静态指令解释、Loader token 分析、switch VM 语义 CFG 恢复、数据流优化与原生代码生成。 |
| `build.rs` | CUDA NVRTC 与头文件构建期按需下载、SHA-256 校验与 `runtime/` 目录准备。 |
| `tests/` | 与 `src/` 平级并镜像其目录结构的测试模块。 |

## 3. 模块规范

以下小节依次对应第 2 节。依赖方向为 `main` → `unpack` / `devirt` / `common`，`unpack` → `devirt` / `evb` / `common`，`evb` → `unpack::config` / `common`，`devirt` → `unpack`（仅 runtime 提取与节定位）/ `common`，`common` 不依赖其它内部模块。x86（PE32）与 x64（PE32+）各自独立维护在对应子模块，按 PE 架构显式分派，禁止跨架构混用偏移、寄存器宽度或隐式回退。

### 3.1 `src/main.rs`

- CLI 参数固定为 `<INPUT> [RVA]`、`--mode <unpack|scan|devirt|runtime>`（默认 `unpack`）、`-o/--output <PATH>`、`--mod <cuda|wgpu|cpu>`；不增加样本专属开关或调试选项。
- 打开输入文件前完成参数与模式组合校验：`--mod` 仅允许配合 `unpack`；`unpack` 不接受 `RVA` 和 `-o`；`scan` 与 `runtime` 不接受 `RVA`；`devirt` 必须提供 32 位十六进制 `RVA`（支持可选 `0x`/`0X` 前缀）。
- `unpack` 输出到输入同级 `unpack/` 目录（保留原 EXE 文件名与 EVB 相对路径）；`runtime` 默认写入同级 `unpack/runtime.dll`，指定 `-o` 时直接写入目标文件；`scan` 输出排序去重后的 `vm_enter` RVA 列表；`devirt` 默认输出 Intel 语法汇编，输出路径扩展名为 `.bin` 时写入机器码字节。所有落盘操作禁止覆盖已有文件或目录。

### 3.2 `src/common`

- `io`：字节与整数读写统一通过 `take`、`u16_at`、`u32_at`、`u64_at`、`put_u32_at`、`put_u64_at` 和 `Cursor` 完成，读前校验范围与溢出，其它模块不重复定义游标或手写无校验切片转换。文件写出统一使用 `write_new_file`（`create_new(true)`），目录发布统一使用 `publish_directory`（先写同级临时目录，校验目标不存在后原子重命名，失败清理临时目录）。
- `pe`：校验 `MZ`、`PE\0\0`、PE32（`0x14c`/`0x10b`）与 PE32+（`0x8664`/`0x20b`）、可选头范围、节表范围、非空节 RVA 唯一性与 `FileAlignment`。零长节保留节表索引但不参与 RVA 映射或冲突判定；重叠原始范围按最高起始 RVA 映射；RVA 读取不得跨节越界。PE 校验和与导入名称解析集中在 `pe`。
- `codec`：实现 Enigma LZ 解压、用作 salt 预筛的保守前缀可行性检查 `plausible_prefix`，以及 `E8`/`E9`/`FF 25` 分支逆滤波 `fix_branches`。Loader 流允许块尾填充（`strict = false`），配置、节与 EVB 目录流要求恰好消费全部输入（`strict = true`）；前缀耗尽视为未定，绝不能丢弃合法候选。
- `crypto` 与 `idea`：`Rc4` 支持密钥 KSA 初始化与从任意 256 字节状态表直接启动 PRGA（`from_state`），`SectionProbe` 复用前 16 轮固定 seed KSA 并提供 4 路交错 KSA；`Idea` 实现大端轮密钥展开、模 `65537` 乘法逆元及 Loader 自定义的 CBC 反馈与尾块加密异或。算法模块只处理字节和参数，不读写文件。

### 3.3 `src/unpack`

- 完整解包顺序固定为：解析 PE → 静态追踪 OEP 引导并解码内嵌 Loader → 推导配置投影并解密校验配置 → 提取宿主节密文并还原入口补丁 → 搜索或验证节 salt 并解码全部启用节 → 恢复导入表与 API 转发桩 → 恢复 OEP 或编译入口 VM → 重建 PE 映像 → 提取内嵌 EVB → 原子发布输出目录。在提取 EVB 前释放宿主节临时缓冲区。
- `entry`：按 PE 首选基址建立静态映像，从 OEP 沿真实可达控制流解释指令（使用 Brent 环检测防止死循环），跳过不可达垃圾代码；证明计数 XOR 循环的访存宽度（1/4 字节）、独立指针步长、单位计数递减与回边后汇总解密；验证解压调用参数，解压并逆滤波得到 RVA 映射的 Loader DLL。`extract_runtime` 仅提取并校验 DLL 标志，不解析配置或搜索密钥。
- `config`：从 Loader 实际拷贝代码推导 `ctx` 投影与机器绑定标志位，校验密文 MD5，尝试包含/跳过共享节两种原始节 MD5 异或密钥配方，严格解压后校验明文 MD5。解析入口覆盖补丁与 80 字节节描述符，校验序列化配置长度与 Loader 投影总长度一致；检测到机器绑定节密钥后缀时直接报错拒绝。
- `search`、`cpu_search`、`gpu_kernel`、`cuda_search`、`wgpu_search`：先用无 salt 验证全部启用节；需要 salt 时选最小非空 RC4 节作为预筛探针，遍历完整 `0..=u32::MAX` 空间（含两端边界）。未指定 `--mod` 时按 `CUDA → WGPU → CPU` 自动回退，显式指定后端失败时直接报错。GPU 内核用 `catch_unwind` 隔离驱动/着色器 panic，每个批次按实际命中计数读取并排序候选，不使用固定大小小缓冲区截断命中；任何预筛命中必须通过全部启用节的完整 CRC32 与严格 LZ 校验。
- `imports`：按 Loader 推导出的描述符、名称密钥与可选授权密钥分支（零密钥与序列化异或密钥）解密并严格解压导入记录，要求唯一合法分支。解析 DLL/API 名称与序号（x86 32 位、x64 64 位），x86 缺失直接 IAT 槽时从可执行节内的调用/跳转/加载操作数反推唯一 IAT 槽；扫描 IAT 范围并将非零缺口通过 Loader API Hook 表与静态桩分析归约为真实导入，校验每个连续导入分组末尾的空槽终止符。
- `rebuild`：保留宿主节并按节描述符 RVA 恢复原始 `Characteristics`，不猜测无描述符的节；构建新导入节（x86 `.rebuild` / x64 `.unpack`），写入 ILT/名称、还原原 IAT 槽、重建 TLS 目录（含 BSS 零填充模板与宿主回调校验）、合并重定位（x86 `HIGHLOW` / x64 `DIR64`）与 x64 异常表（`.pdata` 范围校验），更新头部统计、清除动态基址/不兼容标志并重算 PE 校验和。

### 3.4 `src/evb`

- 从已校验的配置 `ctx` 镜像与 PE 节联合定位内嵌容器：遍历候选连续状态表与 `align_up(table + 0x400, 4)` 处的 `(length, bias)`（两个 `u32`），解密容器 `+56` 处的 64 字节头，要求头长度 `64`、目录偏移 `120`、`+32 + 120 == length`、`+48 == length` 且目录版本为 `1` 或 `3`，去重后候选必须唯一；不搜索明文 `EVB\0` 或文件名。
- 未定位到有效容器时输出 `WARNING: EVB status unconfirmed` 并返回空列表；一旦定位成功，任何目录、索引、压缩流或路径错误均直接返回错误。
- 目录解析采用迭代前序遍历并要求完整消费目录字节：版本 1 逐记录独立重启 PRGA 并与文件数据交错存储，且末尾必须恰好到达容器边界；版本 3 解密并严格解压独立目录树。路径解析跳过空名与 `%DEFAULT FOLDER%`，拒绝绝对路径、`..`、控制字符、非法字符、未展开的 `%...%` 占位符、Windows 保留设备名及尾随点/空格，并拒绝大小写不敏感的重复输出路径。
- 存储模式按整容器判定：普通模式要求全部文件 `stored == size` 且每 8192 字节用内容状态表重启 PRGA；压缩模式要求每个非空文件具有完整连续的 `ceil(size / 65536) * 12` 字节块索引，每条索引与每个压缩块均独立重启 PRGA 并解压校验。若普通模式与压缩模式同时合法，报 `ambiguous EVB storage` 错误，不偏袒任一模式。

### 3.5 `src/devirt`

- 所有 x86/x64 机器码统一使用 `iced-x86` 解码、格式化与 `CodeAssembler` 编码，不得使用原始机器码字节匹配或外部汇编器。
- `cpu` 与 `memory`：实现 x86（32 位，含 CoW 稀疏分页内存）与 x64（64 位）抽象解释器。未知输入保留符号身份、已知位掩码与至多双候选值集合（`{a, b}`），条件分支（`test`/`cmp` 零值判断）在真假边上分别收紧候选；状态合流（join）做保守过近似，通过拓扑排序拒绝无终止证明的内部环，绝不靠填充任意具体寄存器值越过未知分支。
- `x86::vm`、`x86::loader`、`x86::native_layout` 与 `x64::runtime`、`x64::profile`：从解密 Loader 入口解码 token 表、序列化模板 profile（streams、handlers、patch 槽与 dispatcher）及 `0x231` 变长原生扩展回调；通过指令与数据流推导配置拷贝投影、导入字段、API Hook 表（计数、步长、目标列）、TLS 索引转移、重定位消费端和机器绑定后缀标志。
- `switch`、`lift`、`ir`、`graph`、`demand`、`optimize`、`partition`：跟随输入 dispatcher 与 handler 将字节码提升为带内存 epoch 的位向量表达式 DAG 与语义 CFG；区分私有 VM 栈/上下文与宿主访存（`GuestPointer`），弹出后的私有栈槽通过 `retire_stack` 回收并禁止未重写的悬空读取；后向按位活跃性分析（`demand`）消除死位与被覆盖的回调标志位，前向常量传播、恒等赋值消除与前驱分割等价类化简（`partition`）迭代至不动点。全流程受 `Budget`（默认 180 秒，可通过 `ENIGMA_DEVIRT_TIMEOUT_SECONDS` 在 `1..=3600` 秒内调整）约束，不收敛或超时直接报错。
- `codegen`、`native`、`analysis`：将优化后的 CFG 直接编译为原生 x86/x64 指令流，解析内部 continuation / bytecode / runtime 数据符号并记录重定位（x86 `HIGHLOW` / x64 `DIR64`）；生成后重新解码校验每条指令合法且所有内部近跳转均落到指令边界；未解析的私有地址、未知输入或缺失后继分支直接报错。`Analysis` 同时支持受保护 EXE 与已提取的 RVA 映射 runtime DLL。

### 3.6 测试

- 测试统一放在与 `src/` 平级的 `tests/` 目录内（`Cargo.toml` 设置 `autotests = false`），内部按 `src/` 的原始目录结构与文件名一一对应放置，在被测源文件中通过 `#[cfg(test)] #[path = "..."] mod tests;` 挂载，测试文件内使用 `use super::*;`。不保留独立的 `test/` 目录、集成测试入口或 Python 辅助脚本。
- 覆盖 CLI 参数校验、PE 映射与边界、LZ/分支逆滤波/RC4/IDEA 已知向量、配置投影与哈希校验、CPU/GPU salt 搜索边界、导入与间接 IAT 恢复、PE/TLS/节权限重建、EVB V1/V3 目录与存储模式判定、x86/x64 抽象解释器、token/loader 推导、语义 CFG 优化与原生代码生成执行等价性。
- 优先使用合成数据、内存中用 `CodeAssembler` 构造的指令序列和最小字节向量；受版权保护的游戏样本、提取出的 runtime DLL 和大型二进制夹具不入库，不使用 `include_bytes!` 嵌入样本切片；需要本机 GPU 硬件的测试标记 `#[ignore]` 并写明运行方式；临时目录带唯一标识并在测试结束前清理。
- 测试以格式和指令语义规定的合法与非法输入为依据，不为人为数量或大小上限编写拒绝测试。

## 4. 进度、预算与错误

- 库与 CLI 统一使用 `anyhow::{Result, Context, bail, ensure}`，错误保留完整原因链及 RVA、偏移、节索引、VM 阶段等上下文；不吞掉错误，不把损坏数据或未知结构静默当作空结果（唯独未定位到内嵌 EVB 时按约定输出明确警告）。
- 解包 salt 搜索通过 `indicatif` 向 `stderr` 输出进度条与完成速率；阶段摘要（Salt、EVB 文件、Devirtualized 统计、Rebuilt 摘要、Saved 路径）输出到 `stderr`，保持 `stdout` 仅用于 `scan` / `devirt` 的分析结果输出，并妥善处理 `BrokenPipe`。
- VM 恢复、优化与代码生成共享 `Budget` 墙钟预算，在循环和阶段边界调用 `budget.check`；超时或状态发散立即中止并返回带阶段信息的错误。
- 错误信息与进度日志使用英文；不输出敏感密钥材料或大块原始二进制数据。

## 5. 代码风格

### 格式

- 排版统一使用 `cargo fmt --all`；文件使用无 BOM 的 UTF-8、LF 和末尾换行。

### 语言特性

- 生产代码禁止 `unwrap`、`expect`、`panic!`、`unreachable!`、`todo!`，失败统一返回 `Result`；测试确需 `unwrap` / `panic!` 时在测试模块局部添加 `#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]`。
- 根模块（`src/lib.rs`、`src/main.rs`、`build.rs`）启用 `#![deny(unsafe_code)]`，仅在 `cuda_search`（探测驱动/NVRTC 动态库）与 `gpu_kernel`（CubeCL 内核定义与启动）局部添加 `#[allow(unsafe_code)]`，每处 `unsafe` 块前写明 `// SAFETY:` 注释说明边界与不变量；其余模块禁止 `unsafe`。
- RVA 用 `u32`，x64 虚拟地址与大偏移用 `u64`，内存索引用 `usize`，窄化转换优先 `TryFrom`。地址与边界计算使用 `checked_*`，指令语义回绕使用 `wrapping_*`，饱和语义使用 `saturating_*`；算术右移显式使用有符号整数类型。
- 优先借用与 `Cow`，避免无意义克隆；公开类型按需实现 `Debug`/`Clone`，持有密钥或状态表的类型（如 `Rc4`、`SectionProbe`、`Idea`、`Descriptor`）在 `Debug` 中隐藏敏感字节。

### 命名

- 类型、trait、枚举成员用 `UpperCamelCase`；函数、方法、变量、模块用 `snake_case`；常量用 `SCREAMING_SNAKE_CASE`。不顺带重命名无关代码。

### 文件组织

- `lib.rs` 只放顶层模块声明；各子目录 `mod.rs` 只放模块声明与公开重导出（`pub use`），具体实现放入职责明确的独立文件，不新增泛化的 `utils`/`helpers` 模块，也不保留单文件套子目录的冗余层级。

### 注释

- 代码注释与文档注释使用英文。模块顶部 `//!` 说明职责、格式依据与关键不变量；注释只写可核对的指令、字段偏移或算法依据，不引用外部项目路径、不存在的分析报告、临时目录或具体样本文件名。

## 6. 简洁性：不写与要删除的代码

以下写法不得新增；清理时保持恢复行为和安全约束，限定在任务相关范围：

- **无用封装**：一对一字段复制的中间类型、纯转发薄封装、没有替换需求的 trait，以及仅为测试存在的生产分支或配置项。
- **无调用方的成员**：不可达模式、废弃的探测回退、未使用的辅助函数或模块。删除前用 `rg` 核对 `src/`、`tests/` 和 `build.rs`。
- **无意义赋值**：只写不读、立即覆盖、无用别名和临时集合拷贝；只需跳过的数据直接推进游标并保留范围检查。
- **过度防御**：格式或架构没有要求的文件大小、解压上限、节数、导入数、EVB 文件数或循环次数阈值；对受控内部不变量重复做运行期检查。
- **重复实现**：`common::io`、`common::pe`、`common::codec`、`common::crypto` 已有能力（如游标读取、PRGA、PE 导入表解析）不得在其它模块重复手写。

保留格式与语义必需的校验：PE 头与节边界、MD5/CRC32/校验和、LZ 终止与展开长度、IAT 分组空终止符、EVB 容器头自校验与双解歧义拒绝、抽象解释环检测、生成指令解码与跳转边界校验、输出文件独占创建与原子目录发布。

## 7. 验证

代码或 Cargo 配置修改后，在仓库根目录按顺序执行；失败时先修复再进入下一步：

```bash
cargo fmt --all --check
cargo clippy --all-targets --all-features -- -D warnings
cargo clippy --all-targets --no-default-features -- -D warnings
cargo test --all
```

- 格式失败先运行 `cargo fmt --all`；默认 features 与 `--no-default-features` 下 Clippy 均须零告警，全部常规测试通过。
- 修改 GPU 内核、CUDA 运行时准备或具备对应硬件环境时，按需追加运行忽略的硬件一致性测试：`cargo test -- --ignored --nocapture`。
- 纯文档修改核对路径、命令和实现，执行 `git diff --check -- <修改的文档>`，无需运行 Rust 测试。未执行或失败的检查如实说明。

## 8. 文档与交付

- `README.md` 只保留编译环境、编译命令、使用命令与输出说明、局限及社区链接；命令行参数或支持范围变化时同步更新，不把规划写成现有能力，也不在仓库内保留调试日志或分析笔记目录（如 `docs/`）。
- 保留工作树中已有的未提交改动，不执行丢弃或隐藏它们的 `checkout`/`restore`/`reset`/`stash`/`clean`；未经明确要求不提交或推送。
- 不提交 `target/`、临时输出、提取产物、`.pyc` 缓存和受限样本。
- 提交使用 `type(scope): summary`，`scope` 取模块名（`common`、`unpack`、`evb`、`devirt`、`cli`、`build`），`summary` 用英文祈使句；一个提交聚焦单一改动。
- 交付说明变更内容、验证结果和未完成检查；新增依赖、MSRV 或构建逻辑变化写明理由。

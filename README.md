# enigma-rs

## 编译环境

- Windows x64、Rust 工具链（含 Cargo）、MSVC C++ 构建工具及 Windows SDK。
- 使用 CUDA 后端需 NVIDIA 驱动和 `curl`；构建时自动准备所需组件，无需安装完整 CUDA Toolkit。
- 使用 WGPU 后端需兼容的显卡及驱动；仅使用 CPU 时不需要 GPU。

## 编译

```bash
# 默认包含 CUDA、WGPU 和 CPU 后端
cargo build --release

# 仅 CPU
cargo build --release --no-default-features

# CUDA + CPU，或 WGPU + CPU
cargo build --release --no-default-features --features cuda
cargo build --release --no-default-features --features wgpu
```

产物位于 `target/release/enigma-rs.exe`。分发 CUDA 构建时，同时复制旁边生成的 `runtime` 文件夹。

## 使用

```bash
# 解包（默认模式）
./target/release/enigma-rs.exe "input.exe"

# 指定搜索后端：cuda / wgpu / cpu
./target/release/enigma-rs.exe "input.exe" --mod cuda

# 仅提取内嵌 runtime DLL
./target/release/enigma-rs.exe "input.exe" --mode runtime
# 或指定输出路径
./target/release/enigma-rs.exe "input.exe" --mode runtime -o runtime.dll

# 列出已注册的模板 VM 入口 RVA
./target/release/enigma-rs.exe "input.exe" --mode scan

# 将指定入口还原为 x86 汇编
./target/release/enigma-rs.exe "input.exe" --mode devirt 0x23b053 -o function.asm
```

解包结果写入输入文件旁的 `unpack` 目录，EXE 保持原名，EVB 文件输出到同一目录。已有 `unpack` 时直接报错并保留，不覆盖；EVB 未确认时会明确警告。

`runtime` 默认输出到输入旁的 `unpack/runtime.dll`，已有 `unpack` 则报错；使用 `-o` 时仅要求目标文件不存在。此模式只提取 DLL，不解包宿主或运行样本。

默认自动选择搜索后端，`--mod` 仅用于解包。`devirt` 的 RVA 使用 `scan` 输出的十六进制值；省略 `-o` 则打印汇编，输出扩展名为 `.bin` 则保存机器码。分析输出不覆盖已有文件，生成代码可能仍引用原映像，并非独立可执行文件。

## 局限

目前仅支持 x86（32 位 PE），不支持 x64。

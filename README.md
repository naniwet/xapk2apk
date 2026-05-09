# xapk2apk

把 XAPK / split APK 合并成一个能 sideload 的单 APK,纯 Python,不依赖 Android SDK 或 Java 工具链。

## 它解决的问题

XAPK 是 split APK 的打包格式 —— 一个 base APK 加一堆 `config.*.apk`(按 ABI / 语言 / 屏幕密度切片)。Android 的「未知来源安装」对这种格式不友好:文件管理器只认单个 `.apk`,直接装 base 会被 PackageInstaller 拦截,报 `INSTALL_FAILED_MISSING_SPLIT`。

现有方案各自都有缺口:

| 方案 | 缺口 |
|------|------|
| Google bundletool | 输入是 `.aab`,不是 `.xapk`,链路对不上 |
| APKEditor | Java JAR,要 JDK + 下载若干个外部工具 |
| SAI(F-Droid) | 要在手机端装一个 app |

`xapk2apk` 的定位:**纯 Python,一行命令,XAPK → 单 APK**,前提是你只要一个能装能跑的 APK,不在乎语言/屏幕密度优化。

## 安装

```bash
git clone <repo-url>
cd xapk2apk
pip install -e .
```

或者不安装,直接运行:

```bash
pip install cryptography
python -m xapk2apk <input>
```

## 使用

```bash
# 输入 .xapk 文件
xapk2apk app.xapk

# 输入解压后的目录
xapk2apk ./extracted/ -o claude.apk

# 32 位机器(armeabi-v7a / x86 / x86_64)
xapk2apk app.xapk -a armeabi-v7a
```

输出在当前目录,默认文件名 `merged-<base>-<abi>.apk`。装机:

```bash
adb install -r merged-com.foo.app-arm64-v8a.apk
```

## 示例:把 Claude 的 XAPK 装到手机上

Claude 的 Android 应用在 Play 商店之外只能找到 XAPK 包(比如 APKPure / APKCombo)。直接下个 APK 没那么容易,因为它把 ABI / 语言 / 屏幕密度都拆成了 split。

下载得到 `Claude_v1.260430.10.xapk`,arm64 手机:

```bash
$ xapk2apk Claude_v1.260430.10.xapk
detected splits: ['com.anthropic.claude.apk', 'config.ar.apk',
  'config.arm64_v8a.apk', 'config.armeabi_v7a.apk', ..., 'config.zh.apk']
base APK: /tmp/xapk2apk_xxx/com.anthropic.claude.apk
ABI split (arm64-v8a): /tmp/xapk2apk_xxx/config.arm64_v8a.apk
[1/3] patching AndroidManifest.xml
  cleared resource IDs: ['0x101064e', '0x101064f']
[2/3] merging → unsigned APK
  unsigned size: 31,205,094 bytes
[3/3] signing v2 → /your/cwd/merged-com.anthropic.claude-arm64-v8a.apk
  signed size: 31,206,550 bytes (sig block 1456 bytes)

done. install with: adb install -r /your/cwd/merged-com.anthropic.claude-arm64-v8a.apk
```

把 30 多个 split 合成了一个 30 MB 的单 APK。装机:

```bash
adb install -r merged-com.anthropic.claude-arm64-v8a.apk
```

或者直接把 APK 拷到手机上,文件管理器里点开就能装(需要先打开"未知来源安装"权限)。

⚠️ 装上之后 UI 默认是英文(因为没合 `config.zh.apk`,见上面的"已知限制")。要中文界面就改用 SAI。

## 它是怎么工作的

合 split APK 的核心问题有三个,工具的三个模块各自解决一个:

### 1. 让 PackageInstaller 别拒装(`xapk2apk/axml.py`)

base APK 的 `AndroidManifest.xml` 里有这两个属性,告诉系统必须装齐 split:

```xml
<manifest android:requiredSplitTypes="base__abi,base__density"
          android:splitTypes="" ...>
```

我们的做法:在 binary AXML 的 **resource map** 里把这两个 framework attribute 的 resource ID(`0x0101064F` / `0x0101064E`)清零。

为什么这样行:Android 用 **resource ID** 而不是字符串名识别 framework 属性。`PackageParser` 里调用 `obtainAttributes(parser, R.styleable.AndroidManifest)`,这个 API 按 resource ID 匹配。把 resource ID 改成 0,系统就识别不到这是 `requiredSplitTypes`,split 检查直接跳过。

整个 AXML 字节布局保持不变 —— 只是把 4 个字节从某个值改成 0,无需重打包,无需调整任何 chunk size。

### 2. 加回 native libs(`xapk2apk/merge.py`)

base APK 不含 `.so`,native libs 全在 ABI split 里。把 chosen ABI 的 `.so` 加进 APK 即可。

但有两个细节:base manifest 里 `extractNativeLibs="false"`,所以 `.so` 必须

- **STORED**(无压缩)
- **4096 字节页对齐**(从 local file header 之后的数据起算)

这两点 `zipfile.ZipFile` 不支持精确控制,所以我们手写 ZIP:对每个 `.so` 在 ZIP 的 `extra` 字段里塞 alignment-padding,确保数据偏移落在 4K 边界。`resources.arsc` 同样需要 4 字节对齐。

### 3. 重新签名(`xapk2apk/sign.py`)

base 的原签名块在我们改完内容后失效了,得重签。Android 11+(API 30+)要求 [APK Signature Scheme v2](https://source.android.com/docs/security/features/apksigning/v2) 或 v3。

实现 v2 大约 200 行 Python:

- 用 `cryptography` 生成 self-signed RSA-2048 证书
- 按 spec 计算 chunked-SHA256 摘要,三段(zip entries / central directory / EOCD)各自 1 MiB 一块
- 构造 v2 signing block(magic `APK Sig Block 42`)
- 插到 zip entries 与 CD 之间,把 EOCD 里 CD 的 offset 往后挪

不做 v3:v3 主要解决 key rotation,sideload 用不上;v2 alone 覆盖 Android 7.0+。

不做 v1:v1 在 Android 11+ 已被新装拒绝,留着只是浪费体积。

## 已知限制

- **只合 native libs,不合语言/密度 split。** UI 可能丢非默认语言(比如中文),图标在超高 DPI 屏上稍糊。要保留多语言/多密度需要合并 `resources.arsc`(Android resource 二进制表),出错率高,我们故意没做。如果非要保留全部 split 资源,**用 [SAI](https://f-droid.org/packages/com.aefyr.sai.fdroid/) 是更稳的方案**。
- **自签证书**。每次 build 用新 key,装上之后想从 Play 商店增量升级走不通(签名不匹配),要更新得卸载重装。
- **单 ABI 输出**。32 位机和 64 位机要分别 build。
- **CLI 不支持 v3**。如果你的目标设备拒收 v2-only(极少见,大都是企业管控 ROM),目前没办法。

## 替代方案对比

| 场景 | 用什么 |
|------|--------|
| 想保留多语言、多密度、多 ABI | SAI(手机端 split installer) |
| 已有 `.aab` 文件,要装 universal APK | bundletool |
| 要做更复杂的 APK 改动(注入 frida、改 smali) | APKEditor + apksigner |
| **就要一个能装的 APK,不在乎语言/优化** | **本工具** |

## 开发

```bash
pip install -e ".[dev]"
pytest tests/
```

测试覆盖三个模块:

- `test_axml.py`:resource ID 清零 / 字节长度保持 / 幂等性 / 非 AXML 报错
- `test_merge.py`:`.so` 页对齐 / `resources.arsc` 4 字节对齐 / 原签名文件被剔除 / native lib 注入
- `test_sign.py`:签名后 ZIP 仍可读 / 签名块 magic 与 ID 正确 / EOCD 中 CD offset 正确更新 / `apksigtool` 第三方校验(可选)

## License

MIT

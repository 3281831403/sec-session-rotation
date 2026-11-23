登录前后会话 ID 没换，被人抓住一个固定 ID 就直接接管了账号：new_id 用 random.random() 产生会话 ID，熵源可预测；new_id 只对 user 做哈希，同一用户在不同时间会得到同一个 ID；rotate 返回新 ID 却不删除旧 ID，旧 ID 仍然有效；rotate 复用旧 ID 的 TTL，不重置过期时间；bind 不记录创建时间，TTL 无法判定；validate 不比较绑定用户，A 的 ID 可以访问 B 的会话；validate 用 now - created > ttl 判定但毫秒与秒混用，过期判断失效；replay_guard 使用模块级固定 nonce 集合，重启后丢失重放窗口；invalidate_all 只删当前用户的一条会话，其他端仍然在线；session_batch 复用同一个 store，第二用户的事件会命中第一用户会话。session/rotation.py 是核心，tests/test_rotation.py 15个红。要修的是：new_id 的密码学熵源与固定长度，rotate 的旧 ID 立即失效、TTL 重置与并发单赢家，bind 的 created_at 与 TTL，validate 的绑定用户、毫秒/秒归一化与零容差，replay_guard 的持久化 nonce，invalidate_all 的全端清理，validate_store 的重复/过期/无绑定检查，以及 session_batch 的用户隔离与时间顺序。

## 运行方式与初始状态

在仓库根目录执行：

```text
python -m pytest tests -q
```

初始状态必须恰好输出 `15 failed`，没有 collection error、import error 或 syntax error；15 个失败均应来自尚未实现的 `NotImplementedError`。如果出现 error，或失败数不是 15，说明初始环境或测试文件已被破坏，不应继续。

## 字段表

| 字段 | 取值 |
| --- | --- |
| 所属领域 | 安全 |
| 子方向 | 漏洞检测与攻防 |
| 任务类型 | Bugfix |
| 语言/框架 | Python 3, pytest |
| 环境可复现等级 | 无外部依赖 |

## 契约与约束

- 会话 ID 固定为 64 个小写十六进制字符；TTL 默认 300 秒；过期容差为 0，年龄达到 TTL 即失效。
- 时间戳统一使用 Unix epoch 毫秒，TTL 使用秒，实现必须显式做单位归一化。
- 只使用标准库（math、hashlib、hmac）和 pytest；离线运行，不联网、不安装依赖。
- 不使用 random、os.urandom、time.time() 一类隐式随机或时钟；熵源与当前时间都由调用方显式传入。
- store 是普通字典：`ttl`、`principal`、`now`、`secret`（服务端显式注入的轮换密钥，至少 32 字节）、`sessions`（记录列表）、`nonces`（按会话 ID 分组的已用 nonce）。可重放状态必须持久化在 store 中，不能藏在模块级集合里；`rotate` 必须把 `secret`、旧 ID、用户和 `now` 一起作为派生材料，不能只依赖攻击者已知的旧 ID。
- 修复范围只允许 `session/rotation.py`。`tests/test_rotation.py` 为固定验收测试，不得修改、删除、跳过、xfail、改写断言或缩减测试数量；测试恰好 15 个。
- 不要执行 `git init`、`git push` 或任何联网操作。

## 验收覆盖面

15 个测试覆盖 10 个给定缺陷，并额外断言：轮换后旧 ID 无效、过期会话拒绝、绑定用户不一致拒绝、全端下线后无有效会话、两用户批量处理与各自单独处理结果一致。测试还包含固定 ID 接管尝试与同一旧记录并发轮换只能有一个成功者的场景。

# topology 显式公钥注入实验

用户批准的实验实现于 `crypto/memauth/topology_experiment.py`。全局 PA 公钥由本机角色编排器显式注入，不修改原文盲化报文，且不声称这种方式提供匿名性或不可关联性。

验证方传入已保存的挑战坐标 z、hRoot 和历史事件摘要 Hkey。证明者只提供原文的完整摘要序列及 CH 开口 rho；不是 Merkle path。依已批准实验参数重建 Root，检查 Hkey 在序列中，再检查 CH_PKPA(Root,rho)=hRoot。全部通过才返回 y=H1(z||hRoot)，直接交给 open 验证。

测试验证真实 APPEND 后开口、序列倒序、删除历史事件、错误随机数、公钥替换及历史摘要错误。成员检查不是严格前缀证明，不擅自增强为论文没有规定的序列前缀规则。

默认展示不导出 rho 或完整 CH 双开口，以遵守已确认的秘密展示边界；内部按原式验证完整开口。接收开口的 SA 在原模型下仍具备双开口相关知识，隐藏 UI 字段不消除此数学风险。见 algebra-review.md。

此模块不验证 link、签名、会话挑战认证或身份，因此 topology/open/upd 都通过也不代表完整连续认证通过。

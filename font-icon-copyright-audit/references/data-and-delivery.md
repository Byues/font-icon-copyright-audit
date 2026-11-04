# 统一数据、脚本与交付

## 目录与编号

按任务输出 Word审计报告、Excel风险清单、字体识别证据、高风险项目截图、官方授权条款索引、无法识别及待补材料、扫描日志和本地图文索引。要求追加时增加“后续待审文件”。不空建占位成果。

F／TXT（或 U）／E／LIC／R 分别标识资产、使用、证据、授权和风险。复用旧编号前读旧数据，不按排序重新改号。旧报告 T/P/W/N/M/D/I 可作关联编号，不提升未确认事实。压缩成员用“包相对路径::成员路径”，同内容保留不同业务路径。

## 辅助工具输入契约

`inventory` 只做递归清点、文件头提示、哈希、重复关系及读取缺口，不解析字体、不展开压缩包。输出 `扫描日志/资产清单.json` 和 CSV。`--append` 要求相同输入根，按路径保留编号，记录新增／变更／移除并归档旧清单。变更文件不能复用旧解析。文件头仅供路由，不表示字体检测成功。

CSV 对可能被办公软件解释成公式的文本加前导单引号，JSON 仍保留原始文件名／路径。该显示保护不改变原文件。

`classify`／`site` 输入 UTF-8 JSON，顶层包含 `project`、`files`、`uses`。字段定义如下，不是已检测结果：

| 对象 | 字段 |
|---|---|
| project | company、scope、date、source_root、output_root；日期取本次用户时区 |
| files[] | id、name、relative_path、sha256、status；可带 preview、evidence_path、scope_status |
| uses[] | id、file_id、asset_kind（font/icon）、in_scope（布尔或 null）、actual_use（布尔或 null）、font_read、font_original、font_identity（confirmed/unconfirmed/unknown）、location、text、evidence_grade、evidence_path、limitation；vendor_verified（厂商归属已核对）、font_read_role（substitute 表示已知替代目标）、substitution_status（confirmed 表示已明确替代）；图标可补 icon_identity=confirmed 及其技术证据 |
| uses[].authorization | state、evidence_path、coverage_verified、checks_complete、scope_match、rights_verified、explicit_gap、review_complete、gap_reason；可附 subject、channels、validity、official_url、checked_date |

布尔字段用 JSON 真布尔，不能写字符串“true”。`scope_status=not_applicable` 只用于确无本范围事项，不能因未解析而填此值。`font_identity=confirmed` 须有技术证据，只有文件级声明不能设 actual_use=true。图标身份和权利来源独立确认；没有 icon_identity 不能借文字字体字段推定已识别图标。已知替代目标不参与原字体字库高风险匹配。Swis721 等候选别名及拉丁厂商前缀，核实对应归属后才设 vendor_verified=true。

`classify` 不阅读合同或解释条款。授权布尔声明由实际审阅者根据证据填写，脚本仅派生两个结论。输出保留原字段，增加 risk、check_status、risk_reason、policy_id、policy_vendor。先看范围与实际对象，再看具体缺口／内部高优先级／授权覆盖／证据不足。字体确认不代表授权。

`site` 只将已评级数据变成离线网页，使用真实 evidence_path／preview，不伪造截图。文件按最高已分级使用记录分组，未确认部分另列；无记录且未证实不适用的文件保留待核查。路径绝对或相对 JSON 所在目录；移动已评级 JSON 时保留绝对证据路径或同步改相对路径。

`verify` 只验证编号、引用、HTML 条目数与本地链接。它不验证字体识别、授权真伪、视觉排版或法务结论。脚本目标已存在时拒绝覆盖，先留备份或换新文件名。

“不适用”在辅助工具中用于排除／无事项展示，不作为五档合规风险之一统计。实际风险数量只统计本范围内的实际使用；排除项另表保留。

## Excel

全面审计至少含：审计总览、逐文件字体使用明细、字体去重汇总、高风险与严重风险专项清单、授权证明核对表、待人工复核清单、版权整改跟踪表、证据与官方来源索引。另列完整资产清单和图标明细以核对覆盖。

明细字段：序号、部门、类别、产品／品牌、文件名、相对路径、格式、位置、字体名／内部名／权利人／版本、渠道、授权依据、侵权核查状态、风险、证据等级、证据路径、官方链接、评级理由、整改建议、责任人、处理状态、复核日期、备注；补 SHA-256、确认范围与独立授权证据。未知主体与发布状态写待确认，不从文件名猜。

字体按原名、内部名、字重、版本及哈希关联；PDF 子集前缀可规范化检索，仍保留原名。版本未知不能合并为已确认同版，图标不计独立字体数，重复物料保留业务路径和口径。总览按独立使用／风险 ID 统计，不误将多条使用计为多款字体。

所有工作表设筛选、冻结、换行、列宽、分类配色和风险条件格式。专项清单关联基础明细更新，避免直接改公式输出。用户只要精简表时另存，按指定列提取并从1编号，不破坏完整审计数据。

## Word、图文证据与验收

参考报告只作格式和线索。可沿用蓝白样式、页眉页脚、资产编号和 A–D／P1/P2，结论必须来自本次核查。完整报告十章：结论与界限、证据标准、跨字库授权、全部文件与字体明细、严重／高风险、疑似未授权证据、采购与缺口、整改建议、待补材料、官方来源与限制。

正文呈现重点，完整明细由附表或独立附件覆盖；Word／Excel／HTML／统一数据编号、字体、路径、结论一致。截图旁注明证据 ID、文件、页／坐标、哈希、方法与局限。保留技术 JSON／TXT，但普通用户通过 HTML 看图文。

重开 Excel／Word，重算公式并检查各表；Word 转 PDF 逐页检查，优先已有正规工具，组件缺失则披露限制。WPS／Office 转换或字体替代不能冒充原始字体确认。导出成功与视觉校验分别记录。

清点、完整／部分解析、技术确认、失败、仅登记、压缩成员和重复文件分别统计。每个失败／未覆盖项有路径、原因和下一步。检查全部网页证据链接，抽核代表字体对象，逐项复核所有严重／高风险。范围外备注不参与分级；待审目录未检查文件不计已审。

最终汇报真实口径与保存位置；有 CDR／图片／轮廓／压缩成员／授权资料等缺口就直说，不宣称全量版权审计完成。风险数量不是侵权数量。

# rules

Personal sing-box rule-set sources and generated artifacts.

## Layout

- `src/*.list`: source rules in Clash-style `TYPE,VALUE[,no-resolve]` format.
- `rule_json/*.json`: generated sing-box source rule sets.
- `rule_srs/*.srs`: generated binary sing-box rule sets.
- `scripts/convert_rules.py`: strict converter and validator used by CI.

## Supported source rule types

The converter supports only rule types that can be represented in a sing-box headless rule set:

- `DOMAIN`
- `DOMAIN-SUFFIX`
- `DOMAIN-KEYWORD`
- `IP-CIDR`
- `IP-CIDR6`
- `IP-ASN`

Unsupported types such as `GEOIP` and `USER-AGENT` are intentionally rejected instead of being silently dropped. Put those rules in the main sing-box configuration layer if needed.

The optional third field `no-resolve` is accepted for compatibility with Clash-style lists, but it is not emitted into the generated sing-box rule set.

## Local build

Install `sing-box`, then run:

```bash
python scripts/convert_rules.py
```

To validate and generate JSON only:

```bash
python scripts/convert_rules.py --skip-compile
```

## WeChat article routing

WeChat public-account article domains are pinned in `src/my_direct.list` so article pages and Tencent image/CDN assets stay direct:

- `mp.weixin.qq.com`
- `weixin.qq.com`
- `res.wx.qq.com`
- `qpic.cn`
- `qlogo.cn`
- `gtimg.com`
- `qq.com`
- `wechat.com`
- `servicewechat.com`
- `tencent.com`

Current Gist configs consume the custom rules as source JSON rule sets, for example `rule_json/my_direct.json` and `rule_json/my_proxy.json`. The generated `.srs` files are still available for configs that prefer binary rule sets.

Make sure the `my_direct` rule set is placed before broad proxy/final rules in the consuming sing-box config.
